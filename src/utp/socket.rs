// utp/socket.rs

use crate::utp::common::{ConnectionState, UtpError, current_micros};
use crate::utp::packet::{UtpPacket, UtpHeader};
use crate::utp::connection::Connection;
use crate::utp::congestion::CongestionControl;
use crate::utp::reliability::{ReliabilityManager, SentPacketInfo};

use std::collections::{VecDeque, HashMap};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::cmp::min;

// Timeouts in milliseconds
const DEFAULT_KEEPALIVE_INTERVAL: u64 = 29000;   // 29 seconds - from libutp
const CONNECT_TIMEOUT: u64 = 6000;               // 6 seconds timeout for connection attempts
const MAX_TIMEOUT_CHECK_INTERVAL: u64 = 500;     // Check for timeouts every 500ms

// Constants for the socket
const MIN_PACKET_SIZE: usize = 150;
const DUPLICATE_ACKS_BEFORE_RESEND: u32 = 3;
const MAX_RETRANSMISSIONS: u32 = 5;

/// Represents a single uTP connection.
/// Similar to UTPSocket in libutp
pub struct UtpSocket {
    // Keep internal state behind a mutex to allow sharing
    pub internal: Arc<Mutex<UtpSocketInternal>>,
}

/// Internal state of the uTP socket
pub struct UtpSocketInternal {
    // Network addresses
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,

    // Connection state
    pub state: ConnectionState,

    // Connection parameters 
    pub conn: Connection,

    // Congestion controller (LEDBAT implementation)
    pub cc: CongestionControl,

    // Reliability (RTT, RTO, retransmissions, SACK)
    pub rm: ReliabilityManager,

    // Application data buffers
    pub send_buffer: VecDeque<u8>, // Data waiting to be sent
    pub recv_buffer: VecDeque<u8>, // Data waiting to be read by application

    // Packet queues
    pub incoming_packets: VecDeque<UtpPacket>, // Incoming packets from UDP
    pub outgoing_packets: VecDeque<UtpPacket>, // Outgoing packets to UDP

    // Timing information
    pub last_packet_sent_time: u64, // Microseconds
    pub last_packet_recv_time: u64, // Microseconds
    pub created_time: u64,          // Microseconds when the socket was created

    // Connection tracking
    pub duplicate_ack_count: u32,
    pub last_ack: u16,
    pub fin_sent: bool,
    pub fin_received: bool,
    pub read_shutdown: bool,
    pub close_requested: bool,
    pub last_timeout_check: u64,
    pub rto_timeout: u64,           // RTO timeout in milliseconds

    // MTU discovery
    pub mtu_probe_seq: u16,
    pub mtu_probe_size: u16,
    pub mtu_ceiling: u16,
    pub mtu_floor: u16,
    pub mtu_discovery_time: u64,
}

impl UtpSocket {
    /// Creates a new uTP socket ready to connect or listen.
    pub fn new(local_addr: SocketAddr, remote_addr: SocketAddr) -> Self {
        let current_ts_micros = current_micros();
        let internal = UtpSocketInternal {
            local_addr,
            remote_addr,
            state: ConnectionState::Idle,
            conn: Connection::new_for_initiator(remote_addr),
            cc: CongestionControl::new(),
            rm: ReliabilityManager::new(),
            send_buffer: VecDeque::new(),
            recv_buffer: VecDeque::new(),
            incoming_packets: VecDeque::new(),
            outgoing_packets: VecDeque::new(),
            last_packet_sent_time: current_ts_micros,
            last_packet_recv_time: current_ts_micros,
            created_time: current_ts_micros,
            duplicate_ack_count: 0,
            last_ack: 0,
            fin_sent: false,
            fin_received: false,
            read_shutdown: false,
            close_requested: false,
            last_timeout_check: current_ts_micros / 1000,  // Convert to milliseconds
            rto_timeout: 0,
            mtu_probe_seq: 0,
            mtu_probe_size: 0,
            mtu_ceiling: 1400,  // Default maximum MTU
            mtu_floor: 576,     // Minimum MTU that should pass
            mtu_discovery_time: current_ts_micros / 1000 + 30 * 60 * 1000, // 30 minutes from now
        };
        Self {
            internal: Arc::new(Mutex::new(internal)),
        }
    }

    /// Initiates a connection to the remote peer
    pub fn connect(&self) -> Result<(), UtpError> {
        let mut internal_guard = self.internal.lock().unwrap();
        let internal = &mut *internal_guard;

        // Can only connect from Idle state
        if internal.state != ConnectionState::Idle {
            return Err(UtpError::InvalidState);
        }

        internal.conn.initiate_connection();
        internal.state = ConnectionState::SynSent;

        // Get receive window size for the SYN packet
        let current_receive_window_size = internal.cc.get_receive_window_size() as u32;

        // Create and queue ST_SYN packet
        let syn_packet = internal.conn.create_syn_packet(current_receive_window_size);
        internal.outgoing_packets.push_back(syn_packet);
        internal.last_packet_sent_time = current_micros();

        // Set RTO timeout for the SYN packet - slightly longer than normal packets
        let rto = internal.rm.get_current_rto();
        internal.rto_timeout = current_micros() / 1000 + (rto as u64);

        println!("uTP: Queued SYN for {}", internal.remote_addr);
        Ok(())
    }

    /// Processes an incoming UDP datagram for this socket
    pub fn process_incoming_datagram(&self, data: &[u8], from_addr: SocketAddr) {
        // Quick check if the packet is for this socket
        let is_valid_source = {
            let guard = self.internal.lock().unwrap();
            from_addr == guard.remote_addr
        };

        if !is_valid_source {
            return;
        }

        // Parse the packet
        match UtpPacket::from_bytes(data, from_addr) {
            Ok(packet) => {
                let mut internal = self.internal.lock().unwrap();
                internal.incoming_packets.push_back(packet);
            },
            Err(e) => {
                eprintln!("uTP: Failed to parse incoming packet: {}", e);
            }
        }
    }

    /// Main state machine for the socket
    /// Should be called periodically to drive the connection
    /// Returns data to send over UDP if any
    pub fn tick(&self) -> Result<Option<Vec<u8>>, UtpError> {
        let mut internal_guard = self.internal.lock().unwrap();
        let internal = &mut *internal_guard;
        let current_ts_micros = current_micros();
        let current_ms = current_ts_micros / 1000;

        // Process any incoming packets
        while let Some(packet) = internal.incoming_packets.pop_front() {
            internal.last_packet_recv_time = current_ts_micros;

            // Process the packet based on its type
            internal.conn.handle_incoming_packet(
                &packet,
                &mut internal.cc,
                &mut internal.rm,
                &mut internal.recv_buffer,
                &mut internal.state,
                current_ts_micros
            );

            // Update last ack to detect duplicate acks
            internal.last_ack = packet.header.ack_nr();
        }

        // Check for timeouts if enough time has passed
        if current_ms - internal.last_timeout_check >= MAX_TIMEOUT_CHECK_INTERVAL {
            internal.last_timeout_check = current_ms;
            self.check_timeouts(&mut internal_guard);
        }

        // Send an ack if reliability manager indicates one is needed
        if internal.rm.needs_ack {
            let current_receive_window_size = internal.cc.get_receive_window_size() as u32;
            let sack_data = internal.rm.get_sack_data(internal.conn.get_ack_nr());
            let ack_packet = internal.conn.create_ack_packet(current_receive_window_size, sack_data, false);
            internal.outgoing_packets.push_back(ack_packet);
            internal.rm.needs_ack = false;
        }

        // Package and send data from the send buffer if window allows
        self.package_data_from_buffer(&mut internal_guard);

        // Send a keep-alive if needed
        if internal.state == ConnectionState::Connected && !internal.fin_sent &&
            current_ms - internal.last_packet_sent_time/1000 >= DEFAULT_KEEPALIVE_INTERVAL {
            self.send_keep_alive(&mut internal_guard);
        }

        // Send one packet if there's any pending
        if let Some(packet_to_send) = internal.outgoing_packets.pop_front() {
            internal.last_packet_sent_time = current_ts_micros;
            let mut raw_packet_data = Vec::new();
            packet_to_send.serialize(&mut raw_packet_data);
            return Ok(Some(raw_packet_data));
        }

        Ok(None)
    }

    /// Checks for various timeouts (RTO, connect timeout, etc)
    fn check_timeouts(&self, internal: &mut std::sync::MutexGuard<UtpSocketInternal>) {
        let current_ms = current_micros() / 1000;

        // Check RTO timeout for packets in flight
        if internal.rto_timeout > 0 && current_ms >= internal.rto_timeout {
            if internal.state == ConnectionState::SynSent {
                // For connection attempts, retry SYN a few times then fail
                if internal.conn.retransmit_count >= 3 {
                    internal.state = ConnectionState::Reset;
                    return;
                }
                // Resend SYN with exponential backoff
                let current_receive_window_size = internal.cc.get_receive_window_size() as u32;
                let syn_packet = internal.conn.create_syn_packet(current_receive_window_size);
                internal.outgoing_packets.push_back(syn_packet);
                internal.conn.retransmit_count += 1;

                // Exponential backoff for RTO
                let new_rto = internal.rm.get_current_rto() * 2;
                internal.rto_timeout = current_ms + (new_rto as u64);
            } else {
                // Check with reliability manager for packets to retransmit
                if let Some(retransmission_packet) = internal.rm.check_timeouts(
                    current_micros(),
                    internal.conn.get_seq_nr(),
                    &mut internal.conn.sent_packets
                ) {
                    internal.outgoing_packets.push_back(retransmission_packet);
                    internal.cc.on_timeout(); // Adjust congestion window

                    // Reset RTO timeout
                    let rto = internal.rm.get_current_rto();
                    internal.rto_timeout = current_ms + (rto as u64);
                }
            }
        }

        // Check if we've been in SYN_SENT state too long (connect timeout)
        if internal.state == ConnectionState::SynSent &&
            current_ms - internal.created_time/1000 > CONNECT_TIMEOUT {
            internal.state = ConnectionState::Reset;
        }

        // Check if we can transition from FinSent to Closed after timeout
        if internal.state == ConnectionState::FinSent &&
            current_ms - internal.last_packet_sent_time/1000 > (internal.rm.get_current_rto() as u64) * 2 {
            internal.state = ConnectionState::Closed;
        }

        // Check if we're done with a connection that's been reset
        if internal.state == ConnectionState::Reset &&
            current_ms - internal.last_packet_sent_time/1000 > 1000 {
            internal.state = ConnectionState::Destroy;
        }
    }

    /// Sends a keep-alive packet to maintain the connection
    fn send_keep_alive(&self, internal: &mut std::sync::MutexGuard<UtpSocketInternal>) {
        // Temporarily decrement ack_nr to send a duplicate ACK as a keepalive
        internal.conn.ack_nr = internal.conn.ack_nr.wrapping_sub(1);

        let current_receive_window_size = internal.cc.get_receive_window_size() as u32;
        let sack_data = internal.rm.get_sack_data(internal.conn.get_ack_nr());

        // Create and send ACK packet
        let keep_alive_packet = internal.conn.create_ack_packet(current_receive_window_size, sack_data, false);
        internal.outgoing_packets.push_back(keep_alive_packet);

        // Restore ack_nr
        internal.conn.ack_nr = internal.conn.ack_nr.wrapping_add(1);
    }

    /// Packages data from the send buffer into packets for transmission
    fn package_data_from_buffer(&self, internal: &mut std::sync::MutexGuard<UtpSocketInternal>) {
        // Only send if we're connected and have data to send
        if internal.state != ConnectionState::Connected || internal.send_buffer.is_empty() {
            return;
        }

        // Get our window sizes
        let max_window = internal.cc.get_congestion_window_size();
        let packet_size = min(1400, max_window);
        let window_available = max_window.saturating_sub(internal.conn.cur_window);

        // Don't send if window is full
        if window_available < MIN_PACKET_SIZE || packet_size < MIN_PACKET_SIZE {
            return;
        }

        // Determine how much to send
        let bytes_to_send = min(packet_size, internal.send_buffer.len());
        if bytes_to_send == 0 {
            return;
        }

        // Extract data from the send buffer
        let mut payload = Vec::with_capacity(bytes_to_send);
        for _ in 0..bytes_to_send {
            if let Some(byte) = internal.send_buffer.pop_front() {
                payload.push(byte);
            } else {
                break;
            }
        }

        // Create data packet
        let current_receive_window_size = internal.cc.get_receive_window_size() as u32;
        let sack_data = internal.rm.get_sack_data(internal.conn.get_ack_nr());
        let data_packet = internal.conn.create_data_packet(payload, current_receive_window_size, sack_data);

        // Register the packet with reliability manager
        internal.rm.on_packet_sent(&data_packet, current_micros(), &mut internal.conn.sent_packets);

        // Update congestion control
        internal.cc.on_packet_sent(data_packet.payload.len());
        internal.conn.cur_window += data_packet.payload.len();

        // Queue the packet for sending
        internal.outgoing_packets.push_back(data_packet);
    }

    /// Writes application data to the socket
    pub fn write_data(&self, data: &[u8]) -> Result<usize, UtpError> {
        let mut internal = self.internal.lock().unwrap();

        // Check if we can write
        if internal.state != ConnectionState::Connected ||
            internal.fin_sent || internal.close_requested {
            return Err(UtpError::InvalidState);
        }

        // Queue data for sending
        internal.send_buffer.extend(data.iter());

        // Data will be packaged and sent in the next tick() call
        Ok(data.len())
    }

    /// Reads received data from the socket
    pub fn read_data(&self, buffer: &mut [u8]) -> Result<usize, UtpError> {
        let mut internal = self.internal.lock().unwrap();

        // Check if we have data or if we're at EOF
        if internal.recv_buffer.is_empty() {
            if internal.fin_received ||
                internal.state == ConnectionState::Closed ||
                internal.state == ConnectionState::Reset {
                return Ok(0); // EOF
            }
            // No data available yet
            return Ok(0);
        }

        // Copy data to the provided buffer
        let mut bytes_read = 0;
        while bytes_read < buffer.len() {
            if let Some(byte) = internal.recv_buffer.pop_front() {
                buffer[bytes_read] = byte;
                bytes_read += 1;
            } else {
                break;
            }
        }

        // If we've read data and have space for more, update receive window
        if bytes_read > 0 {
            let rcv_window = internal.cc.get_receive_window_size();
            if rcv_window > 0 {
                internal.rm.needs_ack = true;
            }
        }

        Ok(bytes_read)
    }

    /// Closes the socket gracefully
    pub fn close(&self) -> Result<(), UtpError> {
        let mut internal_guard = self.internal.lock().unwrap();
        let internal = &mut *internal_guard;

        // Mark the socket for closing
        internal.close_requested = true;

        match internal.state {
            ConnectionState::Connected | ConnectionState::ConnectedFull => {
                // Send FIN if we haven't already
                if !internal.fin_sent {
                    internal.state = ConnectionState::FinSent;
                    internal.fin_sent = true;

                    // Create and queue the FIN packet
                    let current_receive_window_size = internal.cc.get_receive_window_size() as u32;
                    let fin_packet = internal.conn.create_fin_packet(current_receive_window_size);
                    internal.outgoing_packets.push_back(fin_packet);
                    internal.last_packet_sent_time = current_micros();

                    println!("uTP: Queued FIN for {}", internal.remote_addr);
                }
            },
            ConnectionState::SynSent | ConnectionState::SynRecv => {
                // Connection hasn't been established, just reset it
                internal.state = ConnectionState::Reset;
            },
            _ => {} // Other states - do nothing
        }

        Ok(())
    }

    /// Gets the current state of the socket
    pub fn get_state(&self) -> ConnectionState {
        self.internal.lock().unwrap().state
    }

    /// Gets the remote address the socket is connected to
    pub fn remote_address(&self) -> SocketAddr {
        self.internal.lock().unwrap().remote_addr
    }

    /// Checks if the socket buffers are empty (used by UtpStream)
    pub fn is_send_buffer_empty(&self) -> bool {
        let guard = self.internal.lock().unwrap();
        guard.send_buffer.is_empty() && guard.outgoing_packets.is_empty()
    }

    /// Gets the current round-trip time (RTT) in milliseconds
    pub fn get_rtt(&self) -> u32 {
        let guard = self.internal.lock().unwrap();
        guard.rm.get_latest_rtt_micros() / 1000
    }

    /// Determines if the socket is full (congestion window is full)
    pub fn is_full(&self, bytes: Option<usize>) -> bool {
        let guard = self.internal.lock().unwrap();

        let max_window = guard.cc.get_congestion_window_size();
        let additional = bytes.unwrap_or(0);

        guard.conn.cur_window + additional > max_window
    }

    /// Gets the MTU (Maximum Transmission Unit) for this connection
    pub fn get_mtu(&self) -> u16 {
        let guard = self.internal.lock().unwrap();
        min(guard.mtu_ceiling, 1500) // Reasonable maximum
    }
}
