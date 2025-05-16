// utp/socket.rs
#![forbid(unsafe_code)]

use crate::utp::common::{ConnectionState, UtpError, current_micros, UtpSocketStats, ST_SYN, ST_DATA, ST_STATE, ST_FIN};
use crate::utp::packet::{UtpPacket, BASE_HEADER_SIZE};
use crate::utp::connection::Connection;
use crate::utp::congestion::CongestionControl;
use crate::utp::reliability::ReliabilityManager;

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::cmp::{max, min};

/// Default interval for sending keepalive packets (in milliseconds)
const DEFAULT_KEEPALIVE_INTERVAL: u64 = 29_000;
/// Timeout for connection establishment (in milliseconds)
const CONNECT_TIMEOUT: u64 = 6_000;
/// Interval between timeout checks (in milliseconds)
const MAX_TIMEOUT_CHECK_INTERVAL: u64 = 500;
/// Minimum size for packet payload (in bytes)
const MIN_PACKET_SIZE: usize = 150;
/// Maximum number of retransmission attempts before giving up
const MAX_RETRANSMISSIONS: u32 = 5;

/// A uTP socket managing a connection between a local and remote endpoint
pub struct UtpSocket {
    pub(crate) internal: Arc<Mutex<UtpSocketInternal>>,
}

/// Internal state of the uTP socket
pub struct UtpSocketInternal {
    pub(crate) local_addr: SocketAddr,
    pub(crate) remote_addr: SocketAddr,
    pub(crate) state: ConnectionState,
    pub(crate) conn: Connection,
    pub(crate) cc: CongestionControl,
    pub(crate) rm: ReliabilityManager,
    pub(crate) send_buffer: VecDeque<u8>,
    pub(crate) recv_buffer: VecDeque<u8>,
    pub(crate) incoming_packets: VecDeque<UtpPacket>,
    pub(crate) outgoing_packets: VecDeque<UtpPacket>,
    pub(crate) last_packet_sent_time: u64,
    pub(crate) last_packet_recv_time: u64,
    pub(crate) created_time: u64,
    pub(crate) last_timeout_check: u64,
    pub(crate) rto_timeout: u64,
    pub(crate) retransmit_count: u32,
    pub(crate) needs_ack: bool,
    pub(crate) fin_sent: bool,
    pub(crate) fin_received: bool,
    pub(crate) close_requested: bool,
    /// Connection statistics for monitoring
    pub(crate) stats: UtpSocketStats,
}

impl UtpSocketInternal {
    /// Get the maximum transmission unit (MTU) for this socket
    fn get_mtu(&self) -> usize {
        min(1500, self.cc.get_receive_window_size())
    }

    /// Create a SYN packet to initiate a connection
    fn create_syn(&mut self) -> UtpPacket {
        self.conn.create_syn_packet(&self.cc, &self.rm)
    }

    /// Create an ACK packet to acknowledge received data
    fn create_ack(&mut self, is_synack: bool) -> UtpPacket {
        self.conn.create_ack_packet(&self.cc, &self.rm, is_synack)
    }

    /// Create a DATA packet with payload
    fn create_data(&mut self, payload: Vec<u8>) -> UtpPacket {
        self.conn.create_data_packet(payload, &self.cc, &self.rm)
    }

    /// Create a FIN packet to close the connection
    fn create_fin(&mut self) -> UtpPacket {
        self.conn.create_fin_packet(&self.cc, &self.rm)
    }

    /// Check for packet timeouts and handle them
    fn check_timeouts(&mut self, now_ms: u64) {
        // Check RTO timeout
        if self.rto_timeout > 0 && now_ms >= self.rto_timeout {
            if self.state == ConnectionState::SynSent {
                // Handle SYN timeout - retransmit or reset
                if self.retransmit_count >= MAX_RETRANSMISSIONS {
                    self.state = ConnectionState::Reset;
                    return;
                }
                // Retransmit SYN packet
                let syn = self.create_syn();
                self.outgoing_packets.push_back(syn);
                self.retransmit_count += 1;
                self.stats.packets_retransmitted += 1;

                // Exponential backoff for RTO
                let new_rto = self.rm.get_current_rto() as u64 * 2;
                self.rm.current_rto = new_rto as u32;
                self.rto_timeout = now_ms + new_rto;
            } else if let Some(timed_out_seq) = self.rm.check_timeouts(current_micros()) {
                // A packet timed out and needs retransmission
                self.cc.on_timeout();
                self.stats.packets_lost += 1;

                // Retransmit the timed-out packet, if found in sent_packets
                if let Some(packet_info) = self.conn.sent_packets.get(&timed_out_seq).cloned() {
                    if packet_info.transmissions < MAX_RETRANSMISSIONS {
                        // Create packet from stored data
                        if let Ok(pkt) = UtpPacket::from_bytes(&packet_info.packet_data, self.remote_addr) {
                            self.outgoing_packets.push_back(pkt);
                            self.stats.packets_retransmitted += 1;
                            self.stats.bytes_retransmitted += packet_info.size_bytes as u64;

                            // Update transmission count in sent_packets
                            if let Some(info) = self.conn.sent_packets.get_mut(&timed_out_seq) {
                                info.transmissions += 1;
                                info.need_resend = false;
                                // Update sent_at_micros to track RTT correctly for retransmitted packets
                                info.sent_at_micros = current_micros();
                            }
                        }
                    } else {
                        // Too many retransmissions, reset connection
                        self.state = ConnectionState::Reset;
                    }
                }

                // Set next RTO - use current_ts_micros/1000 instead of now_ms to avoid timing issues
                let rto = self.rm.get_current_rto() as u64;
                self.rto_timeout = current_micros() / 1_000 + rto;
            }
        }

        // Check connection timeout
        if self.state == ConnectionState::SynSent &&
            now_ms.saturating_sub(self.created_time / 1_000) > CONNECT_TIMEOUT {
            self.state = ConnectionState::Reset;
        }

        // Check FIN timeout
        if self.state == ConnectionState::FinSent &&
            now_ms.saturating_sub(self.last_packet_sent_time / 1_000) >
                (self.rm.get_current_rto() as u64 * 2) {
            self.state = ConnectionState::Closed;
        }

        // Move from Reset to Destroying after delay
        if self.state == ConnectionState::Reset &&
            now_ms.saturating_sub(self.last_packet_sent_time / 1_000) > 1_000 {
            self.state = ConnectionState::Destroying;
        }
    }

    /// Package data from buffer into DATA packets
    fn package_data_from_buffer(&mut self) {
        if self.state != ConnectionState::Connected || self.send_buffer.is_empty() {
            return;
        }

        // Calculate maximum payload size
        let cwnd = self.cc.get_congestion_window_size();
        let max_payload = min(cwnd, self.get_mtu() - BASE_HEADER_SIZE);
        let in_flight = self.cc.bytes_in_flight();
        let avail = cwnd.saturating_sub(in_flight);

        // Check if we have enough congestion window
        if avail < MIN_PACKET_SIZE || max_payload < MIN_PACKET_SIZE {
            return;
        }

        // Create packet with data from buffer
        let to_send = min(max_payload, self.send_buffer.len());
        let mut payload = Vec::with_capacity(to_send);
        for _ in 0..to_send {
            if let Some(b) = self.send_buffer.pop_front() {
                payload.push(b);
            }
        }

        // Create and queue packet
        let pkt = self.create_data(payload);
        let payload_size = pkt.payload_size();
        self.cc.on_packet_sent(payload_size);
        self.outgoing_packets.push_back(pkt);
        self.stats.bytes_sent += payload_size as u64;
    }

    /// Send keepalive to maintain connection
    fn send_keep_alive(&mut self) {
        let ka = self.create_ack(false);
        self.outgoing_packets.push_back(ka);
    }

    /// Process incoming packet
    fn process_packet(&mut self, pkt: &UtpPacket, now_us: u64) {
        // Special handling for SYN-ACKs during connection establishment
        if self.state == ConnectionState::SynSent &&
            pkt.header.packet_type() == ST_STATE {
            // The responder must use recv_id for connection ID in SYN-ACK per uTP spec
            if pkt.header.connection_id() == self.conn.recv_id {
                // Verify this is a valid SYN-ACK - must acknowledge our SYN
                if pkt.header.ack_nr() == self.conn.seq_nr.wrapping_sub(1) {
                    // Update our ack_nr to peer's seq_nr
                    self.conn.ack_nr = pkt.header.seq_nr();

                    // Move to connected state
                    self.state = ConnectionState::Connected;

                    // Update RTT stats
                    let rtt_sample = (now_us - self.created_time) as u32;
                    self.stats.rtt_samples += 1;
                    self.stats.min_rtt = if self.stats.min_rtt == 0 { rtt_sample } else { min(self.stats.min_rtt, rtt_sample) };
                    self.stats.max_rtt = max(self.stats.max_rtt, rtt_sample);
                    self.stats.sum_rtt += rtt_sample as u64;

                    // Need to send ACK for the SYN-ACK
                    self.needs_ack = true;

                    return;
                }
            } else {
                // Log the mismatch for debugging
                println!("uTP: Received packet with mismatched connection ID. Expected {}, got {}",
                         self.conn.recv_id, pkt.header.connection_id());
            }
        }

        // Regular packet processing
        self.conn.handle_incoming_packet(
            &pkt,
            &mut self.cc,
            &mut self.rm,
            &mut self.recv_buffer,
            &mut self.state,
            now_us
        );

        // Always set needs_ack to true when receiving a packet
        self.needs_ack = true;

        // Update peer window size from packet
        self.conn.peer_wnd_size = pkt.header.wnd_size();

        // Check for state transitions
        if pkt.header.packet_type() == ST_FIN {
            self.fin_received = true;
            if self.fin_sent {
                // Both sides have sent FIN, move to closed
                self.state = ConnectionState::Closed;
            }
        }
    }
}

impl UtpSocket {
    /// Create a new uTP socket
    pub fn new(local: SocketAddr, remote: SocketAddr) -> Self {
        let now = current_micros();
        let internal = UtpSocketInternal {
            local_addr: local,
            remote_addr: remote,
            state: ConnectionState::Idle,
            conn: Connection::new_for_initiator(remote),
            cc: CongestionControl::new(),
            rm: ReliabilityManager::new(),
            send_buffer: VecDeque::new(),
            recv_buffer: VecDeque::new(),
            incoming_packets: VecDeque::new(),
            outgoing_packets: VecDeque::new(),
            last_packet_sent_time: now,
            last_packet_recv_time: now,
            created_time: now,
            last_timeout_check: now / 1_000,
            rto_timeout: 0,
            retransmit_count: 0,
            needs_ack: false,
            fin_sent: false,
            fin_received: false,
            close_requested: false,
            stats: UtpSocketStats::default(),
        };
        UtpSocket { internal: Arc::new(Mutex::new(internal)) }
    }

    /// Initiate a connection to the remote peer
    pub fn connect(&self) -> Result<(), UtpError> {
        let mut i = self.internal.lock().unwrap();
        if i.state != ConnectionState::Idle {
            return Err(UtpError::InvalidState);
        }

        i.conn.initiate_connection();
        i.state = ConnectionState::SynSent;

        // Create and queue SYN packet
        let syn = i.create_syn();
        i.outgoing_packets.push_back(syn);
        i.last_packet_sent_time = current_micros();

        // Set up RTO timer
        let rto = i.rm.get_current_rto() as u64;
        i.rto_timeout = current_micros() / 1_000 + rto;
        i.stats.packets_sent += 1;

        Ok(())
    }

    /// Process an incoming datagram
    pub fn process_incoming_datagram(&self, data: &[u8], from: SocketAddr) {
        // Verify packet is from expected peer
        let valid = { self.internal.lock().unwrap().remote_addr == from };
        if !valid { return; }

        // Parse packet and queue for processing
        if let Ok(pkt) = UtpPacket::from_bytes(data, from) {
            let mut guard = self.internal.lock().unwrap();
            guard.incoming_packets.push_back(pkt);
            guard.stats.packets_received += 1;
            guard.stats.bytes_received += data.len() as u64;
        }
    }

    /// Process socket state and return any outgoing packets
    pub fn tick(&self) -> Result<Option<Vec<u8>>, UtpError> {
        let mut i = self.internal.lock().unwrap();
        let now_us = current_micros();
        let now_ms = now_us / 1_000;

        // Process incoming packets
        while let Some(pkt) = i.incoming_packets.pop_front() {
            i.last_packet_recv_time = now_us;

            // Process the packet
            i.process_packet(&pkt, now_us);
        }

        // Check timeouts periodically
        if now_ms.saturating_sub(i.last_timeout_check) >= MAX_TIMEOUT_CHECK_INTERVAL {
            i.last_timeout_check = now_ms;
            i.check_timeouts(now_ms);
        }

        // Send ACK if needed
        if i.needs_ack {
            let ack = i.create_ack(false);
            i.outgoing_packets.push_back(ack);
            i.needs_ack = false;
            i.stats.packets_sent += 1;
        }

        // Package data from buffer
        i.package_data_from_buffer();

        // Send keepalive if needed
        if i.state == ConnectionState::Connected
            && !i.fin_sent
            && now_ms.saturating_sub(i.last_packet_sent_time / 1_000) >= DEFAULT_KEEPALIVE_INTERVAL
        {
            i.send_keep_alive();
            i.stats.packets_sent += 1;
        }

        // Emit packet if any
        if let Some(outgoing_pkt) = i.outgoing_packets.pop_front() {
            i.last_packet_sent_time = now_us;
            let ty = outgoing_pkt.header.packet_type();

            // Track data packets for retransmission
            if ty == ST_DATA || ty == ST_SYN {
                // Use destructuring pattern to get mutable references to fields
                let UtpSocketInternal { rm, conn, .. } = &mut *i;
                rm.on_packet_sent(&outgoing_pkt, now_us, &mut conn.sent_packets);
            }

            // Serialize packet for transmission
            let mut buf = Vec::new();
            outgoing_pkt.serialize(&mut buf);
            return Ok(Some(buf));
        }

        Ok(None)
    }

    /// Write data to the send buffer
    pub fn write_data(&self, data: &[u8]) -> Result<usize, UtpError> {
        let mut i = self.internal.lock().unwrap();

        // Check connection state
        if i.state != ConnectionState::Connected || i.fin_sent || i.close_requested {
            return Err(UtpError::InvalidState);
        }

        // Add data to send buffer
        i.send_buffer.extend(data);
        Ok(data.len())
    }

    /// Read data from the receive buffer
    pub fn read_data(&self, buf: &mut [u8]) -> Result<usize, UtpError> {
        let mut i = self.internal.lock().unwrap();

        // Check if data is available
        if i.recv_buffer.is_empty() {
            // Return EOF for terminated connections
            if i.fin_received
                || i.state == ConnectionState::Closed
                || i.state == ConnectionState::Reset
            {
                return Ok(0);
            }

            // No data available yet
            return Err(UtpError::Network(std::io::Error::new(
                std::io::ErrorKind::WouldBlock, "No data available",
            )));
        }

        // Copy data to provided buffer
        let mut n = 0;
        while n < buf.len() {
            if let Some(b) = i.recv_buffer.pop_front() {
                buf[n] = b;
                n += 1;
            } else {
                break;
            }
        }

        // Signal need for ACK after reading
        if n > 0 {
            i.needs_ack = true;
        }

        Ok(n)
    }

    /// Close the connection
    pub fn close(&self) -> Result<(), UtpError> {
        let mut i = self.internal.lock().unwrap();
        i.close_requested = true;

        match i.state {
            ConnectionState::Connected | ConnectionState::ConnectedFull => {
                if !i.fin_sent {
                    i.state = ConnectionState::FinSent;
                    i.fin_sent = true;

                    // Create and queue FIN
                    let fin = i.create_fin();
                    i.outgoing_packets.push_back(fin);
                    i.last_packet_sent_time = current_micros();
                    i.stats.packets_sent += 1;
                }
            }
            ConnectionState::SynSent | ConnectionState::SynRecv => {
                // If still connecting, reset
                i.state = ConnectionState::Reset;
            }
            _ => {} // No action needed for other states
        }

        Ok(())
    }

    /// Get current connection state
    pub fn get_state(&self) -> ConnectionState {
        self.internal.lock().unwrap().state
    }

    /// Get remote address
    pub fn remote_address(&self) -> SocketAddr {
        self.internal.lock().unwrap().remote_addr
    }

    /// Get current RTT in milliseconds
    pub fn get_rtt(&self) -> u32 {
        self.internal.lock().unwrap().rm.get_latest_rtt_micros() / 1_000
    }

    /// Get MTU size in bytes
    pub fn get_mtu(&self) -> usize {
        self.internal.lock().unwrap().get_mtu()
    }

    /// Check if send buffer is empty
    pub fn is_send_buffer_empty(&self) -> bool {
        self.internal.lock().unwrap().send_buffer.is_empty()
    }

    /// Get connection ID
    pub fn connection_id(&self) -> u16 {
        self.internal.lock().unwrap().conn.recv_id
    }

    /// Get connection statistics
    pub fn get_stats(&self) -> UtpSocketStats {
        self.internal.lock().unwrap().stats.clone()
    }

    /// Initialize from existing connection ID
    pub async fn initialize_from_connection(&self, conn_id: u16) -> Result<(), UtpError> {
        let mut internal = self.internal.lock().unwrap();

        // Setup connection IDs properly
        internal.conn.recv_id = conn_id;
        internal.conn.send_id = conn_id.wrapping_sub(1);

        // Initialize state for accepted connection
        internal.state = ConnectionState::Connected;
        internal.created_time = current_micros();
        internal.last_packet_recv_time = current_micros();
        internal.rm.current_rto = crate::utp::common::INITIAL_RTO_MICROS;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use crate::utp::packet::UtpHeader;

    fn create_test_socket() -> UtpSocket {
        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1234);
        let remote_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5678);
        UtpSocket::new(local_addr, remote_addr)
    }

    fn create_packet(packet_type: u8, conn_id: u16, seq_nr: u16, ack_nr: u16, payload: &[u8]) -> UtpPacket {
        let header = UtpHeader::new(
            packet_type,
            conn_id,
            current_micros() as u32,
            0,
            1000,
            seq_nr,
            ack_nr,
            0
        );

        UtpPacket {
            header,
            payload: payload.to_vec(),
            sack_data: None,
            remote_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5678),
        }
    }

    fn serialize_packet(packet: &UtpPacket) -> Vec<u8> {
        let mut buf = Vec::new();
        packet.serialize(&mut buf);
        buf
    }

    #[test]
    fn test_socket_creation() {
        let socket = create_test_socket();
        assert_eq!(socket.get_state(), ConnectionState::Idle);
    }

    #[test]
    fn test_socket_connect() {
        let socket = create_test_socket();
        socket.connect().unwrap();
        assert_eq!(socket.get_state(), ConnectionState::SynSent);

        // Verify SYN packet is queued
        let output = socket.tick().unwrap();
        assert!(output.is_some());
    }

    #[test]
    fn test_write_and_read_data() {
        let socket = create_test_socket();

        // Set connected state
        {
            let mut internal = socket.internal.lock().unwrap();
            internal.state = ConnectionState::Connected;
        }

        // Write test data
        let test_data = b"Hello, uTP!";
        let bytes_written = socket.write_data(test_data).unwrap();
        assert_eq!(bytes_written, test_data.len());

        // Process tick to generate packet
        let output = socket.tick().unwrap();
        assert!(output.is_some());

        // Simulate receiving data
        let recv_id = socket.connection_id();
        let remote_addr = socket.remote_address();
        let data_packet = create_packet(ST_DATA, recv_id, 1, 0, b"Received data");
        socket.process_incoming_datagram(&serialize_packet(&data_packet), remote_addr);

        // Process incoming packet
        socket.tick().unwrap();

        // Read data
        let mut read_buf = [0u8; 20];
        let bytes_read = socket.read_data(&mut read_buf).unwrap();
        assert_eq!(bytes_read, b"Received data".len());
        assert_eq!(&read_buf[..bytes_read], b"Received data");
    }

    #[test]
    fn test_connection_establishment() {
        let socket = create_test_socket();

        // Initiate connection
        socket.connect().unwrap();

        // Extract SYN packet
        let _ = socket.tick().unwrap();

        // Get initial sequence number and connection IDs
        let (_, recv_id) = {
            let internal = socket.internal.lock().unwrap();
            (internal.conn.send_id, internal.conn.recv_id)
        };
        let initial_seq_nr = recv_id.wrapping_sub(1); // SYN consumes a seq nr

        // Create SYN-ACK using RECV_ID for connection ID (not send_id)
        // This matches how uTP protocol works - the responder uses the initiator's recv_id
        let remote_addr = socket.remote_address();
        let synack = create_packet(ST_STATE, recv_id, 1, initial_seq_nr, &[]);
        socket.process_incoming_datagram(&serialize_packet(&synack), remote_addr);

        // Process the SYN-ACK
        socket.tick().unwrap();

        // Should be connected now
        assert_eq!(socket.get_state(), ConnectionState::Connected);
    }

    #[test]
    fn test_async_initialize() {
        let socket = create_test_socket();

        // Use tokio runtime for async test
        let rt = tokio::runtime::Runtime::new().unwrap();

        rt.block_on(async {
            // Initialize with existing connection ID
            let conn_id = 12345;
            socket.initialize_from_connection(conn_id).await.unwrap();

            assert_eq!(socket.connection_id(), conn_id);
            assert_eq!(socket.get_state(), ConnectionState::Connected);
        });
    }

    #[test]
    fn test_packet_retransmission() {
        let socket = create_test_socket();
        let current_time = current_micros();

        // Set up connected state and prepare for retransmission test
        {
            let mut internal = socket.internal.lock().unwrap();
            internal.state = ConnectionState::Connected;

            // Set retransmission timeout to a value in the past to trigger immediately
            internal.rto_timeout = (current_time / 1000).saturating_sub(1);

            // Mock a sent but unacked packet
            let test_packet = create_packet(ST_DATA, internal.conn.send_id, 1, 0, b"Test data");
            let mut packet_data = Vec::new();
            test_packet.serialize(&mut packet_data);

            // Create SentPacketInfo with need_resend=true to ensure it gets retransmitted
            let packet_info = crate::utp::reliability::SentPacketInfo::new(
                1,                                      // seq_nr
                current_time.saturating_sub(1_000_000), // sent_at_micros (1 second ago)
                packet_data.len(),                      // size_bytes
                1,                                      // transmissions
                packet_data,                            // packet_data
                false,                                  // is_syn
                true                                    // need_resend - IMPORTANT: marked for retransmission
            );

            internal.conn.sent_packets.insert(1, packet_info);

            // Ensure the reliability manager will pick this packet for retransmission
            internal.rm.set_needs_retransmit(1);

            // Ensure timeout value is set properly
            internal.last_timeout_check = 0; // Force timeout check immediately
        }

        // Run multiple ticks to ensure processing
        for _ in 0..3 {
            let _ = socket.tick().unwrap();
        }

        // Check stats after multiple ticks
        let stats = socket.get_stats();
        assert!(stats.packets_retransmitted > 0, "Packet was not retransmitted");
    }

    #[test]
    fn test_connection_close() {
        let socket = create_test_socket();

        // Set connected state
        {
            let mut internal = socket.internal.lock().unwrap();
            internal.state = ConnectionState::Connected;
        }

        // Close the connection
        socket.close().unwrap();

        // Should be in FIN_SENT state
        assert_eq!(socket.get_state(), ConnectionState::FinSent);

        // Should have a FIN packet queued
        let fin_data = socket.tick().unwrap();
        assert!(fin_data.is_some());

        // Simulate receiving FIN-ACK
        let remote_addr = socket.remote_address();
        let send_id = {
            let internal = socket.internal.lock().unwrap();
            internal.conn.send_id
        };
        let fin_ack = create_packet(ST_FIN, send_id, 1, 0, &[]);
        socket.process_incoming_datagram(&serialize_packet(&fin_ack), remote_addr);

        // Process the FIN-ACK
        socket.tick().unwrap();

        // Should be in Closed state
        assert_eq!(socket.get_state(), ConnectionState::Closed);
    }
}
