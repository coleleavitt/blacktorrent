// utp/connection.rs

#![forbid(unsafe_code)]

use std::collections::{VecDeque, HashMap};
use std::net::SocketAddr;

use crate::utp::common::{ConnectionId, ConnectionState, ST_SYN, ST_DATA, ST_FIN, ST_STATE, ST_RESET, current_micros};
use crate::utp::packet::{UtpHeader, UtpPacket};
use crate::utp::congestion::CongestionControl;
use crate::utp::reliability::{ReliabilityManager, SentPacketInfo};

/// Manages connection state for a uTP connection including handshaking,
/// sequence/acknowledgment numbers, and packet creation
pub struct Connection {
    /// Our send connection ID (peer's receive ID)
    pub send_id: ConnectionId,

    /// Our receive connection ID (peer's send ID)
    pub recv_id: ConnectionId,

    /// Next sequence number to send
    pub seq_nr: u16,

    /// Next sequence number expected from peer / last in-order received
    pub ack_nr: u16,

    /// Peer's last advertised receive window size
    pub peer_wnd_size: u32,

    /// Information about packets we've sent that are awaiting ACK
    /// Key: seq_nr, Value: SentPacketInfo
    pub sent_packets: HashMap<u16, SentPacketInfo>,

    /// Remote peer address
    pub remote_addr: SocketAddr,

    /// Last timestamp received from peer (for timestamp_diff calculation)
    last_received_timestamp: u32,

    /// Time when we received the packet with the above timestamp
    last_received_timestamp_local: u64,
}

impl Connection {
    /// Creates a new connection as the initiator (client side)
    pub fn new_for_initiator(remote_addr: SocketAddr) -> Self {
        let initial_seq_nr = rand::random::<u16>(); // Random initial sequence number
        let conn_id = rand::random::<u16>(); // Connection ID for SYN

        Self {
            // For SYN, conn_id in header is our intended recv_id
            // Peer responds with this as their send_id
            // Our send_id will be conn_id + 1 (their recv_id)
            recv_id: conn_id,
            send_id: conn_id.wrapping_add(1),
            seq_nr: initial_seq_nr,
            ack_nr: 0, // Set from SYN-ACK's seq_nr
            peer_wnd_size: crate::utp::common::DEFAULT_MAX_PACKET_SIZE as u32 * 10, // Initial assumption
            sent_packets: HashMap::new(),
            remote_addr,
            last_received_timestamp: 0,
            last_received_timestamp_local: 0,
        }
    }

    /// Creates a new connection as the acceptor (server side)
    pub fn new_for_listener(remote_addr: SocketAddr, syn_packet: &UtpPacket) -> Self {
        // From SYN packet:
        // Our recv_id is SYN's conn_id + 1
        // Our send_id is SYN's conn_id
        Self {
            recv_id: syn_packet.header.connection_id().wrapping_add(1),
            send_id: syn_packet.header.connection_id(),
            seq_nr: rand::random::<u16>(),
            ack_nr: syn_packet.header.seq_nr(), // Ack the SYN's sequence number
            peer_wnd_size: syn_packet.header.wnd_size(),
            sent_packets: HashMap::new(),
            remote_addr,
            last_received_timestamp: syn_packet.header.timestamp_micros(),
            last_received_timestamp_local: current_micros(),
        }
    }

    /// Initiates a new connection (client side)
    pub fn initiate_connection(&mut self) {
        // Configuration already set in new_for_initiator
        // Just a hook in case we want to add initialization logic
    }

    /// Common function for creating packets of different types
    fn common_create_packet(
        &mut self,
        packet_type: u8,
        payload: Vec<u8>,
        cc: &CongestionControl,
        rm: &ReliabilityManager,
        sack_data: Option<Vec<u8>>,
    ) -> UtpPacket {
        let current_ts_micros = current_micros() as u32;

        // Calculate timestamp difference based on last received packet
        // This is the one-way delay measurement used by LEDBAT
        let timestamp_diff_micros = if self.last_received_timestamp_local > 0 {
            (current_micros() - self.last_received_timestamp_local) as u32
        } else {
            0
        };

        let header = UtpHeader::new(
            packet_type,
            self.send_id, // For non-SYN packets, conn_id is our send_id
            current_ts_micros,
            timestamp_diff_micros,
            cc.get_receive_window_size() as u32,
            self.seq_nr,
            self.ack_nr,
            if sack_data.is_some() { 1 } else { 0 }, // Extension type: 1 for SACK
        );

        let packet = UtpPacket {
            header,
            payload,
            sack_data,
            remote_addr: self.remote_addr,
        };

        if packet_type == ST_DATA || packet_type == ST_FIN || packet_type == ST_SYN {
            // Only increment seq_nr for packets that consume a sequence number
            // Special case for SYN if initial_seq_nr was 0
            if packet_type == ST_SYN && self.seq_nr == 0 {
                // libutp does this for SYN sometimes
                // self.seq_nr = 1;
            }
            self.seq_nr = self.seq_nr.wrapping_add(1);
        }

        packet
    }

    /// Creates a SYN packet to initiate a connection
    pub fn create_syn_packet(&mut self, cc: &CongestionControl, _rm: &ReliabilityManager) -> UtpPacket {
        let current_ts_micros = current_micros() as u32;

        let header = UtpHeader::new(
            ST_SYN,
            self.recv_id, // SYN uses our intended recv_id as conn_id
            current_ts_micros,
            0, // No timestamp_diff for first packet
            cc.get_receive_window_size() as u32,
            self.seq_nr,
            0, // ack_nr is 0 for initial SYN
            0, // No extensions initially
        );

        let packet = UtpPacket {
            header,
            payload: Vec::new(),
            sack_data: None,
            remote_addr: self.remote_addr,
        };

        self.seq_nr = self.seq_nr.wrapping_add(1); // SYN consumes a sequence number
        packet
    }

    /// Creates a DATA packet with payload
    pub fn create_data_packet(&mut self, payload: Vec<u8>, cc: &CongestionControl, rm: &ReliabilityManager) -> UtpPacket {
        self.common_create_packet(ST_DATA, payload, cc, rm, rm.get_sack_data(self.ack_nr))
    }

    /// Creates an ACK packet (ST_STATE)
    pub fn create_ack_packet(&mut self, cc: &CongestionControl, rm: &ReliabilityManager, is_synack: bool) -> UtpPacket {
        // For SYN-ACK, logic is slightly different
        // ack_nr is peer's SYN seq_nr
        // Our seq_nr is our initial random one
        // conn_id is our send_id (which is peer's SYN conn_id)
        if is_synack {
            // This could configure specific SYN-ACK state if needed
        }

        self.common_create_packet(ST_STATE, Vec::new(), cc, rm, rm.get_sack_data(self.ack_nr))
    }

    /// Creates a FIN packet to close the connection
    pub fn create_fin_packet(&mut self, cc: &CongestionControl, rm: &ReliabilityManager) -> UtpPacket {
        self.common_create_packet(ST_FIN, Vec::new(), cc, rm, None)
    }

    /// Handles an incoming packet and updates connection state accordingly
    pub fn handle_incoming_packet(
        &mut self,
        packet: &UtpPacket,
        cc: &mut CongestionControl,
        rm: &mut ReliabilityManager,
        recv_buffer: &mut VecDeque<u8>,
        current_state: &mut ConnectionState,
        current_ts_micros: u64,
    ) {
        // Basic validation - verify packet's connection ID matches our recv_id (except for SYN)
        if packet.header.packet_type() != ST_SYN && packet.header.connection_id() != self.recv_id {
            eprintln!(
                "uTP: Received packet with mismatched connection ID. Expected {}, got {}",
                self.recv_id, packet.header.connection_id()
            );
            return;
        }

        // Update peer window size
        self.peer_wnd_size = packet.header.wnd_size();

        // Update timestamp tracking for one-way delay measurement
        self.last_received_timestamp = packet.header.timestamp_micros();
        self.last_received_timestamp_local = current_ts_micros;

        // Process ACKs
        let received_ack_nr = packet.header.ack_nr();
        let newly_acked_bytes = rm.process_ack(
            received_ack_nr,
            packet.sack_data.as_deref(),
            &mut self.sent_packets,
            current_ts_micros
        );

        // Update congestion control if we received ACKs
        if newly_acked_bytes > 0 {
            cc.on_ack_received(
                newly_acked_bytes,
                rm.get_latest_rtt_micros(),
                rm.get_min_rtt_micros(),
                packet.header.timestamp_micros(),        // Added missing parameter
                packet.header.timestamp_diff_micros()    // Added missing parameter
            );
        }

        // Handle packet based on type
        match packet.header.packet_type() {
            ST_SYN => {
                // SYN handling differs based on our current state
                if *current_state == ConnectionState::Idle || *current_state == ConnectionState::SynSent {
                    if *current_state == ConnectionState::SynSent {
                        // Handle SYN-ACK for our outgoing connection
                        if packet.header.ack_nr() == self.seq_nr.wrapping_sub(1) {
                            self.ack_nr = packet.header.seq_nr();
                            *current_state = ConnectionState::Connected;
                            println!("uTP: Connection established with {}", self.remote_addr);
                        }
                    }
                }
            },

            ST_STATE => {
                // ACKs processed via rm.process_ack above
                // No payload to handle
            },

            ST_DATA => {
                if *current_state == ConnectionState::Connected || *current_state == ConnectionState::ConnectedFull {
                    // Check for in-order delivery
                    if packet.header.seq_nr() == self.ack_nr.wrapping_add(1) {
                        // In-order packet - process directly
                        self.ack_nr = self.ack_nr.wrapping_add(1);
                        recv_buffer.extend(&packet.payload);
                        rm.needs_ack = true;
                    } else {
                        // Out-of-order packet - buffer for future processing
                        rm.buffer_ooo_packet(packet);
                        rm.needs_ack = true; // Send SACK
                    }
                }
            },

            ST_FIN => {
                if *current_state == ConnectionState::Connected || *current_state == ConnectionState::ConnectedFull {
                    // Connection teardown initiated by peer
                    self.ack_nr = packet.header.seq_nr();
                    *current_state = ConnectionState::FinRecv;
                    rm.needs_ack = true; // ACK the FIN
                    println!("uTP: Received FIN from {}", self.remote_addr);
                }
            },

            ST_RESET => {
                // Connection reset by peer
                *current_state = ConnectionState::Reset;
                println!("uTP: Received RESET from {}", self.remote_addr);
            },

            _ => {} // Unknown packet type
        }

        // Update our ack_nr based on SACK logic
        self.ack_nr = rm.update_cumulative_ack(self.ack_nr);
    }

    // Accessor methods
    pub fn get_seq_nr(&self) -> u16 { self.seq_nr }
    pub fn get_ack_nr(&self) -> u16 { self.ack_nr }
    pub fn get_sent_packets(&self) -> &HashMap<u16, SentPacketInfo> {
        &self.sent_packets
    }

    /// Gets timestamp values for RTT calculation
    pub fn get_timestamp_values(&self) -> (u32, u64) {
        (self.last_received_timestamp, self.last_received_timestamp_local)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utp::common::current_micros;

    #[test]
    fn test_connection_id_setup_initiator() {
        let remote = SocketAddr::from(([127, 0, 0, 1], 8080));
        let conn = Connection::new_for_initiator(remote);

        // Verify that send_id = recv_id + 1 (for initiator)
        assert_eq!(conn.send_id, conn.recv_id.wrapping_add(1));
    }

    #[test]
    fn test_syn_packet_creation() {
        let remote = SocketAddr::from(([127, 0, 0, 1], 8080));
        let mut conn = Connection::new_for_initiator(remote);
        let old_seq = conn.seq_nr;

        // Mock the dependencies
        let cc = CongestionControl::new();
        let rm = ReliabilityManager::new();

        // Create a SYN packet
        let syn = conn.create_syn_packet(&cc, &rm);

        // Verify packet properties
        assert_eq!(syn.header.packet_type(), ST_SYN);
        assert_eq!(syn.header.connection_id(), conn.recv_id);
        assert_eq!(syn.header.seq_nr(), old_seq);
        assert_eq!(syn.header.ack_nr(), 0);

        // Verify sequence number was incremented
        assert_eq!(conn.seq_nr, old_seq.wrapping_add(1));
    }

    #[test]
    fn test_data_packet_creation() {
        let remote = SocketAddr::from(([127, 0, 0, 1], 8080));
        let mut conn = Connection::new_for_initiator(remote);
        let payload = b"Hello, uTP!".to_vec();
        let old_seq = conn.seq_nr;

        // Mock the dependencies
        let cc = CongestionControl::new();
        let rm = ReliabilityManager::new();

        // Create a DATA packet
        let data_pkt = conn.create_data_packet(payload.clone(), &cc, &rm);

        // Verify packet properties
        assert_eq!(data_pkt.header.packet_type(), ST_DATA);
        assert_eq!(data_pkt.header.seq_nr(), old_seq);
        assert_eq!(data_pkt.payload, payload);

        // Verify sequence number was incremented
        assert_eq!(conn.seq_nr, old_seq.wrapping_add(1));
    }

    #[test]
    fn test_ack_packet_creation() {
        let remote = SocketAddr::from(([127, 0, 0, 1], 8080));
        let mut conn = Connection::new_for_initiator(remote);
        conn.ack_nr = 42; // Set an ack number

        // Mock the dependencies
        let cc = CongestionControl::new();
        let rm = ReliabilityManager::new();

        // Create an ACK packet
        let ack_pkt = conn.create_ack_packet(&cc, &rm, false);

        // Verify packet properties
        assert_eq!(ack_pkt.header.packet_type(), ST_STATE);
        assert_eq!(ack_pkt.header.ack_nr(), 42);
        assert!(ack_pkt.payload.is_empty());

        // Sequence number should not increment for ACKs
        assert_eq!(conn.seq_nr, conn.seq_nr);
    }

    #[test]
    fn test_fin_packet_creation() {
        let remote = SocketAddr::from(([127, 0, 0, 1], 8080));
        let mut conn = Connection::new_for_initiator(remote);
        let old_seq = conn.seq_nr;

        // Mock the dependencies
        let cc = CongestionControl::new();
        let rm = ReliabilityManager::new();

        // Create a FIN packet
        let fin_pkt = conn.create_fin_packet(&cc, &rm);

        // Verify packet properties
        assert_eq!(fin_pkt.header.packet_type(), ST_FIN);
        assert_eq!(fin_pkt.header.seq_nr(), old_seq);
        assert!(fin_pkt.payload.is_empty());

        // Verify sequence number was incremented
        assert_eq!(conn.seq_nr, old_seq.wrapping_add(1));
    }

    #[test]
    fn test_timestamp_tracking() {
        let remote = SocketAddr::from(([127, 0, 0, 1], 8080));
        let mut conn = Connection::new_for_initiator(remote);

        // Mock incoming packet with timestamp
        let test_timestamp = 12345678u32;
        let before_time = current_micros();

        // Create a packet header with our test timestamp
        let header = UtpHeader::new(
            ST_STATE,
            conn.recv_id,
            test_timestamp,
            0,
            1000,
            1,
            0,
            0
        );

        // Create packet
        let packet = UtpPacket {
            header,
            payload: Vec::new(),
            sack_data: None,
            remote_addr: remote,
        };

        // Mock dependencies for handling
        let mut cc = CongestionControl::new();
        let mut rm = ReliabilityManager::new();
        let mut buffer = VecDeque::new();
        let mut state = ConnectionState::Connected;
        let now = current_micros();

        // Process the packet
        conn.handle_incoming_packet(&packet, &mut cc, &mut rm, &mut buffer, &mut state, now);

        // Verify timestamp tracking
        let (stored_timestamp, stored_local_time) = conn.get_timestamp_values();
        assert_eq!(stored_timestamp, test_timestamp);
        assert!(stored_local_time >= before_time);
        assert!(stored_local_time <= current_micros());
    }
}
