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
        rm: &ReliabilityManager, // rm is now used for get_sack_data
        sack_data: Option<Vec<u8>>,
    ) -> UtpPacket {
        let current_ts_micros = current_micros() as u32;

        let timestamp_diff_micros = if self.last_received_timestamp_local > 0 {
            // Ensure subtraction doesn't underflow if current_micros is somehow less
            // (though with monotonic clocks this shouldn't happen often)
            current_micros().saturating_sub(self.last_received_timestamp_local) as u32
        } else {
            0
        };

        let header = UtpHeader::new(
            packet_type,
            self.send_id,
            current_ts_micros,
            timestamp_diff_micros,
            cc.get_receive_window_size() as u32,
            self.seq_nr,
            self.ack_nr,
            if sack_data.is_some() { 1 } else { 0 },
        );

        let packet = UtpPacket {
            header,
            payload,
            sack_data,
            remote_addr: self.remote_addr,
        };

        if packet_type == ST_DATA || packet_type == ST_FIN || packet_type == ST_SYN {
            self.seq_nr = self.seq_nr.wrapping_add(1);
        }

        packet
    }

    /// Creates a SYN packet to initiate a connection
    pub fn create_syn_packet(&mut self, cc: &CongestionControl, rm: &ReliabilityManager) -> UtpPacket {
        // SYN packets use recv_id in the connection_id field of the header.
        // common_create_packet uses self.send_id by default.
        // So, we handle SYN packet creation specially.
        let current_ts_micros = current_micros() as u32;

        let header = UtpHeader::new(
            ST_SYN,
            self.recv_id, // Crucial: SYN uses our intended recv_id as conn_id
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
            sack_data: None, // No SACK in SYN
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
        if is_synack {
            // For SYN-ACK, the connection_id in the header is our send_id (which is peer's SYN conn_id)
            // The seq_nr is our new initial sequence number.
            // The ack_nr acknowledges the peer's SYN sequence number.
            let current_ts_micros = current_micros() as u32;
            let timestamp_diff_micros = if self.last_received_timestamp_local > 0 {
                current_micros().saturating_sub(self.last_received_timestamp_local) as u32
            } else {
                0 // Should have received SYN, so last_received_timestamp_local > 0
            };

            let sack_data = rm.get_sack_data(self.ack_nr);
            let header = UtpHeader::new(
                ST_STATE,
                self.send_id, // For SYN-ACK, conn_id is our send_id
                current_ts_micros,
                timestamp_diff_micros,
                cc.get_receive_window_size() as u32,
                self.seq_nr, // Our initial sequence number for this direction
                self.ack_nr, // Acknowledging peer's SYN seq_nr
                if sack_data.is_some() { 1 } else { 0 },
            );
            // SYN-ACK consumes a sequence number because it's like our first "data-bearing" (even if empty) packet.
            // However, libutp often sends SYN-ACK with seq_nr = random_isn and then next data with random_isn + 1.
            // Let's assume ST_STATE itself doesn't consume a seq_nr unless it's a FIN.
            // The common_create_packet handles seq_nr increment for ST_DATA, ST_FIN, ST_SYN.
            // If SYN-ACK should consume one, it needs special handling or common_create_packet needs adjustment.
            // For now, assuming ST_STATE (even as SYN-ACK) doesn't increment self.seq_nr here,
            // as the first actual data packet will use self.seq_nr.
            // If it *should* consume one, then self.seq_nr = self.seq_nr.wrapping_add(1); here.
            // Let's stick to common_create_packet not incrementing for ST_STATE.
            // The seq_nr for SYN-ACK is our ISN for this direction.
            // The *next* data packet we send will use self.seq_nr.wrapping_add(1) if SYN-ACK consumed one.
            // It's simpler if SYN-ACK's seq_nr is set, and the *next* data packet uses seq_nr.wrapping_add(0) from current self.seq_nr
            // and then self.seq_nr is incremented.
            // The current create_syn_packet increments self.seq_nr.
            // If this is a SYN-ACK, self.seq_nr was already set by new_for_listener.
            // So, the seq_nr in the SYN-ACK header is correct.
            // The question is whether to increment self.seq_nr *after* creating the SYN-ACK.
            // Standard TCP SYN-ACK does consume a sequence number.
            // Let's assume our ST_STATE for SYN-ACK also consumes one.
            // self.seq_nr = self.seq_nr.wrapping_add(1); // If SYN-ACK consumes a sequence number

            UtpPacket {
                header,
                payload: Vec::new(),
                sack_data,
                remote_addr: self.remote_addr,
            }
        } else {
            self.common_create_packet(ST_STATE, Vec::new(), cc, rm, rm.get_sack_data(self.ack_nr))
        }
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
        current_state: &mut ConnectionState, // This is UtpSocket's state
        current_ts_micros: u64,
    ) {
        // SYN packet handling is special and typically done by the listener/dispatcher
        // to create the Connection object itself, or by UtpSocket for SYN-ACK.
        // This method assumes it's called on an already somewhat established connection context.
        if packet.header.packet_type() == ST_SYN {
            // This case should ideally be handled before a Connection object exists for this packet,
            // or if it's a simultaneous open / re-SYN.
            // If current_state is SynSent, and this is a SYN from peer (not SYN-ACK which is ST_STATE),
            // it could be a simultaneous open.
            if *current_state == ConnectionState::SynSent {
                // This is a SYN from peer while we also sent a SYN.
                // Update our ack_nr to their seq_nr.
                self.ack_nr = packet.header.seq_nr();
                // Our send_id should be their connection_id + 1
                // Our recv_id should be their connection_id
                // This might need adjustment if conn_ids are not as expected for simultaneous open.
                // For now, assume this SYN means we should move to SynRecv if not already Connected.
                if *current_state != ConnectionState::Connected { // Avoid reverting from Connected
                    *current_state = ConnectionState::SynRecv; // We've sent SYN, received SYN
                }
                rm.needs_ack = true; // Need to send our SYN-ACK (or just ACK if already sent SYN-ACK)
                println!("uTP (Connection): SYN received in SynSent state (simultaneous open?). State -> SynRecv. Our ack_nr set to {}", self.ack_nr);
            } else if *current_state == ConnectionState::Idle || *current_state == ConnectionState::Uninitialized {
                // This is an incoming SYN for a listener.
                // This Connection object would have just been created by new_for_listener.
                // ack_nr is already set to packet.header.seq_nr().
                // seq_nr is our random ISN.
                // send_id is packet.header.connection_id().
                // recv_id is packet.header.connection_id().wrapping_add(1).
                *current_state = ConnectionState::SynRecv; // Server state after receiving SYN
                rm.needs_ack = true; // Server needs to send SYN-ACK
                println!("uTP (Connection): SYN received for new connection. State -> SynRecv.");
            }
            // If already Connected, a SYN might be a retransmission or error, usually ignored or RST'd.
            // For now, we don't handle retransmitted SYNs here explicitly beyond acking.
            // The UtpSocket layer handles the SYN-ACK transition to Connected for outgoing SYNs.
        }


        // Basic validation - verify packet's connection ID matches our recv_id
        // For SYN, conn_id is peer's send_id, which is our send_id.
        // For other packets, conn_id is peer's send_id, which is our recv_id.
        // The check in UtpSocketInternal::process_packet for SYN-ACK (ST_STATE) is more specific.
        let expected_conn_id = if packet.header.packet_type() == ST_SYN {
            self.send_id // Incoming SYN has conn_id = peer's chosen send_id = our send_id
        } else {
            self.recv_id // Other packets from peer use conn_id = peer's send_id = our recv_id
        };

        if packet.header.connection_id() != expected_conn_id {
            // This check might be too strict if the UtpSocket layer already filtered based on its own recv_id logic.
            // For example, a SYN-ACK (ST_STATE) from server to client will have conn_id = client's recv_id.
            // Let's rely on UtpSocket's primary filtering for ST_STATE as SYN-ACK.
            if packet.header.packet_type() != ST_STATE { // Be more lenient for ST_STATE which could be SYN-ACK
                eprintln!(
                    "uTP (Connection): Received packet with mismatched connection ID. Type: {}. Expected {}, got {}. Our send_id: {}, recv_id: {}",
                    packet.header.packet_type(), expected_conn_id, packet.header.connection_id(), self.send_id, self.recv_id
                );
                return;
            }
        }


        self.peer_wnd_size = packet.header.wnd_size();
        self.last_received_timestamp = packet.header.timestamp_micros();
        self.last_received_timestamp_local = current_ts_micros;

        let received_ack_nr = packet.header.ack_nr();
        let newly_acked_bytes = rm.process_ack(
            received_ack_nr,
            packet.sack_data.as_deref(),
            &mut self.sent_packets,
            current_ts_micros
        );

        if newly_acked_bytes > 0 {
            cc.on_ack_received(
                newly_acked_bytes,
                rm.get_latest_rtt_micros(),
                rm.get_min_rtt_micros(),
                packet.header.timestamp_micros(),
                packet.header.timestamp_diff_micros()
            );
        }

        match packet.header.packet_type() {
            ST_SYN => {
                // Already handled above for state transition, just ensure ack is needed.
                rm.needs_ack = true;
            },
            ST_STATE => {
                // If this ST_STATE is a SYN-ACK and we are SynSent, UtpSocket::process_packet handles it.
                // If it's a regular ACK, rm.process_ack handled it.
                // If it's an ACK for our FIN:
                if *current_state == ConnectionState::FinSent && received_ack_nr == self.seq_nr.wrapping_sub(1) {
                    // Our FIN is acknowledged. If we also received a FIN, we can close.
                    // Otherwise, we wait for peer's FIN or timeout.
                    // UtpSocket will handle the transition to Closed or Destroying.
                    println!("uTP (Connection): Our FIN acknowledged.");
                    // The UtpSocket layer will check if fin_received is also true to move to Closed.
                }
            },
            ST_DATA => {
                if *current_state == ConnectionState::Connected || *current_state == ConnectionState::ConnectedFull || *current_state == ConnectionState::SynRecv {
                    if packet.header.seq_nr() == self.ack_nr.wrapping_add(1) {
                        self.ack_nr = self.ack_nr.wrapping_add(1);
                        recv_buffer.extend(&packet.payload);
                        rm.needs_ack = true;
                        // If we were in SynRecv, receiving data means connection is now established
                        if *current_state == ConnectionState::SynRecv {
                            *current_state = ConnectionState::Connected;
                            println!("uTP (Connection): Transitioned from SynRecv to Connected upon receiving data.");
                        }
                    } else if crate::utp::common::seq_greater_than(packet.header.seq_nr(), self.ack_nr) {
                        // Out-of-order packet but ahead of our current ack_nr
                        rm.buffer_ooo_packet(packet);
                        rm.needs_ack = true; // Send SACK
                    } else {
                        // Old, duplicate packet, already acked. Send ACK again.
                        rm.needs_ack = true;
                    }
                }
            },
            ST_FIN => {
                // FIN flag means this packet also consumes a sequence number.
                // We should ACK packet.header.seq_nr().
                if *current_state == ConnectionState::Connected ||
                    *current_state == ConnectionState::ConnectedFull ||
                    *current_state == ConnectionState::FinSent { // We might have sent FIN first

                    // Acknowledge the FIN by setting our ack_nr to its seq_nr
                    // (or seq_nr + 1 if FIN also carries data, but uTP FINs are usually empty)
                    // The reliable delivery means we should ack up to this FIN's seq_nr.
                    if crate::utp::common::seq_greater_than(packet.header.seq_nr(), self.ack_nr) {
                        self.ack_nr = packet.header.seq_nr();
                    }
                    // If it's an in-order FIN (seq_nr == self.ack_nr + 1), payload is processed if any.
                    // For simplicity, assume FINs are acked by setting self.ack_nr to FIN's seq_nr.
                    // And then rm.update_cumulative_ack will advance it if possible.

                    // The UtpSocket layer handles the fin_received flag and state transitions.
                    // Here, we just ensure we're ready to ACK it.
                    rm.needs_ack = true;
                    println!("uTP (Connection): FIN received (seq_nr {}). Our ack_nr set to {}. Current state: {:?}", packet.header.seq_nr(), self.ack_nr, current_state);
                }
            },
            ST_RESET => {
                *current_state = ConnectionState::Reset;
                println!("uTP (Connection): Received RESET from {}", self.remote_addr);
            },
            _ => {}
        }

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
        assert_eq!(conn.send_id, conn.recv_id.wrapping_add(1));
    }

    #[test]
    fn test_syn_packet_creation() {
        let remote = SocketAddr::from(([127, 0, 0, 1], 8080));
        let mut conn = Connection::new_for_initiator(remote);
        let old_seq = conn.seq_nr;

        let cc = CongestionControl::new();
        let rm = ReliabilityManager::new();
        let syn = conn.create_syn_packet(&cc, &rm);

        assert_eq!(syn.header.packet_type(), ST_SYN);
        assert_eq!(syn.header.connection_id(), conn.recv_id); // SYN uses recv_id
        assert_eq!(syn.header.seq_nr(), old_seq);
        assert_eq!(syn.header.ack_nr(), 0);
        assert_eq!(conn.seq_nr, old_seq.wrapping_add(1));
    }

    #[test]
    fn test_data_packet_creation() {
        let remote = SocketAddr::from(([127, 0, 0, 1], 8080));
        let mut conn = Connection::new_for_initiator(remote);
        let payload = b"Hello, uTP!".to_vec();
        let old_seq = conn.seq_nr;

        let cc = CongestionControl::new();
        let rm = ReliabilityManager::new();
        let data_pkt = conn.create_data_packet(payload.clone(), &cc, &rm);

        assert_eq!(data_pkt.header.packet_type(), ST_DATA);
        assert_eq!(data_pkt.header.connection_id(), conn.send_id); // Data uses send_id
        assert_eq!(data_pkt.header.seq_nr(), old_seq);
        assert_eq!(data_pkt.payload, payload);
        assert_eq!(conn.seq_nr, old_seq.wrapping_add(1));
    }

    #[test]
    fn test_ack_packet_creation_regular() {
        let remote = SocketAddr::from(([127, 0, 0, 1], 8080));
        let mut conn = Connection::new_for_initiator(remote);
        conn.ack_nr = 42;
        let old_seq = conn.seq_nr;

        let cc = CongestionControl::new();
        let rm = ReliabilityManager::new();
        let ack_pkt = conn.create_ack_packet(&cc, &rm, false); // Not a SYN-ACK

        assert_eq!(ack_pkt.header.packet_type(), ST_STATE);
        assert_eq!(ack_pkt.header.connection_id(), conn.send_id);
        assert_eq!(ack_pkt.header.ack_nr(), 42);
        assert_eq!(ack_pkt.header.seq_nr(), old_seq); // seq_nr for ACK is current next_send
        assert!(ack_pkt.payload.is_empty());
        assert_eq!(conn.seq_nr, old_seq); // ST_STATE does not consume seq_nr
    }

    #[test]
    fn test_ack_packet_creation_synack() {
        let remote = SocketAddr::from(([127, 0, 0, 1], 1234));
        // Simulate receiving a SYN to create a listener-side connection
        let syn_header = UtpHeader::new(ST_SYN, 1000, 0,0,15000, 500, 0,0);
        let syn_packet = UtpPacket { header: syn_header, payload: vec![], sack_data: None, remote_addr: remote};

        let mut conn = Connection::new_for_listener(remote, &syn_packet);
        // conn.seq_nr is server's ISN, conn.ack_nr is client's SYN seq_nr (500)
        // conn.send_id is client's SYN conn_id (1000)
        // conn.recv_id is client's SYN conn_id + 1 (1001)

        let server_isn = conn.seq_nr; // Server's ISN for the SYN-ACK

        let cc = CongestionControl::new();
        let rm = ReliabilityManager::new();
        let syn_ack_pkt = conn.create_ack_packet(&cc, &rm, true); // Is a SYN-ACK

        assert_eq!(syn_ack_pkt.header.packet_type(), ST_STATE);
        assert_eq!(syn_ack_pkt.header.connection_id(), conn.send_id); // Should be conn.send_id
        assert_eq!(syn_ack_pkt.header.seq_nr(), server_isn);
        assert_eq!(syn_ack_pkt.header.ack_nr(), 500); // Acking client's SYN
        assert!(syn_ack_pkt.payload.is_empty());
        // self.seq_nr is NOT incremented by create_ack_packet for ST_STATE
        assert_eq!(conn.seq_nr, server_isn);
    }


    #[test]
    fn test_fin_packet_creation() {
        let remote = SocketAddr::from(([127, 0, 0, 1], 8080));
        let mut conn = Connection::new_for_initiator(remote);
        let old_seq = conn.seq_nr;

        let cc = CongestionControl::new();
        let rm = ReliabilityManager::new();
        let fin_pkt = conn.create_fin_packet(&cc, &rm);

        assert_eq!(fin_pkt.header.packet_type(), ST_FIN);
        assert_eq!(fin_pkt.header.connection_id(), conn.send_id);
        assert_eq!(fin_pkt.header.seq_nr(), old_seq);
        assert!(fin_pkt.payload.is_empty());
        assert_eq!(conn.seq_nr, old_seq.wrapping_add(1));
    }

    #[test]
    fn test_timestamp_tracking() {
        let remote = SocketAddr::from(([127, 0, 0, 1], 8080));
        let mut conn = Connection::new_for_initiator(remote);

        let test_timestamp = 12345678u32;
        let before_time = current_micros();

        let header = UtpHeader::new(ST_STATE, conn.recv_id, test_timestamp, 0, 1000, 1, 0, 0);
        let packet = UtpPacket { header, payload: Vec::new(), sack_data: None, remote_addr: remote };

        let mut cc = CongestionControl::new();
        let mut rm = ReliabilityManager::new();
        let mut buffer = VecDeque::new();
        let mut state = ConnectionState::Connected;
        let now = current_micros();

        conn.handle_incoming_packet(&packet, &mut cc, &mut rm, &mut buffer, &mut state, now);

        let (stored_timestamp, stored_local_time) = conn.get_timestamp_values();
        assert_eq!(stored_timestamp, test_timestamp);
        assert!(stored_local_time >= before_time);
        assert!(stored_local_time <= current_micros());
    }
}