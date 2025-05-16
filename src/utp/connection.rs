// utp/connection.rs

use crate::utp::common::{ConnectionId, ConnectionState, ST_SYN, ST_DATA, ST_FIN, ST_STATE, current_micros};
use crate::utp::packet::{UtpHeader, UtpPacket};
use crate::utp::congestion::CongestionControl;
use crate::utp::reliability::{ReliabilityManager, SentPacketInfo};
use std::collections::VecDeque;
use std::net::SocketAddr;

pub struct Connection {
    // Connection IDs
    pub send_id: ConnectionId, // Our send ID (peer's recv ID)
    pub recv_id: ConnectionId, // Our recv ID (peer's send ID, or our send_id + 1 for initiator)

    // Sequence and acknowledgment numbers
    pub seq_nr: u16, // Next sequence number to send
    pub ack_nr: u16, // Next sequence number expected from peer / last in-order received

    // Peer's last advertised window size
    pub peer_wnd_size: u32,

    // Information about packets we've sent that are awaiting ACK
    // Key: seq_nr, Value: SentPacketInfo
    // This would likely be part of ReliabilityManager in a fuller design
    pub sent_packets: std::collections::HashMap<u16, SentPacketInfo>,

    // Remote peer address
    pub remote_addr: SocketAddr,
}

impl Connection {
    /// For the side initiating the connection (client)
    pub fn new_for_initiator(remote_addr: SocketAddr) -> Self {
        let initial_seq_nr = rand::random::<u16>(); // Random initial sequence number
        let conn_id = rand::random::<u16>(); // This is our connection ID for sending the SYN

        Self {
            // For SYN, conn_id in header is our intended recv_id. Peer responds with this as their send_id.
            // Our send_id will be their recv_id (which is conn_id + 1).
            // See libutp utp_connect and utp_initialize_socket[1]
            // conn_id_recv for us (what we put in SYN conn_id field)
            // conn_id_send for us (conn_id_recv + 1)
            recv_id: conn_id,
            send_id: conn_id.wrapping_add(1),
            seq_nr: initial_seq_nr,
            ack_nr: 0, // Will be set from SYN-ACK's seq_nr
            peer_wnd_size: crate::utp::common::DEFAULT_MAX_PACKET_SIZE as u32 * 10, // Initial assumption
            sent_packets: std::collections::HashMap::new(),
            remote_addr,
        }
    }

    /// For the side accepting the connection (server)
    pub fn new_for_listener(remote_addr: SocketAddr, syn_packet: &UtpPacket) -> Self {
        // From libutp utp_process_udp for ST_SYN:
        // conn_id_recv for us = syn_packet.header.connection_id() + 1
        // conn_id_send for us = syn_packet.header.connection_id()
        Self {
            recv_id: syn_packet.header.connection_id().wrapping_add(1),
            send_id: syn_packet.header.connection_id(),
            seq_nr: rand::random::<u16>(),
            ack_nr: syn_packet.header.seq_nr(), // Ack the SYN's sequence number
            peer_wnd_size: syn_packet.header.wnd_size(),
            sent_packets: std::collections::HashMap::new(),
            remote_addr,
        }
    }

    pub fn initiate_connection(&mut self) {
        // Client-side: seq_nr is random, ack_nr is 0.
        // send_id and recv_id are set in new_for_initiator.
        // (No specific action beyond what's in `new_for_initiator` and `create_syn_packet`)
    }

    fn common_create_packet(
        &mut self,
        packet_type: u8,
        payload: Vec<u8>,
        cc: &CongestionControl,
        _rm: &ReliabilityManager, // rm might be used for SACK data in future
        sack_data: Option<Vec<u8>>,
    ) -> UtpPacket {
        let current_ts_micros = current_micros() as u32; // uTP uses 32-bit timestamps in header

        // timestamp_diff is calculated based on peer's last timestamp_micros received.
        // This needs state from the last received packet from the peer.
        // For now, placeholder.
        let timestamp_diff_micros = 0;

        let header = UtpHeader::new(
            packet_type,
            self.send_id, // For non-SYN packets, conn_id is our send_id
            current_ts_micros,
            timestamp_diff_micros,
            cc.get_receive_window_size() as u32, // Our current receive window
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
            // SYN packets also consume a sequence number
            if packet_type == ST_SYN && self.seq_nr == 0 { // Special case if initial_seq_nr was 0
                // self.seq_nr = 1; // libutp does this for SYN sometimes
            }
            self.seq_nr = self.seq_nr.wrapping_add(1);
        }
        packet
    }

    pub fn create_syn_packet(&mut self, cc: &CongestionControl, rm: &ReliabilityManager) -> UtpPacket {
        let current_ts_micros = current_micros() as u32;
        let header = UtpHeader::new(
            ST_SYN,
            self.recv_id, // SYN packet conn_id is our intended recv_id (peer's send_id if they accept)
            current_ts_micros,
            0, // No timestamp_diff for first packet
            cc.get_receive_window_size() as u32,
            self.seq_nr,
            0, // ack_nr is 0 for initial SYN
            0, // No extension initially
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

    pub fn create_data_packet(&mut self, payload: Vec<u8>, cc: &CongestionControl, rm: &ReliabilityManager) -> UtpPacket {
        self.common_create_packet(ST_DATA, payload, cc, rm, rm.get_sack_data(self.ack_nr))
    }

    pub fn create_ack_packet(&mut self, cc: &CongestionControl, rm: &ReliabilityManager, is_syn_ack: bool) -> UtpPacket {
        let packet_type = ST_STATE;
        // For SYN-ACK, the logic is slightly different as it's responding to a SYN.
        // ack_nr is peer's SYN seq_nr. Our seq_nr is our initial random one.
        // conn_id is our send_id (which is peer's SYN conn_id).
        // This method assumes it's a regular ACK or part of SYN-ACK.
        // The common_create_packet handles most, but SYN-ACK might need specific setup before calling.
        if is_syn_ack {
            // seq_nr for SYN-ACK should be our initial seq_nr.
            // ack_nr for SYN-ACK should be the peer's SYN seq_nr.
            // conn_id for SYN-ACK should be our send_id.
        }
        self.common_create_packet(packet_type, Vec::new(), cc, rm, rm.get_sack_data(self.ack_nr))
    }

    pub fn create_fin_packet(&mut self, cc: &CongestionControl, rm: &ReliabilityManager) -> UtpPacket {
        self.common_create_packet(ST_FIN, Vec::new(), cc, rm, None)
    }

    // Simplified handler
    pub fn handle_incoming_packet(
        &mut self,
        packet: &UtpPacket,
        cc: &mut CongestionControl,
        rm: &mut ReliabilityManager,
        recv_buffer: &mut VecDeque<u8>,
        current_state: &mut ConnectionState,
        current_ts_micros: u64,
    ) {
        // Basic validation
        // For non-SYN, packet.header.connection_id() should be our recv_id
        if packet.header.packet_type() != ST_SYN && packet.header.connection_id() != self.recv_id {
            eprintln!("uTP: Received packet with mismatched connection ID. Expected {}, got {}", self.recv_id, packet.header.connection_id());
            return;
        }

        self.peer_wnd_size = packet.header.wnd_size();
        let received_ack_nr = packet.header.ack_nr();
        let newly_acked_bytes = rm.process_ack(received_ack_nr, packet.sack_data.as_deref(), &mut self.sent_packets, current_ts_micros);

        if newly_acked_bytes > 0 {
            cc.on_ack_received(newly_acked_bytes, rm.get_latest_rtt_micros(), rm.get_min_rtt_micros());
        }

        // Handle based on packet type
        match packet.header.packet_type() {
            ST_SYN => { // Should be handled by a listener to create a new connection typically
                if *current_state == ConnectionState::Idle || *current_state == ConnectionState::SynSent { // Listener handling or simultaneous open
                    // This is complex: if we are listener, we'd create a new UtpSocket for this.
                    // If we are client and this is SYN-ACK:
                    if *current_state == ConnectionState::SynSent {
                        // Validate it's a SYN-ACK (ack_nr acks our SYN seq_nr-1)
                        if packet.header.ack_nr() == self.seq_nr.wrapping_sub(1) {
                            self.ack_nr = packet.header.seq_nr(); // Ack their SYN's seq_nr
                            // self.send_id = packet.header.connection_id(); // Their send_id is our recv_id
                            // self.recv_id = packet.header.connection_id().wrapping_add(1); // Their recv_id is our send_id. This needs to match our SYN.
                            *current_state = ConnectionState::Connected;
                            println!("uTP: Connection established with {}", self.remote_addr);
                            // Send a final ACK for their SYN-ACK (often an empty ST_STATE or piggybacked on first ST_DATA)
                            // This might be queued by reliability manager.
                        }
                    }
                }
            }
            ST_STATE => { // ACK packet
                // ACKs are processed by rm.process_ack above.
                // No payload.
            }
            ST_DATA => {
                if *current_state == ConnectionState::Connected || *current_state == ConnectionState::ConnectedFull {
                    // Check sequence number for in-order delivery
                    if packet.header.seq_nr() == self.ack_nr.wrapping_add(1) {
                        self.ack_nr = self.ack_nr.wrapping_add(1);
                        recv_buffer.extend(&packet.payload);
                        // Handle further in-order packets from reorder buffer (SACK related)
                        // ...
                        // Queue an ACK
                        rm.needs_ack = true;
                    } else {
                        // Out of order, buffer if SACK enabled and valid
                        rm.buffer_ooo_packet(packet);
                        rm.needs_ack = true; // Send ACK with SACK info
                    }
                }
            }
            ST_FIN => {
                if *current_state == ConnectionState::Connected || *current_state == ConnectionState::ConnectedFull {
                    self.ack_nr = packet.header.seq_nr(); // Ack the FIN
                    *current_state = ConnectionState::FinRecv; // Or directly to Closed if we also sent FIN
                    // Queue an ACK for the FIN
                    rm.needs_ack = true;
                    println!("uTP: Received FIN from {}", self.remote_addr);
                }
            }
            ST_RESET => {
                *current_state = ConnectionState::Reset;
                println!("uTP: Received RESET from {}", self.remote_addr);
            }
            _ => { /* Unknown packet type */ }
        }
        // Update our ack_nr based on SACK logic too
        self.ack_nr = rm.update_cumulative_ack(self.ack_nr);
    }

    pub fn get_seq_nr(&self) -> u16 { self.seq_nr }
    pub fn get_ack_nr(&self) -> u16 { self.ack_nr }
    pub fn get_sent_packets(&self) -> &std::collections::HashMap<u16, SentPacketInfo> {
        &self.sent_packets
    }
}