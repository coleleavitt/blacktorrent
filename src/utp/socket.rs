// utp/socket.rs
#![forbid(unsafe_code)]

use crate::utp::common::{
    ConnectionState, UtpError, current_micros, UtpSocketStats, ST_SYN, ST_DATA, ST_STATE, ST_FIN,
    MAX_RTO_MICROS,
};
use crate::utp::packet::{UtpPacket, BASE_HEADER_SIZE};
use crate::utp::connection::Connection;
use crate::utp::congestion::CongestionControl;
use crate::utp::reliability::ReliabilityManager;

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::cmp::min;
use std::mem;

const DEFAULT_KEEPALIVE_INTERVAL: u64 = 29_000;
const CONNECT_TIMEOUT_DURATION: u64 = 6_000;
const MAX_TIMEOUT_CHECK_INTERVAL: u64 = 500;
const MIN_PACKET_SIZE_FOR_PAYLOAD: usize = 150;
const MAX_RETRANSMISSIONS_LIMIT: u32 = 5;

pub struct UtpSocket {
    pub(crate) internal: Arc<Mutex<UtpSocketInternal>>,
}

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
    pub(crate) rto_timeout_at_ms: u64,
    pub(crate) syn_retransmit_count: u32,
    pub(crate) fin_sent: bool,
    pub(crate) fin_received: bool,
    pub(crate) close_requested: bool,
    pub(crate) stats: UtpSocketStats,
}

impl UtpSocketInternal {
    fn get_mtu(&self) -> usize {
        crate::utp::common::DEFAULT_MAX_PACKET_SIZE - BASE_HEADER_SIZE
    }

    fn create_syn(&mut self) -> UtpPacket {
        self.conn.create_syn_packet(&self.cc, &self.rm)
    }

    fn create_ack(&mut self, is_synack: bool) -> UtpPacket {
        self.conn.create_ack_packet(&self.cc, &self.rm, is_synack)
    }

    fn create_data(&mut self, payload: Vec<u8>) -> UtpPacket {
        self.conn.create_data_packet(payload, &self.cc, &self.rm)
    }

    fn create_fin(&mut self) -> UtpPacket {
        self.conn.create_fin_packet(&self.cc, &self.rm)
    }

    fn check_timeouts(&mut self, now_ms: u64) {
        eprintln!("[SOCKET DEBUG] check_timeouts: Entered. now_ms: {}, rto_timeout_at_ms: {}, state: {:?}",
                  now_ms, self.rto_timeout_at_ms, self.state);

        if self.rto_timeout_at_ms > 0 && now_ms >= self.rto_timeout_at_ms {
            eprintln!("[SOCKET DEBUG] check_timeouts: RTO timer expired.");
            if self.state == ConnectionState::SynSent {
                eprintln!("[SOCKET DEBUG] check_timeouts: State is SynSent.");
                if self.syn_retransmit_count >= MAX_RETRANSMISSIONS_LIMIT {
                    eprintln!("[SOCKET DEBUG] check_timeouts: Max SYN retransmissions reached. Resetting.");
                    self.state = ConnectionState::Reset;
                    return;
                }
                let syn = self.create_syn();
                self.outgoing_packets.push_back(syn);
                self.syn_retransmit_count += 1;
                self.stats.packets_retransmitted += 1;
                eprintln!("[SOCKET DEBUG] check_timeouts: SYN retransmitted. Count: {}, Stats retransmitted: {}",
                          self.syn_retransmit_count, self.stats.packets_retransmitted);

                let current_rto_micros = self.rm.get_current_rto();
                let new_rto_micros = min(current_rto_micros.saturating_mul(2), MAX_RTO_MICROS);
                self.rm.current_rto = new_rto_micros;
                self.rto_timeout_at_ms = now_ms + (new_rto_micros as u64 / 1000);
                eprintln!("[SOCKET DEBUG] check_timeouts: New RTO for SYN: {}ms", new_rto_micros / 1000);

            } else if let Some(timed_out_seq) = {
                eprintln!("[SOCKET DEBUG] check_timeouts: Calling rm.check_timeouts for data packet.");
                let rm_ref = &mut self.rm;
                rm_ref.check_timeouts(current_micros())
            } {
                eprintln!("[SOCKET DEBUG] check_timeouts: rm.check_timeouts returned Some({})", timed_out_seq);
                self.cc.on_timeout();
                self.stats.packets_lost += 1;
                eprintln!("[SOCKET DEBUG] check_timeouts: packets_lost incremented to {}", self.stats.packets_lost);

                // --- DEBUG: Print all sent_packets keys and the timed_out_seq ---
                let sent_keys: Vec<u16> = self.conn.sent_packets.keys().cloned().collect();
                eprintln!("[SOCKET DEBUG] check_timeouts: sent_packets keys = {:?}, timed_out_seq = {}", sent_keys, timed_out_seq);

                if let Some(packet_info) = self.conn.sent_packets.get_mut(&timed_out_seq) {
                    eprintln!("[SOCKET DEBUG] check_timeouts: Found packet_info for seq {}", timed_out_seq);
                    if packet_info.transmissions < MAX_RETRANSMISSIONS_LIMIT {
                        eprintln!("[SOCKET DEBUG] check_timeouts: Transmissions ({}) < MAX ({})", packet_info.transmissions, MAX_RETRANSMISSIONS_LIMIT);
                        match UtpPacket::from_bytes(&packet_info.packet_data, self.remote_addr) {
                            Ok(pkt_to_resend) => {
                                eprintln!("[SOCKET DEBUG] check_timeouts: UtpPacket::from_bytes OK. Queuing retransmission for seq {}.", timed_out_seq);
                                self.outgoing_packets.push_back(pkt_to_resend);
                                self.stats.packets_retransmitted += 1;
                                eprintln!("[SOCKET DEBUG] check_timeouts: packets_retransmitted incremented to {}", self.stats.packets_retransmitted);
                                self.stats.bytes_retransmitted += packet_info.size_bytes as u64;

                                packet_info.transmissions += 1;
                                packet_info.need_resend = false;
                                packet_info.sent_at_micros = current_micros();
                            }
                            Err(e) => {
                                eprintln!("[SOCKET DEBUG ERROR] UtpPacket::from_bytes failed for seq {}: {}. Data (len {}): {:?}",
                                          timed_out_seq, e, packet_info.packet_data.len(), &packet_info.packet_data[..min(packet_info.packet_data.len(), 60)]);
                                self.state = ConnectionState::Reset;
                                return;
                            }
                        }
                    } else {
                        eprintln!("[SOCKET DEBUG] check_timeouts: Max retransmissions reached for seq {}", timed_out_seq);
                        self.state = ConnectionState::Reset;
                        return;
                    }
                } else {
                    eprintln!("[SOCKET DEBUG ERROR] check_timeouts: Packet info NOT FOUND for timed_out_seq {}", timed_out_seq);
                }
                let current_rto_micros = self.rm.get_current_rto();
                let new_rto_micros = min(current_rto_micros.saturating_mul(2), MAX_RTO_MICROS);
                self.rm.current_rto = new_rto_micros;
                self.rto_timeout_at_ms = now_ms + (new_rto_micros as u64 / 1000);
                eprintln!("[SOCKET DEBUG] check_timeouts: New RTO for data: {}ms", new_rto_micros / 1000);
            } else {
                eprintln!("[SOCKET DEBUG] check_timeouts: RTO expired (now_ms: {}, rto_at: {}) BUT rm.check_timeouts returned None.", now_ms, self.rto_timeout_at_ms);
                self.rto_timeout_at_ms = now_ms + (self.rm.get_current_rto() as u64 / 1000);
            }
        } else if self.rto_timeout_at_ms == 0 && !self.conn.sent_packets.is_empty() {
            self.rto_timeout_at_ms = now_ms + (self.rm.get_current_rto() as u64 / 1000);
            eprintln!("[SOCKET DEBUG] check_timeouts: RTO timer started. Will expire at: {}", self.rto_timeout_at_ms);
        }

        if self.state == ConnectionState::SynSent &&
            now_ms.saturating_sub(self.created_time / 1000) > CONNECT_TIMEOUT_DURATION {
            eprintln!("[SOCKET DEBUG] check_timeouts: SYN_SENT connection timed out.");
            self.state = ConnectionState::Reset;
        }

        if self.state == ConnectionState::FinSent &&
            now_ms.saturating_sub(self.last_packet_sent_time / 1000) >
                (self.rm.get_current_rto() / 1000 * 2) as u64 {
            eprintln!("[SOCKET DEBUG] check_timeouts: FIN_SENT timed out. Closing.");
            self.state = ConnectionState::Closed;
        }

        if self.state == ConnectionState::Reset &&
            now_ms.saturating_sub(self.last_packet_sent_time / 1000) > 1000 {
            eprintln!("[SOCKET DEBUG] check_timeouts: RESET linger timed out. Destroying.");
            self.state = ConnectionState::Destroying;
        }
    }

    fn package_data_from_buffer(&mut self) {
        if self.state != ConnectionState::Connected && self.state != ConnectionState::ConnectedFull {
            return;
        }
        if self.send_buffer.is_empty() {
            return;
        }

        let current_cwnd = self.cc.get_congestion_window_size();
        let bytes_in_flight = self.cc.bytes_in_flight();

        let mut available_window = current_cwnd.saturating_sub(bytes_in_flight);

        while available_window >= MIN_PACKET_SIZE_FOR_PAYLOAD && !self.send_buffer.is_empty() {
            let max_payload_this_packet = min(available_window, self.get_mtu());
            if max_payload_this_packet == 0 { break; }

            let to_send_len = min(max_payload_this_packet, self.send_buffer.len());
            if to_send_len == 0 { break; }

            let mut payload_bytes = Vec::with_capacity(to_send_len);
            for _ in 0..to_send_len {
                if let Some(b) = self.send_buffer.pop_front() {
                    payload_bytes.push(b);
                } else {
                    break;
                }
            }

            if payload_bytes.is_empty() { break; }

            let data_packet = self.create_data(payload_bytes);
            let packet_actual_payload_size = data_packet.payload_size();

            self.cc.on_packet_sent(data_packet.total_size());
            self.outgoing_packets.push_back(data_packet);
            self.stats.bytes_sent += packet_actual_payload_size as u64;

            available_window = available_window.saturating_sub(packet_actual_payload_size);
            if packet_actual_payload_size == 0 {
                break;
            }
        }
        if current_cwnd.saturating_sub(self.cc.bytes_in_flight()) < MIN_PACKET_SIZE_FOR_PAYLOAD && self.state == ConnectionState::Connected {
            self.state = ConnectionState::ConnectedFull;
        }
    }

    fn send_keep_alive(&mut self) {
        let ka_packet = self.create_ack(false);
        self.outgoing_packets.push_back(ka_packet);
        self.stats.packets_sent += 1;
    }

    fn process_packet(&mut self, pkt: &UtpPacket, now_us: u64) {
        if self.state == ConnectionState::SynSent && pkt.header.packet_type() == ST_STATE {
            if pkt.header.connection_id() == self.conn.recv_id &&
                pkt.header.ack_nr() == self.conn.seq_nr.wrapping_sub(1) {

                self.conn.ack_nr = pkt.header.seq_nr();
                self.state = ConnectionState::Connected;
                self.rm.needs_ack = true;

                let syn_acked_seq = self.conn.seq_nr.wrapping_sub(1);
                let mut temp_sent_packets = mem::take(&mut self.conn.sent_packets);
                self.rm.process_ack(syn_acked_seq, None, &mut temp_sent_packets, now_us);
                self.conn.sent_packets = temp_sent_packets;

                self.rto_timeout_at_ms = (now_us / 1000) + (self.rm.get_current_rto() as u64 / 1000);
                return;
            }
        }

        let UtpSocketInternal { ref mut conn, ref mut cc, ref mut rm, ref mut recv_buffer, ref mut state, .. } = *self;
        conn.handle_incoming_packet(
            &pkt,
            cc,
            rm,
            recv_buffer,
            state,
            now_us,
        );

        self.conn.peer_wnd_size = pkt.header.wnd_size();

        if pkt.header.packet_type() == ST_FIN {
            self.fin_received = true;
            if self.fin_sent {
                self.state = ConnectionState::Closed;
            } else {
                self.state = ConnectionState::FinRecv;
                self.rm.needs_ack = true;
            }
        }
        if self.state == ConnectionState::ConnectedFull && self.cc.get_congestion_window_size().saturating_sub(self.cc.bytes_in_flight()) >= MIN_PACKET_SIZE_FOR_PAYLOAD {
            self.state = ConnectionState::Connected;
        }
    }
}

impl UtpSocket {
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
            last_timeout_check: now / 1000,
            rto_timeout_at_ms: 0,
            syn_retransmit_count: 0,
            fin_sent: false,
            fin_received: false,
            close_requested: false,
            stats: UtpSocketStats::default(),
        };
        UtpSocket { internal: Arc::new(Mutex::new(internal)) }
    }

    pub fn connect(&self) -> Result<(), UtpError> {
        let mut i = self.internal.lock().unwrap();

        if i.state != ConnectionState::Idle {
            return Err(UtpError::InvalidState);
        }
        i.conn.initiate_connection();
        i.state = ConnectionState::SynSent;

        let syn_packet = i.create_syn();

        let now = current_micros();
        let mut temp_sent_packets = mem::take(&mut i.conn.sent_packets);
        i.rm.on_packet_sent(&syn_packet, now, &mut temp_sent_packets);
        i.conn.sent_packets = temp_sent_packets;

        i.outgoing_packets.push_back(syn_packet);
        i.last_packet_sent_time = now;

        let rto_ms = i.rm.get_current_rto() / 1000;
        i.rto_timeout_at_ms = (now / 1000) + rto_ms as u64;

        i.stats.packets_sent += 1;
        Ok(())
    }

    pub fn process_incoming_datagram(&self, data: &[u8], from: SocketAddr) {
        let mut i = self.internal.lock().unwrap();
        if i.remote_addr != from && i.state != ConnectionState::Idle {
            return;
        }
        match UtpPacket::from_bytes(data, from) {
            Ok(pkt) => {
                i.incoming_packets.push_back(pkt);
                i.stats.packets_received += 1;
                i.stats.bytes_received += data.len() as u64;
            }
            Err(_) => {
            }
        }
    }

    pub fn tick(&self) -> Result<Option<Vec<u8>>, UtpError> {
        let mut i = self.internal.lock().unwrap();

        // 1) Timestamps
        let now_us = current_micros();
        let now_ms = now_us / 1000;

        // 2) Drain incoming queue
        while let Some(pkt) = i.incoming_packets.pop_front() {
            i.last_packet_recv_time = now_us;
            i.process_packet(&pkt, now_us);
        }

        // 3) Periodic RTO check
        if now_ms.saturating_sub(i.last_timeout_check) >= MAX_TIMEOUT_CHECK_INTERVAL {
            i.last_timeout_check = now_ms;
            i.check_timeouts(now_ms);
        }

        // 4) Immediate retransmit if RM flagged any seq
        if let Some(seq_nr) = i.rm.check_timeouts(now_us) {
            // First copy out all the data we need
            let packet_info = i.conn.sent_packets.get(&seq_nr).map(|info| {
                (info.packet_data.clone(), info.size_bytes)
            });

            // If we have valid packet info, update stats and return
            if let Some((packet_data, size_bytes)) = packet_info {
                i.cc.on_timeout();
                i.stats.packets_lost += 1;
                i.stats.packets_retransmitted += 1;
                i.stats.bytes_retransmitted += size_bytes as u64;
                return Ok(Some(packet_data));
            }
        }

        // 5) Tear-down check
        if i.state == ConnectionState::Destroying {
            return Err(UtpError::ConnectionReset);
        }

        // 6) Delayed-ACK?
        if i.rm.needs_ack_packet() {
            let ack = i.create_ack(false);
            i.outgoing_packets.push_back(ack);
            i.rm.ack_sent();
            i.stats.packets_sent += 1;
        }

        // 7) Package any application data into DATA packets
        i.package_data_from_buffer();

        // 8) Keep-alive?
        if i.state == ConnectionState::Connected
            && !i.fin_sent
            && now_ms.saturating_sub(i.last_packet_sent_time / 1000) >= DEFAULT_KEEPALIVE_INTERVAL
        {
            i.send_keep_alive();
        }

        // 9) Pop one packet to actually send
        if let Some(pkt) = i.outgoing_packets.pop_front() {
            i.last_packet_sent_time = now_us;
            let ty = pkt.header.packet_type();

            // Track data-bearing packets
            if ty == ST_DATA || ty == ST_SYN || ty == ST_FIN {
                if ty != ST_SYN {
                    let mut tmp = std::mem::take(&mut i.conn.sent_packets);
                    i.rm.on_packet_sent(&pkt, now_us, &mut tmp);
                    i.conn.sent_packets = tmp;
                }
            }

            // Ensure RTO timer is set
            if !i.conn.sent_packets.is_empty() && i.rto_timeout_at_ms == 0 {
                i.rto_timeout_at_ms = now_ms + (i.rm.get_current_rto() as u64 / 1000);
            }

            // Serialize and return
            let mut buf = Vec::new();
            pkt.serialize(&mut buf);
            return Ok(Some(buf));
        }

        // 10) Nothing to send
        Ok(None)
    }    
    pub fn write_data(&self, data: &[u8]) -> Result<usize, UtpError> {
        let mut i = self.internal.lock().unwrap();
        if i.state != ConnectionState::Connected && i.state != ConnectionState::ConnectedFull {
            if i.fin_sent || i.close_requested ||
                !matches!(i.state, ConnectionState::Connected | ConnectionState::ConnectedFull) {
                return Err(UtpError::InvalidState);
            }
        }
        i.send_buffer.extend(data);
        Ok(data.len())
    }

    pub fn read_data(&self, buf: &mut [u8]) -> Result<usize, UtpError> {
        let mut i = self.internal.lock().unwrap();
        if i.recv_buffer.is_empty() {
            if i.fin_received ||
                i.state == ConnectionState::Closed ||
                i.state == ConnectionState::Reset {
                return Ok(0);
            }
            return Err(UtpError::Network(std::io::Error::new(
                std::io::ErrorKind::WouldBlock, "No data available",
            )));
        }

        let mut bytes_read = 0;
        while bytes_read < buf.len() {
            if let Some(byte_val) = i.recv_buffer.pop_front() {
                buf[bytes_read] = byte_val;
                bytes_read += 1;
            } else {
                break;
            }
        }

        if bytes_read > 0 {
            i.rm.set_needs_ack();
        }
        Ok(bytes_read)
    }

    pub fn close(&self) -> Result<(), UtpError> {
        let mut i = self.internal.lock().unwrap();

        if i.close_requested || i.fin_sent ||
            matches!(i.state, ConnectionState::Closed | ConnectionState::Reset | ConnectionState::Destroying) {
            return Ok(());
        }

        i.close_requested = true;
        match i.state {
            ConnectionState::Connected | ConnectionState::ConnectedFull | ConnectionState::FinRecv => {
                if !i.fin_sent {
                    i.state = ConnectionState::FinSent;
                    i.fin_sent = true;
                    let fin_packet = i.create_fin();

                    let now = current_micros();
                    let mut temp_sent_packets = mem::take(&mut i.conn.sent_packets);
                    i.rm.on_packet_sent(&fin_packet, now, &mut temp_sent_packets);
                    i.conn.sent_packets = temp_sent_packets;

                    if i.rto_timeout_at_ms == 0 {
                        i.rto_timeout_at_ms = (now / 1000) + (i.rm.get_current_rto() as u64 / 1000);
                    }

                    i.outgoing_packets.push_back(fin_packet);
                    i.last_packet_sent_time = now;
                    i.stats.packets_sent += 1;
                }
            }
            ConnectionState::SynSent | ConnectionState::Idle => {
                i.state = ConnectionState::Closed;
            }
            ConnectionState::SynRecv => {
                i.state = ConnectionState::Reset;
            }
            _ => {}
        }
        Ok(())
    }

    pub fn get_state(&self) -> ConnectionState {
        self.internal.lock().unwrap().state
    }

    pub fn remote_address(&self) -> SocketAddr {
        self.internal.lock().unwrap().remote_addr
    }

    pub fn get_rtt(&self) -> u32 {
        self.internal.lock().unwrap().rm.get_latest_rtt_micros() / 1000
    }

    pub fn get_mtu_payload_size(&self) -> usize {
        self.internal.lock().unwrap().get_mtu()
    }

    pub fn is_send_buffer_empty(&self) -> bool {
        self.internal.lock().unwrap().send_buffer.is_empty()
    }

    pub fn connection_id(&self) -> u16 {
        self.internal.lock().unwrap().conn.recv_id
    }

    pub fn get_stats(&self) -> UtpSocketStats {
        self.internal.lock().unwrap().stats.clone()
    }

    pub fn accept_initialize(&self, remote_addr: SocketAddr, syn_packet_ref: &UtpPacket) -> Result<(), UtpError> {
        let mut i = self.internal.lock().unwrap();

        if i.state != ConnectionState::Idle {
            return Err(UtpError::InvalidState);
        }
        i.remote_addr = remote_addr;
        i.conn = Connection::new_for_listener(remote_addr, syn_packet_ref);
        i.state = ConnectionState::SynRecv;
        i.created_time = current_micros();
        i.last_packet_recv_time = current_micros();

        let syn_ack_packet = i.create_ack(true);

        let now = current_micros();
        let mut temp_sent_packets = mem::take(&mut i.conn.sent_packets);
        i.rm.on_packet_sent(&syn_ack_packet, now, &mut temp_sent_packets);
        i.conn.sent_packets = temp_sent_packets;

        i.outgoing_packets.push_back(syn_ack_packet);
        i.last_packet_sent_time = now;

        let rto_ms = i.rm.get_current_rto() / 1000;
        i.rto_timeout_at_ms = (now / 1000) + rto_ms as u64;
        i.stats.packets_sent += 1;
        Ok(())
    }

    pub async fn initialize_from_connection(&self, conn_id: u16) -> Result<(), UtpError> {
        let mut internal = self.internal.lock().unwrap();
        internal.conn.recv_id = conn_id;
        internal.conn.send_id = conn_id.wrapping_sub(1);
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

    fn create_test_socket() -> UtpSocket {
        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1234);
        let remote_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5678);
        UtpSocket::new(local_addr, remote_addr)
    }

    fn create_test_synack_packet(client_recv_id: u16, client_syn_seq_nr: u16, server_seq_nr: u16, remote_addr: SocketAddr, wnd_size: u32) -> UtpPacket {
        UtpPacket::create_ack(
            client_recv_id,
            server_seq_nr,
            client_syn_seq_nr,
            current_micros() as u32,
            0,
            wnd_size,
            None,
            remote_addr,
        )
    }

    fn create_test_data_packet(conn_id: u16, seq_nr: u16, ack_nr: u16, payload_data: &[u8], remote_addr: SocketAddr, wnd_size: u32) -> UtpPacket {
        UtpPacket::create_data(
            conn_id,
            seq_nr,
            ack_nr,
            current_micros() as u32,
            0,
            wnd_size,
            payload_data.to_vec(),
            None,
            remote_addr
        )
    }

    fn create_test_fin_packet(conn_id: u16, seq_nr: u16, ack_nr: u16, remote_addr: SocketAddr, wnd_size: u32) -> UtpPacket {
        UtpPacket::create_fin(
            conn_id,
            seq_nr,
            ack_nr,
            current_micros() as u32,
            0,
            wnd_size,
            remote_addr
        )
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

        let internal_guard = socket.internal.lock().unwrap();
        assert_eq!(internal_guard.syn_retransmit_count, 0);
        assert!(internal_guard.rto_timeout_at_ms > 0);
        assert_eq!(internal_guard.outgoing_packets.len(), 1);
        assert_eq!(internal_guard.conn.sent_packets.len(), 1);
        drop(internal_guard);

        let output = socket.tick().unwrap();
        assert!(output.is_some());

        let internal_guard_after_tick = socket.internal.lock().unwrap();
        assert_eq!(internal_guard_after_tick.outgoing_packets.len(), 0);
    }

    #[test]
    fn test_write_and_read_data() {
        let socket = create_test_socket();
        let remote_addr = socket.remote_address();
        let wnd_size = 10000;

        let client_first_data_seq_nr;
        {
            let mut internal = socket.internal.lock().unwrap();
            internal.state = ConnectionState::Connected;
            internal.conn.ack_nr = 99;
            client_first_data_seq_nr = internal.conn.seq_nr;
        }

        let test_data = b"Hello, uTP!";
        let bytes_written = socket.write_data(test_data).unwrap();
        assert_eq!(bytes_written, test_data.len());

        let output_data_opt = socket.tick().unwrap();
        assert!(output_data_opt.is_some(), "Tick should produce a data packet");

        let client_recv_id = socket.connection_id();

        let incoming_payload = b"Received data from peer";
        let server_data_packet = create_test_data_packet(client_recv_id, 100, client_first_data_seq_nr, incoming_payload, remote_addr, wnd_size);
        socket.process_incoming_datagram(&serialize_packet(&server_data_packet), remote_addr);

        let _ = socket.tick().unwrap();

        let mut read_buf = [0u8; 100];
        let bytes_read = socket.read_data(&mut read_buf).unwrap();
        assert_eq!(bytes_read, incoming_payload.len(), "Did not read expected number of bytes");
        assert_eq!(&read_buf[..bytes_read], incoming_payload, "Read data does not match incoming payload");

        let internal = socket.internal.lock().unwrap();
        assert!(internal.rm.needs_ack_packet(), "Socket should need to send an ACK after receiving data");
    }

    #[test]
    fn test_connection_establishment() {
        let socket = create_test_socket();
        let remote_addr = socket.remote_address();
        let wnd_size = 10000;

        let client_syn_seq_nr = {
            let internal = socket.internal.lock().unwrap();
            internal.conn.seq_nr
        };
        socket.connect().unwrap();
        assert_eq!(socket.get_state(), ConnectionState::SynSent);
        let syn_packet_bytes = socket.tick().unwrap().expect("SYN packet not sent");

        let client_recv_id_from_syn = UtpPacket::from_bytes(&syn_packet_bytes, remote_addr).unwrap().header.connection_id();
        let server_seq_nr: u16 = 500;
        let synack_packet = create_test_synack_packet(client_recv_id_from_syn, client_syn_seq_nr, server_seq_nr, remote_addr, wnd_size);

        socket.process_incoming_datagram(&serialize_packet(&synack_packet), remote_addr);
        let ack_for_synack_opt = socket.tick().unwrap();

        assert_eq!(socket.get_state(), ConnectionState::Connected);
        assert!(ack_for_synack_opt.is_some(), "Client should send an ACK for the SYN-ACK");

        let internal = socket.internal.lock().unwrap();
        assert_eq!(internal.conn.ack_nr, server_seq_nr);
        assert_eq!(internal.rm.needs_ack_packet(), false);
    }

    #[test]
    fn test_async_initialize() {
        let socket = create_test_socket();
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let conn_id = 12345;
            socket.initialize_from_connection(conn_id).await.unwrap();
            assert_eq!(socket.connection_id(), conn_id);

            let internal = socket.internal.lock().unwrap();
            assert_eq!(internal.conn.send_id, conn_id.wrapping_sub(1));
            assert_eq!(internal.state, ConnectionState::Connected);
        });
    }

    #[test]
    fn test_packet_retransmission() {
        let socket = create_test_socket();

        {
            let mut internal = socket.internal.lock().unwrap();
            internal.state = ConnectionState::Connected;
        }

        let test_data = b"Test data for retransmission";
        socket.write_data(test_data).unwrap();

        let _first_packet_bytes = socket.tick().unwrap().expect("Tick 1: Initial packet not sent");

        let seq_nr_of_sent_packet = {
            let internal = socket.internal.lock().unwrap();
            assert_eq!(internal.conn.sent_packets.len(), 1, "Packet not tracked by RM after sending");
            *internal.conn.sent_packets.keys().next().unwrap()
        };

        {
            let mut internal = socket.internal.lock().unwrap();
            internal.rto_timeout_at_ms = (current_micros() / 1000).saturating_sub(100);
            internal.last_timeout_check = (current_micros() / 1000).saturating_sub(MAX_TIMEOUT_CHECK_INTERVAL + 100);
            internal.rm.set_needs_retransmit(seq_nr_of_sent_packet);
        }

        let mut retransmitted_packet_found_in_stats = false;
        for i in 0..10 {
            if socket.tick().unwrap().is_some() {
            }
            let stats_after_tick = socket.get_stats();
            eprintln!("Tick {}: Stats = {:?}", i, stats_after_tick);
            if stats_after_tick.packets_retransmitted > 0 {
                retransmitted_packet_found_in_stats = true;
                break;
            }
        }

        assert!(retransmitted_packet_found_in_stats, "Packet retransmission did not occur or stats not updated. Stats: {:?}", socket.get_stats());
        let final_stats = socket.get_stats();
        assert!(final_stats.packets_retransmitted > 0, "Final check: Packets_retransmitted is still 0. Stats: {:?}", final_stats);
        assert!(final_stats.packets_lost > 0, "Packets_lost should be incremented on timeout. Stats: {:?}", final_stats);
    }

    #[test]
    fn test_connection_close() {
        let socket = create_test_socket();
        let remote_addr = socket.remote_address();
        let wnd_size = 10000;

        {
            let mut internal = socket.internal.lock().unwrap();
            internal.state = ConnectionState::Connected;
        }

        socket.close().unwrap();
        assert_eq!(socket.get_state(), ConnectionState::FinSent);

        let fin_packet_bytes_opt = socket.tick().unwrap();
        assert!(fin_packet_bytes_opt.is_some(), "FIN packet not sent");

        let (client_fin_seq_nr, client_send_id) = {
            let internal = socket.internal.lock().unwrap();
            (internal.conn.seq_nr.wrapping_sub(1), internal.conn.send_id)
        };

        let peer_fin_packet = create_test_fin_packet(client_send_id, 700, client_fin_seq_nr, remote_addr, wnd_size);
        socket.process_incoming_datagram(&serialize_packet(&peer_fin_packet), remote_addr);

        let _ack_for_peer_fin_opt = socket.tick().unwrap();
        assert_eq!(socket.get_state(), ConnectionState::Closed);
    }
}