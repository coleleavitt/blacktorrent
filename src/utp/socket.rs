// utp/socket.rs

use crate::utp::common::{ConnectionState, UtpError, current_micros};
use crate::utp::packet::{UtpPacket, BASE_HEADER_SIZE};
use crate::utp::connection::Connection;
use crate::utp::congestion::CongestionControl;
use crate::utp::reliability::ReliabilityManager;

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::cmp::min;

const DEFAULT_KEEPALIVE_INTERVAL: u64 = 29_000;
const CONNECT_TIMEOUT: u64 = 6_000;
const MAX_TIMEOUT_CHECK_INTERVAL: u64 = 500;
const MIN_PACKET_SIZE: usize = 150;
const MAX_RETRANSMISSIONS: u32 = 5;

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
    pub(crate) rto_timeout: u64,
    pub(crate) retransmit_count: u32,
    pub(crate) needs_ack: bool,
    pub(crate) fin_sent: bool,
    pub(crate) fin_received: bool,
    pub(crate) close_requested: bool,
}

impl UtpSocketInternal {
    fn get_mtu(&self) -> usize {
        min(1500, self.cc.get_receive_window_size())
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
        if self.rto_timeout > 0 && now_ms >= self.rto_timeout {
            if self.state == ConnectionState::SynSent {
                if self.retransmit_count >= MAX_RETRANSMISSIONS {
                    self.state = ConnectionState::Reset;
                    return;
                }
                let syn = self.create_syn();
                self.outgoing_packets.push_back(syn);
                self.retransmit_count += 1;
                let new_rto = self.rm.get_current_rto() as u64 * 2;
                self.rm.current_rto = new_rto as u32;
                self.rto_timeout = now_ms + new_rto;
            } else if self.rm.check_timeouts(current_micros()).is_some() {
                self.cc.on_timeout();
                let rto = self.rm.get_current_rto() as u64;
                self.rto_timeout = now_ms + rto;
            }
        }

        if self.state == ConnectionState::SynSent
            && now_ms.saturating_sub(self.created_time / 1_000) > CONNECT_TIMEOUT
        {
            self.state = ConnectionState::Reset;
        }

        if self.state == ConnectionState::FinSent
            && now_ms.saturating_sub(self.last_packet_sent_time / 1_000)
            > (self.rm.get_current_rto() as u64 * 2)
        {
            self.state = ConnectionState::Closed;
        }

        if self.state == ConnectionState::Reset
            && now_ms.saturating_sub(self.last_packet_sent_time / 1_000) > 1_000
        {
            self.state = ConnectionState::Destroying;
        }
    }

    fn package_data_from_buffer(&mut self) {
        if self.state != ConnectionState::Connected || self.send_buffer.is_empty() {
            return;
        }

        let cwnd = self.cc.get_congestion_window_size();
        let max_payload = min(cwnd, self.get_mtu() - BASE_HEADER_SIZE);
        let in_flight = self.cc.bytes_in_flight();
        let avail = cwnd.saturating_sub(in_flight);

        if avail < MIN_PACKET_SIZE || max_payload < MIN_PACKET_SIZE {
            return;
        }

        let to_send = min(max_payload, self.send_buffer.len());
        let mut payload = Vec::with_capacity(to_send);
        for _ in 0..to_send {
            if let Some(b) = self.send_buffer.pop_front() {
                payload.push(b);
            }
        }

        let pkt = self.create_data(payload);
        self.cc.on_packet_sent(pkt.payload_size());
        self.outgoing_packets.push_back(pkt);
    }

    fn send_keep_alive(&mut self) {
        let ka = self.create_ack(false);
        self.outgoing_packets.push_back(ka);
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
            last_timeout_check: now / 1_000,
            rto_timeout: 0,
            retransmit_count: 0,
            needs_ack: false,
            fin_sent: false,
            fin_received: false,
            close_requested: false,
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
        let syn = i.create_syn();
        i.outgoing_packets.push_back(syn);
        i.last_packet_sent_time = current_micros();
        let rto = i.rm.get_current_rto() as u64;
        i.rto_timeout = current_micros() / 1_000 + rto;
        Ok(())
    }

    pub fn process_incoming_datagram(&self, data: &[u8], from: SocketAddr) {
        let valid = { self.internal.lock().unwrap().remote_addr == from };
        if !valid { return; }
        if let Ok(pkt) = UtpPacket::from_bytes(data, from) {
            self.internal.lock().unwrap().incoming_packets.push_back(pkt);
        }
    }

    pub fn tick(&self) -> Result<Option<Vec<u8>>, UtpError> {
        let mut i = self.internal.lock().unwrap();
        let now_us = current_micros();
        let now_ms = now_us / 1_000;

        // Process incoming packets
        while let Some(pkt) = i.incoming_packets.pop_front() {
            i.last_packet_recv_time = now_us;

            // Extract all needed mutable references in one go
            let UtpSocketInternal {
                conn,
                cc,
                rm,
                recv_buffer,
                state,
                ..
            } = &mut *i;

            conn.handle_incoming_packet(&pkt, cc, rm, recv_buffer, state, now_us);
            i.needs_ack = true;
        }

        // Check timeouts
        if now_ms.saturating_sub(i.last_timeout_check) >= MAX_TIMEOUT_CHECK_INTERVAL {
            i.last_timeout_check = now_ms;
            i.check_timeouts(now_ms);
        }

        // Send ACK if needed
        if i.needs_ack {
            let ack = i.create_ack(false);
            i.outgoing_packets.push_back(ack);
            i.needs_ack = false;
        }

        // Package data from buffer
        i.package_data_from_buffer();

        // Keep-alive
        if i.state == ConnectionState::Connected
            && !i.fin_sent
            && now_ms.saturating_sub(i.last_packet_sent_time / 1_000)
            >= DEFAULT_KEEPALIVE_INTERVAL
        {
            i.send_keep_alive();
        }

        // Emit packet
        if let Some(pkt) = i.outgoing_packets.pop_front() {
            i.last_packet_sent_time = now_us;
            let ty = pkt.header.packet_type();

            // Extract needed mutable references for packet sending
            let UtpSocketInternal { rm, conn, .. } = &mut *i;

            if ty == crate::utp::common::ST_DATA || ty == crate::utp::common::ST_SYN {
                rm.on_packet_sent(&pkt, now_us, &mut conn.sent_packets);
            }

            let mut buf = Vec::new();
            pkt.serialize(&mut buf);
            return Ok(Some(buf));
        }

        Ok(None)
    }
    
    pub fn write_data(&self, data: &[u8]) -> Result<usize, UtpError> {
        let mut i = self.internal.lock().unwrap();
        if i.state != ConnectionState::Connected || i.fin_sent || i.close_requested {
            return Err(UtpError::InvalidState);
        }
        i.send_buffer.extend(data);
        Ok(data.len())
    }

    pub fn read_data(&self, buf: &mut [u8]) -> Result<usize, UtpError> {
        let mut i = self.internal.lock().unwrap();
        if i.recv_buffer.is_empty() {
            if i.fin_received
                || i.state == ConnectionState::Closed
                || i.state == ConnectionState::Reset
            {
                return Ok(0);
            }
            return Err(UtpError::Network(std::io::Error::new(
                std::io::ErrorKind::WouldBlock, "No data available",
            )));
        }
        let mut n = 0;
        while n < buf.len() {
            if let Some(b) = i.recv_buffer.pop_front() {
                buf[n] = b;
                n += 1;
            } else {
                break;
            }
        }
        if n > 0 { i.needs_ack = true; }
        Ok(n)
    }

    pub fn close(&self) -> Result<(), UtpError> {
        let mut i = self.internal.lock().unwrap();
        i.close_requested = true;
        match i.state {
            ConnectionState::Connected | ConnectionState::ConnectedFull => {
                if !i.fin_sent {
                    i.state = ConnectionState::FinSent;
                    i.fin_sent = true;
                    let fin = i.create_fin();
                    i.outgoing_packets.push_back(fin);
                    i.last_packet_sent_time = current_micros();
                }
            }
            ConnectionState::SynSent | ConnectionState::SynRecv => {
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
        self.internal.lock().unwrap().rm.get_latest_rtt_micros() / 1_000
    }

    pub fn get_mtu(&self) -> usize {
        self.internal.lock().unwrap().get_mtu()
    }

    pub fn is_send_buffer_empty(&self) -> bool {
        self.internal.lock().unwrap().send_buffer.is_empty()
    }

    pub fn connection_id(&self) -> u16 {
        // Return the connection ID from internal state
        self.internal.lock().unwrap().conn.recv_id
    }
    
    pub async fn initialize_from_connection(&self, conn_id: u16) -> Result<(), UtpError> {
        // Set connection ID and other needed state
        let mut internal = self.internal.lock().unwrap();
        internal.conn.recv_id = conn_id;
        // Initialize other connection state...
        Ok(())
    }
}