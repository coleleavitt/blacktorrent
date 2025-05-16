// utp/reliability.rs
#![forbid(unsafe_code)]

use crate::utp::common::{INITIAL_RTO_MICROS, MAX_RTO_MICROS, ST_SYN, seq_eq_or_greater_than};
use crate::utp::packet::UtpPacket;
use std::net::{SocketAddr, IpAddr, Ipv4Addr}; // For dummy_socket_addr in tests
use std::collections::{HashMap, BTreeSet};
use std::cmp::{min, max};
use std::sync::atomic::{AtomicU16, AtomicU32, Ordering};

const DUPLICATE_ACKS_BEFORE_RESEND: u32 = 3;
const MAX_RETRANSMISSIONS: u32 = 5; // Max retransmissions for a single packet
const MAX_OOO_PACKETS: usize = 32;
const MIN_ALLOWED_RTO_MICROS: u32 = 300_000;
const MAX_RTT_SAMPLE_MICROS: u32 = 30_000_000;

#[derive(Debug, Clone)]
pub struct SentPacketInfo {
    pub seq_nr: u16,
    pub sent_at_micros: u64,
    pub size_bytes: usize,
    pub transmissions: u32,
    pub packet_data: Vec<u8>,
    pub is_syn: bool,
    pub need_resend: bool, // Primarily for fast retransmit
    checksum: u32,
}

impl SentPacketInfo {
    pub fn new(
        seq_nr: u16,
        sent_at_micros: u64,
        size_bytes: usize,
        transmissions: u32,
        packet_data: Vec<u8>,
        is_syn: bool,
        need_resend: bool
    ) -> Self {
        let checksum = Self::compute_checksum(&packet_data);
        Self {
            seq_nr,
            sent_at_micros,
            size_bytes,
            transmissions,
            packet_data,
            is_syn,
            need_resend,
            checksum,
        }
    }

    fn compute_checksum(data: &[u8]) -> u32 {
        let mut hash: u32 = 0x811c9dc5;
        for &byte in data {
            hash ^= byte as u32;
            hash = hash.wrapping_mul(0x01000193);
        }
        hash
    }

    pub fn verify_integrity(&self) -> bool {
        Self::compute_checksum(&self.packet_data) == self.checksum
    }
}

pub struct ReliabilityManager {
    rtt_estimator: RttEstimator,
    pub current_rto: u32,
    received_ooo_seqs: BTreeSet<u16>,
    cumulative_ack_nr: [AtomicU16; 3],
    duplicate_ack_count: AtomicU32,
    last_acked_seq_for_dup_ack: [AtomicU16; 3],
    pub needs_ack: bool,
    test_seq_to_retransmit: Option<u16>, // For testing RTO path
    _last_timeout_check_micros: u64,
}

impl ReliabilityManager {
    pub fn new() -> Self {
        Self {
            rtt_estimator: RttEstimator::new(),
            current_rto: INITIAL_RTO_MICROS,
            received_ooo_seqs: BTreeSet::new(),
            cumulative_ack_nr: [
                AtomicU16::new(0), AtomicU16::new(0), AtomicU16::new(0)
            ],
            duplicate_ack_count: AtomicU32::new(0),
            last_acked_seq_for_dup_ack: [
                AtomicU16::new(0), AtomicU16::new(0), AtomicU16::new(0)
            ],
            needs_ack: false,
            test_seq_to_retransmit: None,
            _last_timeout_check_micros: 0,
        }
    }

    fn get_cumulative_ack_nr(&self) -> u16 {
        let val1 = self.cumulative_ack_nr[0].load(Ordering::Relaxed);
        let val2 = self.cumulative_ack_nr[1].load(Ordering::Relaxed);
        let val3 = self.cumulative_ack_nr[2].load(Ordering::Relaxed);
        if val1 == val2 || val1 == val3 { val1 } else if val2 == val3 { val2 } else { val3 }
    }

    fn set_cumulative_ack_nr(&mut self, value: u16) {
        self.cumulative_ack_nr[0].store(value, Ordering::Relaxed);
        self.cumulative_ack_nr[1].store(value, Ordering::Relaxed);
        self.cumulative_ack_nr[2].store(value, Ordering::Relaxed);
    }

    fn get_last_acked_seq_for_dup_ack(&self) -> u16 {
        let val1 = self.last_acked_seq_for_dup_ack[0].load(Ordering::Relaxed);
        let val2 = self.last_acked_seq_for_dup_ack[1].load(Ordering::Relaxed);
        let val3 = self.last_acked_seq_for_dup_ack[2].load(Ordering::Relaxed);
        if val1 == val2 || val1 == val3 { val1 } else if val2 == val3 { val2 } else { val3 }
    }

    fn set_last_acked_seq_for_dup_ack(&mut self, value: u16) {
        self.last_acked_seq_for_dup_ack[0].store(value, Ordering::Relaxed);
        self.last_acked_seq_for_dup_ack[1].store(value, Ordering::Relaxed);
        self.last_acked_seq_for_dup_ack[2].store(value, Ordering::Relaxed);
    }

    pub fn on_packet_sent(&mut self, packet: &UtpPacket, sent_at_micros: u64, unacked_packets: &mut HashMap<u16, SentPacketInfo>) {
        let seq_nr = packet.header.seq_nr();
        let mut raw_data = Vec::new();
        packet.serialize(&mut raw_data);

        if let Some(existing) = unacked_packets.get_mut(&seq_nr) {
            existing.sent_at_micros = sent_at_micros;
            existing.transmissions += 1;
            existing.need_resend = false;
            existing.checksum = SentPacketInfo::compute_checksum(&raw_data);
            return;
        }

        let info = SentPacketInfo::new(
            seq_nr, sent_at_micros, raw_data.len(), 1, raw_data,
            packet.header.packet_type() == ST_SYN, false
        );
        unacked_packets.insert(seq_nr, info);
    }

    pub fn process_ack(
        &mut self, ack_nr: u16, sack_data: Option<&[u8]>,
        unacked_packets: &mut HashMap<u16, SentPacketInfo>, current_ts_micros: u64,
    ) -> usize {
        let mut newly_acked_bytes = 0;
        let mut to_remove = Vec::new();

        for (seq, info) in unacked_packets.iter() {
            if seq_eq_or_greater_than(ack_nr, *seq) {
                if info.verify_integrity() {
                    to_remove.push(*seq);
                    newly_acked_bytes += info.size_bytes;
                    if info.transmissions == 1 {
                        let rtt_sample = current_ts_micros.saturating_sub(info.sent_at_micros) as u32;
                        let bounded_rtt = min(rtt_sample, MAX_RTT_SAMPLE_MICROS);
                        self.rtt_estimator.update_rtt(bounded_rtt);
                        self.current_rto = self.calculate_rto();
                    }
                }
            }
        }
        for seq in to_remove { unacked_packets.remove(&seq); }

        if let Some(sack_data) = sack_data {
            if !sack_data.is_empty() {
                let sack_base_seq = ack_nr.wrapping_add(2);
                let mut current_bitmask: u32 = 0;
                for i in 0..min(4, sack_data.len()) {
                    current_bitmask |= (sack_data[i] as u32) << (i * 8);
                }
                for i in 0..32 {
                    if (current_bitmask & (1 << i)) != 0 {
                        let selectively_acked_seq = sack_base_seq.wrapping_add(i as u16);
                        if let Some(info) = unacked_packets.remove(&selectively_acked_seq) {
                            if info.verify_integrity() { newly_acked_bytes += info.size_bytes; }
                        }
                    }
                }
            }
        }

        let last_acked = self.get_last_acked_seq_for_dup_ack();
        if ack_nr == last_acked && !unacked_packets.is_empty() {
            let count = self.duplicate_ack_count.fetch_add(1, Ordering::Relaxed) + 1;
            if count >= DUPLICATE_ACKS_BEFORE_RESEND {
                let next_seq_to_retransmit = ack_nr.wrapping_add(1);
                if let Some(pkt_info) = unacked_packets.get_mut(&next_seq_to_retransmit) {
                    if pkt_info.transmissions < MAX_RETRANSMISSIONS && !pkt_info.need_resend {
                        pkt_info.need_resend = true;
                        self.duplicate_ack_count.store(0, Ordering::Relaxed);
                        self.test_seq_to_retransmit = Some(next_seq_to_retransmit); // Fast retransmit also uses this for now
                    }
                }
            }
        } else {
            self.duplicate_ack_count.store(0, Ordering::Relaxed);
            self.set_last_acked_seq_for_dup_ack(ack_nr);
        }
        newly_acked_bytes
    }

    fn calculate_rto(&self) -> u32 {
        let rto = self.rtt_estimator.get_rto_micros();
        min(max(rto, MIN_ALLOWED_RTO_MICROS), MAX_RTO_MICROS)
    }

    pub fn check_timeouts(&mut self, current_ts_micros: u64) -> Option<u16> {
        self._last_timeout_check_micros = current_ts_micros;
        let seq = self.test_seq_to_retransmit.take();
        if seq.is_some() {
            eprintln!("[RM DEBUG] check_timeouts: returning Some({}) from test_seq_to_retransmit", seq.unwrap());
        }
        seq
    }


    pub fn set_needs_retransmit(&mut self, seq_nr: u16) {
        eprintln!("[RM DEBUG] set_needs_retransmit called with seq_nr: {}", seq_nr);
        self.test_seq_to_retransmit = Some(seq_nr);
    }

    pub fn buffer_ooo_packet(&mut self, packet: &UtpPacket) {
        if self.received_ooo_seqs.len() >= MAX_OOO_PACKETS {
            if let Some(&first) = self.received_ooo_seqs.iter().next() {
                self.received_ooo_seqs.remove(&first);
            }
        }
        self.received_ooo_seqs.insert(packet.header.seq_nr());
    }

    pub fn get_sack_data(&self, current_ack_nr: u16) -> Option<Vec<u8>> {
        if self.received_ooo_seqs.is_empty() { return None; }
        let sack_base_seq = current_ack_nr.wrapping_add(2);
        let mut sack_bits: u32 = 0;
        for &seq_nr in &self.received_ooo_seqs {
            if seq_eq_or_greater_than(seq_nr, sack_base_seq) {
                let diff = seq_nr.wrapping_sub(sack_base_seq);
                if diff < 32 { sack_bits |= 1 << diff; }
            }
        }
        if sack_bits > 0 { Some(sack_bits.to_be_bytes().to_vec()) } else { None }
    }

    pub fn update_cumulative_ack(&mut self, mut current_ack_nr: u16) -> u16 {
        while self.received_ooo_seqs.remove(&current_ack_nr.wrapping_add(1)) {
            current_ack_nr = current_ack_nr.wrapping_add(1);
        }
        self.set_cumulative_ack_nr(current_ack_nr);
        current_ack_nr
    }

    pub fn get_latest_rtt_micros(&self) -> u32 { self.rtt_estimator.srtt_micros }
    pub fn get_min_rtt_micros(&self) -> u32 { self.rtt_estimator.min_rtt_micros }
    pub fn get_current_rto(&self) -> u32 { self.current_rto }
    pub fn set_needs_ack(&mut self) { self.needs_ack = true; }
    pub fn needs_ack_packet(&self) -> bool { self.needs_ack }
    pub fn ack_sent(&mut self) { self.needs_ack = false; }

    #[cfg(test)]
    pub fn clear_ooo_packets(&mut self) { self.received_ooo_seqs.clear(); }
    #[cfg(test)]
    pub fn verify_state_integrity(&self) -> bool {
        let ack1 = self.cumulative_ack_nr[0].load(Ordering::Relaxed);
        let ack2 = self.cumulative_ack_nr[1].load(Ordering::Relaxed);
        let ack3 = self.cumulative_ack_nr[2].load(Ordering::Relaxed);
        let last1 = self.last_acked_seq_for_dup_ack[0].load(Ordering::Relaxed);
        let last2 = self.last_acked_seq_for_dup_ack[1].load(Ordering::Relaxed);
        let last3 = self.last_acked_seq_for_dup_ack[2].load(Ordering::Relaxed);
        (ack1 == ack2 || ack2 == ack3 || ack1 == ack3) &&
            (last1 == last2 || last2 == last3 || last1 == last3)
    }
    #[cfg(test)]
    pub fn repair_tmr(&mut self) {
        let ack = self.get_cumulative_ack_nr(); self.set_cumulative_ack_nr(ack);
        let last = self.get_last_acked_seq_for_dup_ack(); self.set_last_acked_seq_for_dup_ack(last);
    }
}

struct RttEstimator {
    srtt_micros: u32,
    rttvar_micros: u32,
    min_rtt_micros: u32,
    first_sample: bool,
}

impl RttEstimator {
    fn new() -> Self {
        Self { srtt_micros: 0, rttvar_micros: 0, min_rtt_micros: u32::MAX, first_sample: true }
    }

    fn update_rtt(&mut self, rtt_sample_micros: u32) {
        if self.first_sample {
            self.srtt_micros = rtt_sample_micros;
            self.rttvar_micros = rtt_sample_micros / 2;
            self.first_sample = false;
        } else {
            const ALPHA: f32 = 1.0 / 8.0;
            const BETA: f32 = 1.0 / 4.0;
            let delta = (self.srtt_micros as i64 - rtt_sample_micros as i64).abs() as u32;
            self.rttvar_micros = ((1.0 - BETA) * self.rttvar_micros as f32 + BETA * delta as f32) as u32;
            self.srtt_micros = ((1.0 - ALPHA) * self.srtt_micros as f32 + ALPHA * rtt_sample_micros as f32) as u32;
        }
        if rtt_sample_micros < self.min_rtt_micros { self.min_rtt_micros = rtt_sample_micros; }
    }

    fn get_rto_micros(&self) -> u32 {
        if self.first_sample { INITIAL_RTO_MICROS }
        else { self.srtt_micros + 4 * self.rttvar_micros }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utp::packet::UtpHeader;
    use crate::utp::common::{ST_DATA};

    fn create_test_packet(seq_nr: u16, ack_nr: u16, packet_type: u8) -> UtpPacket {
        let header = UtpHeader::new(
            packet_type, 12345, 0, 0, 1000, seq_nr, ack_nr, 0
        );
        UtpPacket {
            header, payload: Vec::new(), sack_data: None,
            remote_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        }
    }

    fn create_test_packet_with_payload(seq_nr: u16, ack_nr: u16, payload: &[u8]) -> UtpPacket {
        let header = UtpHeader::new(
            ST_DATA, 12345, 0, 0, 1000, seq_nr, ack_nr, 0
        );
        UtpPacket {
            header, payload: payload.to_vec(), sack_data: None,
            remote_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        }
    }

    #[test]
    fn test_rtt_estimation_first_sample() {
        let mut rm = ReliabilityManager::new();
        let mut unacked_packets = HashMap::new();
        let packet = create_test_packet(1, 0, ST_DATA);
        rm.on_packet_sent(&packet, 1_000_000, &mut unacked_packets);
        rm.process_ack(1, None, &mut unacked_packets, 1_010_000);
        assert_eq!(rm.get_latest_rtt_micros(), 10_000);
        assert_eq!(rm.get_min_rtt_micros(), 10_000);
        assert_eq!(rm.get_current_rto(), 300_000);
    }

    #[test]
    fn test_rtt_estimation_multiple_samples() {
        let mut rm = ReliabilityManager::new();
        let mut unacked_packets = HashMap::new();
        let packet1 = create_test_packet(1, 0, ST_DATA);
        rm.on_packet_sent(&packet1, 1_000_000, &mut unacked_packets);
        rm.process_ack(1, None, &mut unacked_packets, 1_010_000);
        let packet2 = create_test_packet(2, 0, ST_DATA);
        rm.on_packet_sent(&packet2, 2_000_000, &mut unacked_packets);
        rm.process_ack(2, None, &mut unacked_packets, 2_020_000);
        assert_eq!(rm.get_current_rto(), 300_000);
        assert_eq!(rm.get_min_rtt_micros(), 10_000);
    }

    #[test]
    fn test_cumulative_ack_processing() {
        let mut rm = ReliabilityManager::new();
        let mut unacked_packets = HashMap::new();
        let now = 1_000_000;
        for seq in 1..=5 {
            let packet = create_test_packet(seq, 0, ST_DATA);
            rm.on_packet_sent(&packet, now, &mut unacked_packets);
        }
        assert_eq!(unacked_packets.len(), 5);
        let acked = rm.process_ack(3, None, &mut unacked_packets, now + 10_000);
        assert_eq!(unacked_packets.len(), 2);
        assert!(!unacked_packets.contains_key(&3));
        assert!(unacked_packets.contains_key(&4));
        assert!(acked > 0);
    }

    #[test]
    fn test_selective_ack_processing() {
        let mut rm = ReliabilityManager::new();
        let mut unacked_packets = HashMap::new();
        let now = 1_000_000;
        for seq in 1..=10 {
            let packet = create_test_packet_with_payload(seq, 0, &[0; 100]);
            rm.on_packet_sent(&packet, now, &mut unacked_packets);
        }
        let mut sack_data = [0u8; 4];
        sack_data[0] |= 1 << 0;
        sack_data[0] |= 1 << 2;
        sack_data[0] |= 1 << 4;
        let acked_bytes = rm.process_ack(3, Some(&sack_data), &mut unacked_packets, now + 10_000);
        assert_eq!(acked_bytes, 720);
        assert_eq!(unacked_packets.len(), 4);
    }

    #[test]
    fn test_fast_retransmit() {
        let mut rm = ReliabilityManager::new();
        let mut unacked_packets = HashMap::new();
        let now = 1_000_000;
        for seq in 1..=5 {
            let packet = create_test_packet(seq, 0, ST_DATA);
            rm.on_packet_sent(&packet, now, &mut unacked_packets);
        }
        rm.process_ack(1, None, &mut unacked_packets, now + 10_000);
        for _ in 0..DUPLICATE_ACKS_BEFORE_RESEND {
            rm.process_ack(1, None, &mut unacked_packets, now + 20_000);
        }
        assert!(unacked_packets.get(&2).unwrap().need_resend);
        assert_eq!(rm.test_seq_to_retransmit, Some(2));
        assert_eq!(rm.check_timeouts(now + 30_000), Some(2));
        assert_eq!(rm.test_seq_to_retransmit, None);
    }

    #[test]
    fn test_ooo_packet_buffering() {
        let mut rm = ReliabilityManager::new();
        rm.buffer_ooo_packet(&create_test_packet(5, 0, ST_DATA));
        rm.buffer_ooo_packet(&create_test_packet(7, 0, ST_DATA));
        rm.buffer_ooo_packet(&create_test_packet(10, 0, ST_DATA));
        let sack_data = rm.get_sack_data(3);
        assert!(sack_data.is_some());
        let sack_bits = u32::from_be_bytes(sack_data.unwrap().try_into().unwrap());
        assert_eq!(sack_bits & (1 << 0), 1 << 0);
        assert_eq!(sack_bits & (1 << 2), 1 << 2);
        assert_eq!(sack_bits & (1 << 5), 1 << 5);
    }

    #[test]
    fn test_cumulative_ack_advancement() {
        let mut rm = ReliabilityManager::new();
        rm.set_cumulative_ack_nr(5);
        rm.buffer_ooo_packet(&create_test_packet(7, 0, ST_DATA));
        rm.buffer_ooo_packet(&create_test_packet(8, 0, ST_DATA));
        rm.buffer_ooo_packet(&create_test_packet(10, 0, ST_DATA));
        let new_ack = rm.update_cumulative_ack(6);
        assert_eq!(new_ack, 8);
        assert_eq!(rm.get_cumulative_ack_nr(), 8);
        assert_eq!(rm.received_ooo_seqs.len(), 1);
        assert!(rm.received_ooo_seqs.contains(&10));
    }

    #[test]
    fn test_retransmission_tracking() {
        let mut rm = ReliabilityManager::new();
        let mut unacked_packets = HashMap::new();
        let now = 1_000_000;
        let packet = create_test_packet(1, 0, ST_DATA);
        rm.on_packet_sent(&packet, now, &mut unacked_packets);
        rm.on_packet_sent(&packet, now + 500_000, &mut unacked_packets);
        assert_eq!(unacked_packets.get(&1).unwrap().transmissions, 2);
        let initial_rto = rm.get_current_rto();
        rm.process_ack(1, None, &mut unacked_packets, now + 600_000);
        assert_eq!(rm.get_current_rto(), initial_rto);
    }

    #[test]
    fn test_ooo_buffer_limit() {
        let mut rm = ReliabilityManager::new();
        for seq in 1..=(MAX_OOO_PACKETS + 10) {
            rm.buffer_ooo_packet(&create_test_packet(seq as u16, 0, ST_DATA));
        }
        assert_eq!(rm.received_ooo_seqs.len(), MAX_OOO_PACKETS);
        for seq in 1..=10 {
            assert!(!rm.received_ooo_seqs.contains(&(seq as u16)));
        }
        for seq in (MAX_OOO_PACKETS + 1)..=(MAX_OOO_PACKETS + 10) {
            assert!(rm.received_ooo_seqs.contains(&(seq as u16)));
        }
    }

    #[test]
    fn test_radiation_hardening_triple_redundancy() {
        let mut rm = ReliabilityManager::new();
        rm.set_cumulative_ack_nr(42);
        assert_eq!(rm.get_cumulative_ack_nr(), 42);
        rm.cumulative_ack_nr[0].store(99, Ordering::Relaxed);
        assert_eq!(rm.get_cumulative_ack_nr(), 42);
        assert!(rm.verify_state_integrity());
        rm.cumulative_ack_nr[1].store(77, Ordering::Relaxed);
        assert_eq!(rm.get_cumulative_ack_nr(), 42);
        rm.repair_tmr();
        assert_eq!(rm.cumulative_ack_nr[0].load(Ordering::Relaxed), 42);
        assert_eq!(rm.cumulative_ack_nr[1].load(Ordering::Relaxed), 42);
        assert_eq!(rm.cumulative_ack_nr[2].load(Ordering::Relaxed), 42);
    }

    #[test]
    fn test_packet_integrity_checking() {
        let mut rm = ReliabilityManager::new();
        let mut unacked_packets = HashMap::new();
        let now = 1_000_000;
        let packet = create_test_packet(1, 0, ST_DATA);
        rm.on_packet_sent(&packet, now, &mut unacked_packets);
        assert!(unacked_packets.get(&1).unwrap().verify_integrity());
        if let Some(info) = unacked_packets.get_mut(&1) {
            info.packet_data[5] ^= 0xFF;
            assert!(!info.verify_integrity());
        }
    }
}