// utp/reliability.rs
#![forbid(unsafe_code)]

use crate::utp::common::{INITIAL_RTO_MICROS, MIN_RTO_MICROS, MAX_RTO_MICROS, ST_SYN, seq_eq_or_greater_than};
use crate::utp::packet::UtpPacket;
use std::net::{SocketAddr, IpAddr, Ipv4Addr};
use std::collections::{HashMap, BTreeSet};
use std::cmp::{min, max};
use std::sync::atomic::{AtomicU16, AtomicU32, Ordering};

/// Number of duplicate ACKs required before triggering fast retransmission
const DUPLICATE_ACKS_BEFORE_RESEND: u32 = 3;
/// Maximum number of retransmissions before giving up
const MAX_RETRANSMISSIONS: u32 = 5;
/// Maximum number of out-of-order packets to store in SACK buffer
const MAX_OOO_PACKETS: usize = 32;
/// Minimum RTO limit (in microseconds)
const MIN_ALLOWED_RTO_MICROS: u32 = 300_000; // 300ms
/// Maximum RTT sample value in microseconds (to guard against outliers)
const MAX_RTT_SAMPLE_MICROS: u32 = 30_000_000; // 30 seconds

/// Information about a sent packet awaiting acknowledgment
#[derive(Debug, Clone)]
pub struct SentPacketInfo {
    /// Sequence number of the sent packet
    pub seq_nr: u16,
    /// Timestamp when packet was sent (in microseconds)
    pub sent_at_micros: u64,
    /// Size of packet in bytes
    pub size_bytes: usize,
    /// Number of times this packet has been transmitted
    pub transmissions: u32,
    /// Raw packet data for retransmission
    pub packet_data: Vec<u8>,
    /// Whether this packet is a SYN packet
    pub is_syn: bool,
    /// Whether this packet needs to be retransmitted
    pub need_resend: bool,
    /// Checksum of packet data for integrity verification (radiation hardening)
    checksum: u32,
}

impl SentPacketInfo {
    /// Creates a new SentPacketInfo with automatically calculated checksum
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

    /// Compute CRC-32 checksum of packet data
    fn compute_checksum(data: &[u8]) -> u32 {
        // Simple FNV-1a hash for now
        // In a full implementation, use a proper CRC-32 algorithm
        let mut hash: u32 = 0x811c9dc5;
        for &byte in data {
            hash ^= byte as u32;
            hash = hash.wrapping_mul(0x01000193);
        }
        hash
    }

    /// Verify packet data integrity using checksum
    pub fn verify_integrity(&self) -> bool {
        Self::compute_checksum(&self.packet_data) == self.checksum
    }
}

/// Manages packet reliability including RTT estimation, retransmissions,
/// and selective acknowledgments (SACK)
pub struct ReliabilityManager {
    /// RTT estimator - handles smoothed RTT and variance calculations
    rtt_estimator: RttEstimator,
    /// Current retransmission timeout in microseconds
    pub current_rto: u32,
    /// Set of out-of-order sequence numbers received
    received_ooo_seqs: BTreeSet<u16>,
    /// The latest in-order packet we've acknowledged (with triple redundancy)
    cumulative_ack_nr: [AtomicU16; 3],
    /// Count of duplicate ACKs received for fast retransmit detection
    duplicate_ack_count: AtomicU32,
    /// The sequence number for which we're counting duplicate ACKs (with redundancy)
    last_acked_seq_for_dup_ack: [AtomicU16; 3],
    /// Flag to indicate an ACK should be sent soon
    pub needs_ack: bool,
    /// Sequence number that needs retransmission (for timeout tests)
    seq_to_retransmit: Option<u16>,
    /// Timestamp of last timeout check
    last_timeout_check_micros: u64,
}

impl ReliabilityManager {
    /// Creates a new reliability manager with default values
    pub fn new() -> Self {
        Self {
            rtt_estimator: RttEstimator::new(),
            current_rto: INITIAL_RTO_MICROS,
            received_ooo_seqs: BTreeSet::new(),
            // Initialize triple-redundant cumulative ACK
            cumulative_ack_nr: [
                AtomicU16::new(0),
                AtomicU16::new(0),
                AtomicU16::new(0)
            ],
            duplicate_ack_count: AtomicU32::new(0),
            // Initialize triple-redundant last ACKed sequence
            last_acked_seq_for_dup_ack: [
                AtomicU16::new(0),
                AtomicU16::new(0),
                AtomicU16::new(0)
            ],
            needs_ack: false,
            seq_to_retransmit: None,
            last_timeout_check_micros: 0,
        }
    }

    /// Get cumulative_ack_nr with triple redundancy voting
    fn get_cumulative_ack_nr(&self) -> u16 {
        let val1 = self.cumulative_ack_nr[0].load(Ordering::Relaxed);
        let val2 = self.cumulative_ack_nr[1].load(Ordering::Relaxed);
        let val3 = self.cumulative_ack_nr[2].load(Ordering::Relaxed);

        // Triple redundancy voting logic - majorify wins
        if val1 == val2 || val1 == val3 {
            val1
        } else if val2 == val3 {
            val2
        } else {
            // In a radiation-hardened system, all copies differing is a critical error
            // For now we'll pick the third value, but in production we'd log this event
            val3
        }
    }

    /// Set cumulative_ack_nr with triple redundancy
    fn set_cumulative_ack_nr(&mut self, value: u16) {
        self.cumulative_ack_nr[0].store(value, Ordering::Relaxed);
        self.cumulative_ack_nr[1].store(value, Ordering::Relaxed);
        self.cumulative_ack_nr[2].store(value, Ordering::Relaxed);
    }

    /// Get last_acked_seq_for_dup_ack with triple redundancy voting
    fn get_last_acked_seq_for_dup_ack(&self) -> u16 {
        let val1 = self.last_acked_seq_for_dup_ack[0].load(Ordering::Relaxed);
        let val2 = self.last_acked_seq_for_dup_ack[1].load(Ordering::Relaxed);
        let val3 = self.last_acked_seq_for_dup_ack[2].load(Ordering::Relaxed);

        // Triple redundancy voting logic - majority wins
        if val1 == val2 || val1 == val3 {
            val1
        } else if val2 == val3 {
            val2
        } else {
            // In a radiation-hardened system, all copies differing is a critical error
            // For now we'll pick the third value, but in production we'd log this event
            val3
        }
    }

    /// Set last_acked_seq_for_dup_ack with triple redundancy
    fn set_last_acked_seq_for_dup_ack(&mut self, value: u16) {
        self.last_acked_seq_for_dup_ack[0].store(value, Ordering::Relaxed);
        self.last_acked_seq_for_dup_ack[1].store(value, Ordering::Relaxed);
        self.last_acked_seq_for_dup_ack[2].store(value, Ordering::Relaxed);
    }

    /// Called when a packet is sent to track it for potential retransmission
    pub fn on_packet_sent(&mut self, packet: &UtpPacket, sent_at_micros: u64, unacked_packets: &mut HashMap<u16, SentPacketInfo>) {
        let seq_nr = packet.header.seq_nr();
        let mut raw_data = Vec::new();
        packet.serialize(&mut raw_data);

        // If this packet already exists (retransmission), update it
        if let Some(existing) = unacked_packets.get_mut(&seq_nr) {
            existing.sent_at_micros = sent_at_micros;
            existing.transmissions += 1;
            existing.need_resend = false;
            // Update checksum for new serialized data
            existing.checksum = SentPacketInfo::compute_checksum(&raw_data);
            return;
        }

        // Otherwise create new packet info
        let info = SentPacketInfo::new(
            seq_nr,
            sent_at_micros,
            raw_data.len(),
            1,
            raw_data,
            packet.header.packet_type() == ST_SYN,
            false
        );

        unacked_packets.insert(seq_nr, info);
    }

    /// Process an acknowledgement number and optional selective ACK (SACK) data
    pub fn process_ack(
        &mut self,
        ack_nr: u16,
        sack_data: Option<&[u8]>,
        unacked_packets: &mut HashMap<u16, SentPacketInfo>,
        current_ts_micros: u64,
    ) -> usize {
        let mut newly_acked_bytes = 0;
        let mut to_remove = Vec::new();

        // Process cumulative ACK
        for (seq, info) in unacked_packets.iter() {
            if seq_eq_or_greater_than(ack_nr, *seq) {
                // Verify packet integrity before accepting ACK
                if info.verify_integrity() {
                    to_remove.push(*seq);
                    newly_acked_bytes += info.size_bytes;

                    // Only update RTT estimates for packets that weren't retransmitted
                    if info.transmissions == 1 {
                        let rtt_sample = current_ts_micros.saturating_sub(info.sent_at_micros) as u32;
                        // Bound check RTT sample to prevent outliers
                        let bounded_rtt = min(rtt_sample, MAX_RTT_SAMPLE_MICROS);
                        self.rtt_estimator.update_rtt(bounded_rtt);
                        self.current_rto = self.calculate_rto();
                    }
                }
            }
        }

        // Remove acknowledged packets
        for seq in to_remove {
            unacked_packets.remove(&seq);
        }

        // Process SACK data if available
        if let Some(sack_data) = sack_data {
            if !sack_data.is_empty() {
                let sack_base_seq = ack_nr.wrapping_add(2);
                let mut current_bitmask: u32 = 0;

                // Reconstruct bitmask from SACK bytes
                for i in 0..std::cmp::min(4, sack_data.len()) {
                    // Shift each byte into the proper position in the 32-bit mask
                    current_bitmask |= (sack_data[i] as u32) << (i * 8);
                }

                // Process each bit in the bitmask
                for i in 0..32 {
                    if (current_bitmask & (1 << i)) != 0 {
                        let selectively_acked_seq = sack_base_seq.wrapping_add(i as u16);
                        if let Some(info) = unacked_packets.remove(&selectively_acked_seq) {
                            if info.verify_integrity() {
                                newly_acked_bytes += info.size_bytes;
                            }
                        }
                    }
                }
            }
        }

        // Fast retransmit detection
        let last_acked = self.get_last_acked_seq_for_dup_ack();
        if ack_nr == last_acked && !unacked_packets.is_empty() {
            let count = self.duplicate_ack_count.fetch_add(1, Ordering::Relaxed) + 1;

            if count >= DUPLICATE_ACKS_BEFORE_RESEND {
                let next_seq_to_retransmit = ack_nr.wrapping_add(1);
                if let Some(pkt_info) = unacked_packets.get_mut(&next_seq_to_retransmit) {
                    if pkt_info.transmissions < MAX_RETRANSMISSIONS && !pkt_info.need_resend {
                        pkt_info.need_resend = true;
                        self.duplicate_ack_count.store(0, Ordering::Relaxed);
                        self.seq_to_retransmit = Some(next_seq_to_retransmit);
                    }
                }
            }
        } else {
            self.duplicate_ack_count.store(0, Ordering::Relaxed);
            self.set_last_acked_seq_for_dup_ack(ack_nr);
        }

        newly_acked_bytes
    }

    /// Calculate RTO with bounds checking
    fn calculate_rto(&self) -> u32 {
        let rto = self.rtt_estimator.get_rto_micros();
        min(max(rto, MIN_ALLOWED_RTO_MICROS), MAX_RTO_MICROS)
    }

    /// Check for packets that have timed out and need retransmission
    pub fn check_timeouts(&mut self, current_ts_micros: u64) -> Option<u16> {
        // If we already have a packet to retransmit from fast retransmit
        if let Some(seq) = self.seq_to_retransmit.take() {
            return Some(seq);
        }

        // In a real implementation, we would check if any unacked packets
        // have timed out, but those are managed by the socket layer

        // Update timeout check timestamp
        self.last_timeout_check_micros = current_ts_micros;

        None
    }

    /// Set a packet for retransmission (primarily used for testing)
    pub fn set_needs_retransmit(&mut self, seq_nr: u16) {
        self.seq_to_retransmit = Some(seq_nr);
    }

    /// Buffer an out-of-order packet for SACK
    pub fn buffer_ooo_packet(&mut self, packet: &UtpPacket) {
        // Limit the number of out-of-order packets we track
        if self.received_ooo_seqs.len() >= MAX_OOO_PACKETS {
            // If we're at capacity, remove the oldest packet (lowest seq number)
            if let Some(&first) = self.received_ooo_seqs.iter().next() {
                self.received_ooo_seqs.remove(&first);
            }
        }

        self.received_ooo_seqs.insert(packet.header.seq_nr());
    }

    /// Get SACK data for inclusion in outgoing packets
    pub fn get_sack_data(&self, current_ack_nr: u16) -> Option<Vec<u8>> {
        if self.received_ooo_seqs.is_empty() {
            return None;
        }

        let sack_base_seq = current_ack_nr.wrapping_add(2);
        let mut sack_bits: u32 = 0;

        // Create bitmask for SACK
        for &seq_nr in &self.received_ooo_seqs {
            if seq_eq_or_greater_than(seq_nr, sack_base_seq) {
                let diff = seq_nr.wrapping_sub(sack_base_seq);
                if diff < 32 {
                    sack_bits |= 1 << diff;
                }
            }
        }

        if sack_bits > 0 {
            Some(sack_bits.to_be_bytes().to_vec())
        } else {
            None
        }
    }

    /// Update the cumulative ACK number based on received out-of-order packets
    pub fn update_cumulative_ack(&mut self, mut current_ack_nr: u16) -> u16 {
        // Check if we can advance the cumulative ack with out-of-order packets
        while self.received_ooo_seqs.remove(&current_ack_nr.wrapping_add(1)) {
            current_ack_nr = current_ack_nr.wrapping_add(1);
        }

        // Update all copies with triple redundancy
        self.set_cumulative_ack_nr(current_ack_nr);
        current_ack_nr
    }

    /// Get latest smoothed RTT estimate in microseconds
    pub fn get_latest_rtt_micros(&self) -> u32 {
        self.rtt_estimator.srtt_micros
    }

    /// Get minimum observed RTT in microseconds
    pub fn get_min_rtt_micros(&self) -> u32 {
        self.rtt_estimator.min_rtt_micros
    }

    /// Get current retransmission timeout in microseconds
    pub fn get_current_rto(&self) -> u32 {
        self.current_rto
    }

    /// Mark that an ACK needs to be sent
    pub fn set_needs_ack(&mut self) {
        self.needs_ack = true;
    }

    /// Check if an ACK packet needs to be sent
    pub fn needs_ack_packet(&self) -> bool {
        self.needs_ack
    }

    /// Notify that an ACK has been sent
    pub fn ack_sent(&mut self) {
        self.needs_ack = false;
    }

    /// Clear out-of-order packet buffer (for testing)
    pub fn clear_ooo_packets(&mut self) {
        self.received_ooo_seqs.clear();
    }

    /// Verify data structure integrity (radiation hardening)
    pub fn verify_state_integrity(&self) -> bool {
        // Check triple redundancy consistency
        let ack1 = self.cumulative_ack_nr[0].load(Ordering::Relaxed);
        let ack2 = self.cumulative_ack_nr[1].load(Ordering::Relaxed);
        let ack3 = self.cumulative_ack_nr[2].load(Ordering::Relaxed);

        let last1 = self.last_acked_seq_for_dup_ack[0].load(Ordering::Relaxed);
        let last2 = self.last_acked_seq_for_dup_ack[1].load(Ordering::Relaxed);
        let last3 = self.last_acked_seq_for_dup_ack[2].load(Ordering::Relaxed);

        // At least 2 values must match in each set
        (ack1 == ack2 || ack2 == ack3 || ack1 == ack3) &&
            (last1 == last2 || last2 == last3 || last1 == last3)
    }

    /// Repair triple modular redundancy if values differ
    pub fn repair_tmr(&mut self) {
        // Repair cumulative_ack_nr
        let ack = self.get_cumulative_ack_nr();
        self.set_cumulative_ack_nr(ack);

        // Repair last_acked_seq_for_dup_ack
        let last = self.get_last_acked_seq_for_dup_ack();
        self.set_last_acked_seq_for_dup_ack(last);
    }
}

/// RTT estimation following RFC 6298 algorithm
struct RttEstimator {
    /// Smoothed round-trip time in microseconds
    srtt_micros: u32,
    /// Round-trip time variation in microseconds
    rttvar_micros: u32,
    /// Minimum observed RTT in microseconds
    min_rtt_micros: u32,
    /// Whether this is the first RTT sample
    first_sample: bool,
}

impl RttEstimator {
    /// Create a new RTT estimator with default values
    fn new() -> Self {
        Self {
            srtt_micros: 0,
            rttvar_micros: 0,
            min_rtt_micros: u32::MAX,
            first_sample: true,
        }
    }

    /// Update RTT estimates with a new sample
    fn update_rtt(&mut self, rtt_sample_micros: u32) {
        if self.first_sample {
            self.srtt_micros = rtt_sample_micros;
            self.rttvar_micros = rtt_sample_micros / 2;
            self.first_sample = false;
        } else {
            // RFC 6298 alpha and beta values
            const ALPHA: f32 = 1.0 / 8.0;
            const BETA: f32 = 1.0 / 4.0;

            // Calculate RTT variation
            let delta = (self.srtt_micros as i64 - rtt_sample_micros as i64).abs() as u32;
            self.rttvar_micros = ((1.0 - BETA) * self.rttvar_micros as f32 + BETA * delta as f32) as u32;

            // Update smoothed RTT
            self.srtt_micros = ((1.0 - ALPHA) * self.srtt_micros as f32 + ALPHA * rtt_sample_micros as f32) as u32;
        }

        // Update minimum RTT
        if rtt_sample_micros < self.min_rtt_micros {
            self.min_rtt_micros = rtt_sample_micros;
        }
    }

    /// Calculate RTO based on RTT estimates (per RFC 6298)
    fn get_rto_micros(&self) -> u32 {
        if self.first_sample {
            return INITIAL_RTO_MICROS;
        }

        // K = 4 as recommended in RFC 6298
        self.srtt_micros + 4 * self.rttvar_micros
    }
}

/// For testing purposes
#[allow(dead_code)]
fn dummy_socket_addr() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utp::packet::UtpHeader;
    use crate::utp::common::{ST_DATA, ST_STATE};

    fn create_test_packet(seq_nr: u16, ack_nr: u16, packet_type: u8) -> UtpPacket {
        let header = UtpHeader::new(
            packet_type,
            12345,
            0,
            0,
            1000,
            seq_nr,
            ack_nr,
            0
        );

        UtpPacket {
            header,
            payload: Vec::new(),
            sack_data: None,
            remote_addr: dummy_socket_addr(),
        }
    }

    fn create_test_packet_with_payload(seq_nr: u16, ack_nr: u16, payload: &[u8]) -> UtpPacket {
        let header = UtpHeader::new(
            ST_DATA,
            12345,
            0,
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
            remote_addr: dummy_socket_addr(),
        }
    }

    #[test]
    fn test_rtt_estimation_first_sample() {
        let mut rm = ReliabilityManager::new();
        let mut unacked_packets = HashMap::new();

        // Send and acknowledge a packet
        let packet = create_test_packet(1, 0, ST_DATA);
        let send_time = 1_000_000; // 1 second
        rm.on_packet_sent(&packet, send_time, &mut unacked_packets);

        // Process ACK 10ms later
        let ack_time = 1_010_000; // 1.01 seconds
        rm.process_ack(1, None, &mut unacked_packets, ack_time);

        // RTT should be 10ms = 10,000 microseconds
        assert_eq!(rm.get_latest_rtt_micros(), 10_000);
        assert_eq!(rm.get_min_rtt_micros(), 10_000);

        // RTO should be srtt + 4*rttvar = 10,000 + 4*(10,000/2) = 30,000
        // But also subject to minimum limits
        assert_eq!(rm.get_current_rto(), 300_000); // MIN_ALLOWED_RTO_MICROS
    }

    #[test]
    fn test_rtt_estimation_multiple_samples() {
        let mut rm = ReliabilityManager::new();
        let mut unacked_packets = HashMap::new();

        // First packet - 10ms RTT
        let packet1 = create_test_packet(1, 0, ST_DATA);
        rm.on_packet_sent(&packet1, 1_000_000, &mut unacked_packets);
        rm.process_ack(1, None, &mut unacked_packets, 1_010_000);

        // Second packet - 20ms RTT
        let packet2 = create_test_packet(2, 0, ST_DATA);
        rm.on_packet_sent(&packet2, 2_000_000, &mut unacked_packets);
        rm.process_ack(2, None, &mut unacked_packets, 2_020_000);

        // Using ALPHA=1/8, SRTT = (7/8)*10,000 + (1/8)*20,000 = 8,750 + 2,500 = 11,250
        // Using BETA=1/4, RTTVAR = (3/4)*5,000 + (1/4)*10,000 = 3,750 + 2,500 = 6,250
        // RTO = 11,250 + 4*6,250 = 36,250
        // But with MIN_ALLOWED_RTO_MICROS = 300,000
        assert_eq!(rm.get_current_rto(), 300_000);

        // Min RTT should be 10,000
        assert_eq!(rm.get_min_rtt_micros(), 10_000);
    }

    #[test]
    fn test_cumulative_ack_processing() {
        let mut rm = ReliabilityManager::new();
        let mut unacked_packets = HashMap::new();
        let now = 1_000_000;

        // Send 5 packets
        for seq in 1..=5 {
            let packet = create_test_packet(seq, 0, ST_DATA);
            rm.on_packet_sent(&packet, now, &mut unacked_packets);
        }

        // All 5 packets should be in unacked_packets
        assert_eq!(unacked_packets.len(), 5);

        // Process ACK for packet 3, should remove packets 1-3
        let acked = rm.process_ack(3, None, &mut unacked_packets, now + 10_000);

        // Check that packets 1-3 are removed
        assert_eq!(unacked_packets.len(), 2);
        assert!(!unacked_packets.contains_key(&1));
        assert!(!unacked_packets.contains_key(&2));
        assert!(!unacked_packets.contains_key(&3));
        assert!(unacked_packets.contains_key(&4));
        assert!(unacked_packets.contains_key(&5));

        // Bytes acknowledged should be the sum of sizes for packets 1-3
        assert!(acked > 0);
    }

    #[test]
    fn test_selective_ack_processing() {
        let mut rm = ReliabilityManager::new();
        let mut unacked_packets = HashMap::new();
        let now = 1_000_000;

        // Send 10 packets of 100 bytes each
        for seq in 1..=10 {
            let packet = create_test_packet_with_payload(seq, 0, &[0; 100]);
            rm.on_packet_sent(&packet, now, &mut unacked_packets);
        }

        // Create SACK data for packets 5, 7, 9
        // For ack_nr=3, SACK base is 5 (ack_nr+2), so:
        // Bit 0 = seq 5, bit 2 = seq 7, bit 4 = seq 9
        let mut sack_data = [0u8; 4]; // 32 bits
        sack_data[0] |= 1 << 0; // seq 5
        sack_data[0] |= 1 << 2; // seq 7
        sack_data[0] |= 1 << 4; // seq 9

        // Process ACK for packet 3 with SACK data
        let acked_bytes = rm.process_ack(3, Some(&sack_data), &mut unacked_packets, now + 10_000);

        // Should acknowledge packets 1-3 (cumulative) and 5,7,9 (selective)
        // Each packet includes both payload (100 bytes) and header (~20 bytes)
        // Total: 6 packets × ~120 bytes = 720 bytes
        assert_eq!(acked_bytes, 720);

        // Verify which packets are still unacked
        assert_eq!(unacked_packets.len(), 4); // Should be 4, 6, 8, 10
        for &seq in &[1, 2, 3, 5, 7, 9] {
            assert!(!unacked_packets.contains_key(&seq), "Packet {} should be acked", seq);
        }
        for &seq in &[4, 6, 8, 10] {
            assert!(unacked_packets.contains_key(&seq), "Packet {} should not be acked", seq);
        }
    }

    #[test]
    fn test_fast_retransmit() {
        let mut rm = ReliabilityManager::new();
        let mut unacked_packets = HashMap::new();
        let now = 1_000_000;

        // Send 5 packets
        for seq in 1..=5 {
            let packet = create_test_packet(seq, 0, ST_DATA);
            rm.on_packet_sent(&packet, now, &mut unacked_packets);
        }

        // First ACK for seq 1
        rm.process_ack(1, None, &mut unacked_packets, now + 10_000);

        // Packet 2 is lost, receiver continues to ACK packet 1
        for _ in 0..DUPLICATE_ACKS_BEFORE_RESEND {
            rm.process_ack(1, None, &mut unacked_packets, now + 20_000);
        }

        // Check if packet 2 is marked for retransmission
        assert!(unacked_packets.get(&2).unwrap().need_resend);

        // Check that the sequence to retransmit is set
        assert_eq!(rm.seq_to_retransmit, Some(2));

        // Check that checking timeouts returns the sequence to retransmit
        assert_eq!(rm.check_timeouts(now + 30_000), Some(2));

        // Should be cleared after checking
        assert_eq!(rm.seq_to_retransmit, None);
    }

    #[test]
    fn test_ooo_packet_buffering() {
        let mut rm = ReliabilityManager::new();

        // Buffer some out-of-order packets
        rm.buffer_ooo_packet(&create_test_packet(5, 0, ST_DATA));
        rm.buffer_ooo_packet(&create_test_packet(7, 0, ST_DATA));
        rm.buffer_ooo_packet(&create_test_packet(10, 0, ST_DATA));

        // Check that we have SACK data
        let sack_data = rm.get_sack_data(3);
        assert!(sack_data.is_some());

        // Decode SACK data
        let sack_bits = u32::from_be_bytes([
            sack_data.as_ref().unwrap()[0],
            sack_data.as_ref().unwrap()[1],
            sack_data.as_ref().unwrap()[2],
            sack_data.as_ref().unwrap()[3],
        ]);

        // Base is 5 (3 + 2)
        assert_eq!(sack_bits & (1 << 0), 1 << 0); // seq 5 (base + 0)
        assert_eq!(sack_bits & (1 << 2), 1 << 2); // seq 7 (base + 2)
        assert_eq!(sack_bits & (1 << 5), 1 << 5); // seq 10 (base + 5)
    }

    #[test]
    fn test_cumulative_ack_advancement() {
        let mut rm = ReliabilityManager::new();

        // Assume we've received ACK for sequence 5
        rm.set_cumulative_ack_nr(5);

        // Buffer out-of-order packets 7, 8, and 10
        rm.buffer_ooo_packet(&create_test_packet(7, 0, ST_DATA));
        rm.buffer_ooo_packet(&create_test_packet(8, 0, ST_DATA));
        rm.buffer_ooo_packet(&create_test_packet(10, 0, ST_DATA));

        // Now receive packet 6 in order
        let new_ack = rm.update_cumulative_ack(6);

        // Should advance cumulative ACK to 8 (including packets 7 and 8)
        assert_eq!(new_ack, 8);
        assert_eq!(rm.get_cumulative_ack_nr(), 8);

        // Only packet 10 should remain in the buffer
        assert_eq!(rm.received_ooo_seqs.len(), 1);
        assert!(rm.received_ooo_seqs.contains(&10));
    }

    #[test]
    fn test_retransmission_tracking() {
        let mut rm = ReliabilityManager::new();
        let mut unacked_packets = HashMap::new();
        let now = 1_000_000;

        // Send a packet
        let packet = create_test_packet(1, 0, ST_DATA);
        rm.on_packet_sent(&packet, now, &mut unacked_packets);

        // Retransmit the same packet
        rm.on_packet_sent(&packet, now + 500_000, &mut unacked_packets);

        // Check that the transmissions count was incremented
        assert_eq!(unacked_packets.get(&1).unwrap().transmissions, 2);

        // Process ACK and check RTT isn't updated from retransmitted packet
        let initial_rto = rm.get_current_rto();
        rm.process_ack(1, None, &mut unacked_packets, now + 600_000);

        // RTO should remain unchanged since we don't update for retransmits
        assert_eq!(rm.get_current_rto(), initial_rto);
    }

    #[test]
    fn test_ooo_buffer_limit() {
        let mut rm = ReliabilityManager::new();

        // Fill the buffer to capacity and beyond
        for seq in 1..=(MAX_OOO_PACKETS + 10) {
            rm.buffer_ooo_packet(&create_test_packet(seq as u16, 0, ST_DATA));
        }

        // Buffer should be limited to MAX_OOO_PACKETS
        assert_eq!(rm.received_ooo_seqs.len(), MAX_OOO_PACKETS);

        // Lower sequence numbers should have been dropped
        for seq in 1..=10 {
            assert!(!rm.received_ooo_seqs.contains(&(seq as u16)));
        }

        // Higher sequence numbers should be present
        for seq in (MAX_OOO_PACKETS + 1)..=(MAX_OOO_PACKETS + 10) {
            assert!(rm.received_ooo_seqs.contains(&(seq as u16)));
        }
    }

    #[test]
    fn test_radiation_hardening_triple_redundancy() {
        let mut rm = ReliabilityManager::new();

        // Set a value with triple redundancy
        rm.set_cumulative_ack_nr(42);
        assert_eq!(rm.get_cumulative_ack_nr(), 42);

        // Corrupt one copy
        rm.cumulative_ack_nr[0].store(99, Ordering::Relaxed);

        // Should still get the correct value from majority voting
        assert_eq!(rm.get_cumulative_ack_nr(), 42);

        // Verify integrity check works
        assert!(rm.verify_state_integrity());

        // Corrupt a second copy differently
        rm.cumulative_ack_nr[1].store(77, Ordering::Relaxed);

        // Should get the third value when all differ
        assert_eq!(rm.get_cumulative_ack_nr(), 42);

        // Repair the corrupted values
        rm.repair_tmr();

        // All values should be consistent again
        assert_eq!(rm.cumulative_ack_nr[0].load(Ordering::Relaxed), 42);
        assert_eq!(rm.cumulative_ack_nr[1].load(Ordering::Relaxed), 42);
        assert_eq!(rm.cumulative_ack_nr[2].load(Ordering::Relaxed), 42);
    }

    #[test]
    fn test_packet_integrity_checking() {
        let mut rm = ReliabilityManager::new();
        let mut unacked_packets = HashMap::new();
        let now = 1_000_000;

        // Send a packet
        let packet = create_test_packet(1, 0, ST_DATA);
        rm.on_packet_sent(&packet, now, &mut unacked_packets);

        // Verify packet integrity
        assert!(unacked_packets.get(&1).unwrap().verify_integrity());

        // Corrupt packet data
        if let Some(info) = unacked_packets.get_mut(&1) {
            info.packet_data[5] ^= 0xFF; // Flip some bits

            // Integrity check should now fail
            assert!(!info.verify_integrity());
        }
    }
}
