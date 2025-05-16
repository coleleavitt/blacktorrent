// utp/reliability.rs

use crate::utp::common::{INITIAL_RTO_MICROS, MIN_RTO_MICROS, ST_SYN, seq_eq_or_greater_than};
use crate::utp::packet::UtpPacket;
use std::net::{SocketAddr, IpAddr, Ipv4Addr};
use std::collections::{HashMap, BTreeSet};

// Number of duplicate ACKs required before triggering fast retransmission
const DUPLICATE_ACKS_BEFORE_RESEND: u32 = 3;
// Maximum number of retransmissions before giving up
const MAX_RETRANSMISSIONS: u32 = 5;

#[derive(Debug, Clone)]
pub struct SentPacketInfo {
    pub seq_nr: u16,
    pub sent_at_micros: u64,
    pub size_bytes: usize,
    pub transmissions: u32,
    pub packet_data: Vec<u8>,
    pub is_syn: bool,
    pub need_resend: bool,
}

/// Manages packet reliability including RTT estimation, retransmissions, 
/// and selective acknowledgments
pub struct ReliabilityManager {
    // RTT estimator - handles smoothed RTT and variance calculations
    rtt_estimator: RttEstimator,
    // Current retransmission timeout in microseconds
    rto_micros: u32,
    // Set of out-of-order sequence numbers received
    received_ooo_seqs: BTreeSet<u16>,
    // The latest in-order packet we've acknowledged
    cumulative_ack_nr: u16,
    // Count of duplicate ACKs received for fast retransmit detection
    duplicate_ack_count: u32,
    // The sequence number for which we're counting duplicate ACKs
    last_acked_seq_for_dup_ack: u16,
    // Flag to indicate an ACK should be sent soon
    pub needs_ack: bool,
}

impl ReliabilityManager {
    /// Creates a new reliability manager with default values
    pub fn new() -> Self {
        Self {
            rtt_estimator: RttEstimator::new(),
            rto_micros: INITIAL_RTO_MICROS,
            received_ooo_seqs: BTreeSet::new(),
            cumulative_ack_nr: 0,
            duplicate_ack_count: 0,
            last_acked_seq_for_dup_ack: 0,
            needs_ack: false,
        }
    }

    /// Called when a packet is sent to track it for potential retransmission
    pub fn on_packet_sent(&mut self, packet: &UtpPacket, sent_at_micros: u64, unacked_packets: &mut HashMap<u16, SentPacketInfo>) {
        let seq_nr = packet.header.seq_nr();
        let mut raw_data = Vec::new();
        packet.serialize(&mut raw_data);

        let info = SentPacketInfo {
            seq_nr,
            sent_at_micros,
            size_bytes: raw_data.len(),
            transmissions: 1,
            packet_data: raw_data,
            is_syn: packet.header.packet_type() == ST_SYN,
            need_resend: false,
        };
        unacked_packets.insert(seq_nr, info);
    }

    /// Process an acknowledgement number and optional selective ACK (SACK) data
    /// Returns the number of newly acknowledged bytes
    pub fn process_ack(
        &mut self,
        ack_nr: u16,
        sack_data: Option<&[u8]>,
        unacked_packets: &mut HashMap<u16, SentPacketInfo>,
        current_ts_micros: u64,
    ) -> usize {
        let mut newly_acked_bytes = 0;
        let mut to_remove = Vec::new();

        // Process cumulative ACK - all packets up to and including ack_nr
        for (seq, info) in unacked_packets.iter() {
            if seq_eq_or_greater_than(ack_nr, *seq) {
                to_remove.push(*seq);
                newly_acked_bytes += info.size_bytes;

                // Only update RTT for non-retransmitted packets to avoid ambiguity
                if info.transmissions == 1 {
                    let rtt_sample = current_ts_micros.saturating_sub(info.sent_at_micros) as u32;
                    self.rtt_estimator.update_rtt(rtt_sample);
                    self.rto_micros = self.rtt_estimator.get_rto_micros().max(MIN_RTO_MICROS);
                }
            }
        }

        // Remove acknowledged packets
        for seq in to_remove {
            unacked_packets.remove(&seq);
        }

        // Process SACK data (selective acknowledgment)
        if let Some(sack_data) = sack_data {
            if sack_data.len() >= 4 {
                let sack_base_seq = ack_nr.wrapping_add(2);
                let mut sack_bits = 0u32;

                // Read up to 4 bytes of SACK data into a u32
                for i in 0..std::cmp::min(4, sack_data.len()) {
                    sack_bits |= (sack_data[i] as u32) << (i * 8);
                }

                // Process each bit in the SACK mask
                for i in 0..32 {
                    if (sack_bits & (1 << i)) != 0 {
                        let selectively_acked_seq = sack_base_seq.wrapping_add(i as u16);
                        if let Some(info) = unacked_packets.remove(&selectively_acked_seq) {
                            newly_acked_bytes += info.size_bytes;
                            // Note: For SACK'd packets, we don't update RTT to avoid ambiguity
                        }
                    }
                }
            }
        }

        // Fast retransmit detection - count duplicate ACKs
        if ack_nr == self.last_acked_seq_for_dup_ack {
            // Only count if there are still unacked packets
            if !unacked_packets.is_empty() {
                self.duplicate_ack_count += 1;

                // After DUPLICATE_ACKS_BEFORE_RESEND duplicate ACKs, mark for fast retransmit
                if self.duplicate_ack_count >= DUPLICATE_ACKS_BEFORE_RESEND {
                    let next_seq = ack_nr.wrapping_add(1);
                    if let Some(pkt_info) = unacked_packets.get_mut(&next_seq) {
                        if pkt_info.transmissions < MAX_RETRANSMISSIONS {
                            // Mark for fast retransmission
                            pkt_info.need_resend = true;
                            println!("uTP RM: Fast retransmit marked for {}", pkt_info.seq_nr);
                            // Reset counter to avoid multiple fast retransmits for the same packet
                            self.duplicate_ack_count = 0;
                        }
                    }
                }
            }
        } else {
            // Different ACK number, reset duplicate counter
            self.duplicate_ack_count = 0;
            self.last_acked_seq_for_dup_ack = ack_nr;
        }

        newly_acked_bytes
    }

    /// Check for timeouts and determine if retransmission is needed
    pub fn check_timeouts(&mut self, current_ts_micros: u64, _current_send_seq_nr: u16, unacked_packets: &mut HashMap<u16, SentPacketInfo>) -> Option<UtpPacket> {
        if unacked_packets.is_empty() {
            return None;
        }

        // Find the oldest unacknowledged packet
        let mut oldest_unacked_seq: Option<u16> = None;
        let mut oldest_sent_time: u64 = u64::MAX;

        for (seq_nr, info) in unacked_packets.iter() {
            if info.sent_at_micros < oldest_sent_time {
                oldest_sent_time = info.sent_at_micros;
                oldest_unacked_seq = Some(*seq_nr);
            }

            // Also look for packets marked for fast retransmission
            if info.need_resend {
                if let Ok(packet) = UtpPacket::from_bytes(&info.packet_data, dummy_socket_addr()) {
                    let seq = info.seq_nr;
                    if let Some(info) = unacked_packets.get_mut(&seq) {
                        info.transmissions += 1;
                        info.sent_at_micros = current_ts_micros;
                        info.need_resend = false;
                        return Some(packet);
                    }
                }
            }
        }

        // Process timeout for oldest packet
        if let Some(old_seq) = oldest_unacked_seq {
            if let Some(info) = unacked_packets.get_mut(&old_seq) {
                // Calculate timeout - SYN packets use a longer timeout
                let timeout_duration = if info.is_syn {
                    self.rto_micros.saturating_mul(2)
                } else {
                    self.rto_micros
                };

                // Check if packet has timed out
                if current_ts_micros.saturating_sub(info.sent_at_micros) > timeout_duration as u64 {
                    if info.transmissions < MAX_RETRANSMISSIONS {
                        println!("uTP RM: Timeout for seq_nr {}, retransmitting ({}th time)",
                                 info.seq_nr, info.transmissions + 1);

                        // Update retransmission count and timestamp
                        info.transmissions += 1;
                        info.sent_at_micros = current_ts_micros;

                        // Exponential backoff for RTO
                        self.rto_micros = (self.rto_micros.saturating_mul(2)).max(MIN_RTO_MICROS);

                        // Recreate the packet for retransmission
                        if let Ok(packet) = UtpPacket::from_bytes(&info.packet_data, dummy_socket_addr()) {
                            return Some(packet);
                        }
                    } else {
                        // Too many retransmissions, give up on this packet
                        println!("uTP RM: Too many retransmissions for seq_nr {}, giving up.", info.seq_nr);
                    }
                }
            }
        }

        None
    }

    /// Buffer out-of-order packet for later processing
    pub fn buffer_ooo_packet(&mut self, packet: &UtpPacket) {
        self.received_ooo_seqs.insert(packet.header.seq_nr());
    }

    /// Generate SACK data for the current out-of-order packets
    pub fn get_sack_data(&self, current_ack_nr: u16) -> Option<Vec<u8>> {
        if self.received_ooo_seqs.is_empty() {
            return None;
        }

        // SACK base is ack_nr + 2 (uTP protocol convention)
        let sack_base_seq = current_ack_nr.wrapping_add(2);
        let mut sack_bits: u32 = 0;

        // Create bitmap of received OOO packets relative to base sequence
        for &seq_nr in self.received_ooo_seqs.range(sack_base_seq..) {
            let diff = seq_nr.wrapping_sub(sack_base_seq);
            if diff < 32 { // Max 32 bits in our SACK bitmap
                sack_bits |= 1 << diff;
            } else {
                break; // Beyond what we can represent in a single SACK
            }
        }

        // Only send SACK if we have bits to report
        if sack_bits > 0 {
            Some(sack_bits.to_be_bytes().to_vec())
        } else {
            None
        }
    }

    /// Update the cumulative ACK number based on available data in reorder buffer
    pub fn update_cumulative_ack(&mut self, mut current_ack_nr: u16) -> u16 {
        // Continue incrementing ack_nr as long as we have the next packet
        while self.received_ooo_seqs.remove(&current_ack_nr.wrapping_add(1)) {
            current_ack_nr = current_ack_nr.wrapping_add(1);
        }
        self.cumulative_ack_nr = current_ack_nr;
        current_ack_nr
    }

    /// Returns the latest round-trip time estimate in microseconds
    pub fn get_latest_rtt_micros(&self) -> u32 {
        self.rtt_estimator.srtt_micros
    }

    /// Returns the minimum observed round-trip time in microseconds
    pub fn get_min_rtt_micros(&self) -> u32 {
        self.rtt_estimator.min_rtt_micros
    }

    /// Returns the current retransmission timeout in microseconds
    pub fn get_current_rto(&self) -> u32 {
        self.rto_micros
    }
}

/// RTT estimator using Jacobson/Karels algorithm (similar to TCP)
struct RttEstimator {
    // Smoothed round-trip time
    srtt_micros: u32,
    // Round-trip time variation
    rttvar_micros: u32,
    // Minimum RTT observed (used for congestion control)
    min_rtt_micros: u32,
    // Whether this is the first sample (initialization)
    first_sample: bool,
}

impl RttEstimator {
    /// Create a new RTT estimator
    fn new() -> Self {
        Self {
            srtt_micros: 0,
            rttvar_micros: 0,
            min_rtt_micros: u32::MAX,
            first_sample: true,
        }
    }

    /// Update the RTT estimates with a new sample
    fn update_rtt(&mut self, rtt_sample_micros: u32) {
        if self.first_sample {
            // Initialize with first sample
            self.srtt_micros = rtt_sample_micros;
            self.rttvar_micros = rtt_sample_micros / 2;
            self.first_sample = false;
        } else {
            // EWMA constants from TCP RFC
            const ALPHA: f32 = 1.0 / 8.0;  // 0.125 - SRTT weight
            const BETA: f32 = 1.0 / 4.0;   // 0.25 - RTTVAR weight

            // Calculate absolute difference for RTT variation
            let delta = (self.srtt_micros as i64 - rtt_sample_micros as i64).abs() as u32;

            // Update RTT variance: rttvar = (1-beta)*rttvar + beta*|srtt-sample|
            self.rttvar_micros = ((1.0 - BETA) * self.rttvar_micros as f32 + BETA * delta as f32) as u32;

            // Update smoothed RTT: srtt = (1-alpha)*srtt + alpha*sample
            self.srtt_micros = ((1.0 - ALPHA) * self.srtt_micros as f32 + ALPHA * rtt_sample_micros as f32) as u32;
        }

        // Update minimum RTT observed
        if rtt_sample_micros < self.min_rtt_micros {
            self.min_rtt_micros = rtt_sample_micros;
        }
    }

    /// Calculate retransmission timeout based on current estimates
    fn get_rto_micros(&self) -> u32 {
        // RTO = SRTT + max(G, 4*RTTVAR) where G is clock granularity
        // We use 4*RTTVAR without G, similar to standard TCP RTO calculation
        // Apply minimum RTO for safety
        (self.srtt_micros + 4 * self.rttvar_micros).max(MIN_RTO_MICROS)
    }
}

/// Create a dummy socket address for placeholder purposes
fn dummy_socket_addr() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
}
