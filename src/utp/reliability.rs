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
    pub current_rto: u32,
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
            current_rto: INITIAL_RTO_MICROS,
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
                to_remove.push(*seq);
                newly_acked_bytes += info.size_bytes;

                if info.transmissions == 1 {
                    let rtt_sample = current_ts_micros.saturating_sub(info.sent_at_micros) as u32;
                    self.rtt_estimator.update_rtt(rtt_sample);
                    self.current_rto = self.rtt_estimator.get_rto_micros().max(MIN_RTO_MICROS);
                }
            }
        }

        for seq in to_remove {
            unacked_packets.remove(&seq);
        }

        // Process SACK data
        if let Some(sack_data) = sack_data {
            if !sack_data.is_empty() {
                let sack_base_seq = ack_nr.wrapping_add(2);
                let mut current_bitmask: u32 = 0;

                for i in 0..std::cmp::min(4, sack_data.len()) {
                    current_bitmask |= (sack_data[i] as u32) << (i * 8);
                }

                for i in 0..32 {
                    if (current_bitmask & (1 << i)) != 0 {
                        let selectively_acked_seq = sack_base_seq.wrapping_add(i as u16);
                        if let Some(info) = unacked_packets.remove(&selectively_acked_seq) {
                            newly_acked_bytes += info.size_bytes;
                        }
                    }
                }
            }
        }

        // Fast retransmit detection
        if ack_nr == self.last_acked_seq_for_dup_ack && !unacked_packets.is_empty() {
            self.duplicate_ack_count += 1;

            if self.duplicate_ack_count >= DUPLICATE_ACKS_BEFORE_RESEND {
                let next_seq_to_retransmit = ack_nr.wrapping_add(1);
                if let Some(pkt_info) = unacked_packets.get_mut(&next_seq_to_retransmit) {
                    if pkt_info.transmissions < MAX_RETRANSMISSIONS && !pkt_info.need_resend {
                        pkt_info.need_resend = true;
                        self.duplicate_ack_count = 0;
                    }
                }
            }
        } else {
            self.duplicate_ack_count = 0;
            self.last_acked_seq_for_dup_ack = ack_nr;
        }

        newly_acked_bytes
    }

    pub fn check_timeouts(&mut self, _current_ts_micros: u64) -> Option<u16> {
        None
    }

    pub fn buffer_ooo_packet(&mut self, packet: &UtpPacket) {
        self.received_ooo_seqs.insert(packet.header.seq_nr());
    }

    pub fn get_sack_data(&self, current_ack_nr: u16) -> Option<Vec<u8>> {
        if self.received_ooo_seqs.is_empty() {
            return None;
        }

        let sack_base_seq = current_ack_nr.wrapping_add(2);
        let mut sack_bits: u32 = 0;

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

    pub fn update_cumulative_ack(&mut self, mut current_ack_nr: u16) -> u16 {
        while self.received_ooo_seqs.remove(&current_ack_nr.wrapping_add(1)) {
            current_ack_nr = current_ack_nr.wrapping_add(1);
        }
        self.cumulative_ack_nr = current_ack_nr;
        current_ack_nr
    }

    pub fn get_latest_rtt_micros(&self) -> u32 {
        self.rtt_estimator.srtt_micros
    }

    pub fn get_min_rtt_micros(&self) -> u32 {
        self.rtt_estimator.min_rtt_micros
    }

    pub fn get_current_rto(&self) -> u32 {
        self.current_rto
    }

    pub fn set_needs_ack(&mut self) {
        self.needs_ack = true;
    }

    pub fn needs_ack_packet(&self) -> bool {
        self.needs_ack
    }

    pub fn ack_sent(&mut self) {
        self.needs_ack = false;
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
        Self {
            srtt_micros: 0,
            rttvar_micros: 0,
            min_rtt_micros: u32::MAX,
            first_sample: true,
        }
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

        if rtt_sample_micros < self.min_rtt_micros {
            self.min_rtt_micros = rtt_sample_micros;
        }
    }

    fn get_rto_micros(&self) -> u32 {
        (self.srtt_micros + 4 * self.rttvar_micros).max(MIN_RTO_MICROS)
    }
}

#[allow(dead_code)]
fn dummy_socket_addr() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
}