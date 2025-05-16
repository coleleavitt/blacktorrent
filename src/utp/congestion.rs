// utp/congestion.rs

use crate::utp::common::{current_micros, DEFAULT_TARGET_DELAY_MICROS, MAX_CWND_INCREASE_BYTES_PER_RTT, MIN_WINDOW_SIZE_BYTES, DEFAULT_MAX_PACKET_SIZE};
use std::collections::VecDeque;

const MAX_DELAY_SAMPLES: usize = 5; // Number of recent delay samples to consider

pub struct CongestionControl {
    max_window_bytes: usize,    // Current congestion window (cwnd) in bytes
    target_delay_micros: u32,
    bytes_in_flight: usize,     // Number of bytes sent but not yet ACKed

    // For LEDBAT delay measurement (simplified)
    // (timestamp_sent_micros, packet_size_bytes)
    // More advanced: store (our_timestamp, their_timestamp_echo, rtt_of_packet)
    delay_samples: VecDeque<u32>, // Queuing delay samples in micros
    base_delay_micros: Option<u32>, // Minimum observed one-way delay (or RTT component)

    receive_window_bytes: usize, // Our advertised receive window
}

impl CongestionControl {
    pub fn new() -> Self {
        Self {
            max_window_bytes: DEFAULT_MAX_PACKET_SIZE * 2, // Initial window
            target_delay_micros: DEFAULT_TARGET_DELAY_MICROS,
            bytes_in_flight: 0,
            delay_samples: VecDeque::with_capacity(MAX_DELAY_SAMPLES),
            base_delay_micros: None,
            receive_window_bytes: 1024 * 1024, // Default large receive window
        }
    }

    pub fn get_receive_window_size(&self) -> usize {
        self.receive_window_bytes // This is what we advertise
    }

    pub fn get_congestion_window_size(&self) -> usize {
        self.max_window_bytes
    }

    pub fn bytes_in_flight(&self) -> usize {
        self.bytes_in_flight
    }

    pub fn can_send(&self, packet_size: usize) -> bool {
        self.bytes_in_flight + packet_size <= self.max_window_bytes
    }

    pub fn on_packet_sent(&mut self, packet_size_bytes: usize) {
        self.bytes_in_flight += packet_size_bytes;
    }

    /// Called when an ACK is received.
    /// `bytes_acked`: Number of bytes this ACK covers.
    /// `rtt_micros`: RTT for the ACKed packet(s).
    /// `one_way_delay_micros_sample`: Estimated one-way queuing delay.
    pub fn on_ack_received(&mut self, bytes_acked: usize, rtt_micros: u32, current_min_rtt_micros: u32) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(bytes_acked);

        // Update base delay (one-way path delay + processing, ideally)
        // In uTP, this is tricky. Often, the "our_delay" (remote queuing delay) is used.
        // The difference (timestamp_micros - timestamp_diff_micros) from the ACK gives an RTT component.
        // (current_time - their_timestamp) - (our_timestamp_echoed_by_them - their_original_timestamp_of_our_packet)
        // For simplicity, we'll use the RTT and assume symmetric path for base delay.
        // True uTP uses the echoed timestamp_diff to calculate one-way delays.
        // `actual_delay` in libutp's apply_ccontrol is `pf1->reply_micro`.
        let queuing_delay_sample = rtt_micros.saturating_sub(current_min_rtt_micros);

        if self.delay_samples.len() == MAX_DELAY_SAMPLES {
            self.delay_samples.pop_front();
        }
        self.delay_samples.push_back(queuing_delay_sample);

        // Get current queuing delay (e.g., min of recent samples)
        let current_queuing_delay = self.delay_samples.iter().min().copied().unwrap_or(queuing_delay_sample);

        let off_target = self.target_delay_micros as f64 - current_queuing_delay as f64;
        let window_factor = bytes_acked as f64 / self.max_window_bytes.max(1) as f64; // Fraction of window this ACK represents
        let delay_factor = off_target / self.target_delay_micros.max(1) as f64;

        let gain = MAX_CWND_INCREASE_BYTES_PER_RTT as f64 * window_factor * delay_factor;

        let new_max_window = self.max_window_bytes as f64 + gain;
        self.max_window_bytes = (new_max_window.round() as usize).max(MIN_WINDOW_SIZE_BYTES);

        // TODO: Implement slow start, max window limits based on sndbuf, etc.
    }

    pub fn on_timeout(&mut self) {
        // Reduce congestion window, e.g., halve it (TCP-like) or reset to min.
        // libutp sets max_window = packet_size and slow_start = true
        self.max_window_bytes = (self.max_window_bytes / 2).max(MIN_WINDOW_SIZE_BYTES);
        // TODO: Enter slow start if applicable
        println!("uTP CC: Timeout, cwnd reduced to {}", self.max_window_bytes);
    }
}
