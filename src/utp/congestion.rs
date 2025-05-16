// utp/congestion.rs

#![forbid(unsafe_code)]

use crate::utp::common::{
    current_micros, clamp, DEFAULT_TARGET_DELAY_MICROS,
    MAX_CWND_INCREASE_BYTES_PER_RTT, MIN_WINDOW_SIZE_BYTES, DEFAULT_MAX_PACKET_SIZE
};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::cmp::{min, max};

/// Maximum number of delay samples to consider for base delay calculation
const MAX_DELAY_SAMPLES: usize = 5;

/// Number of minutes after which we reset base delay measurements
/// LEDBAT suggests this to handle potential clock drift and route changes
const BASE_DELAY_RESET_MINUTES: u64 = 10;

/// Maximum congestion window size (4MB)
const MAX_CWND_BYTES: usize = 4 * 1024 * 1024;

/// Slow start threshold in bytes (default: 64KB)
const INITIAL_SSTHRESH_BYTES: usize = 64 * 1024;

/// LEDBAT gain factor as defined in RFC 6817
/// Controls how aggressively we respond to delay changes (default: 1)
const GAIN_FACTOR: f64 = 1.0;

/// Radiation-hardened congestion control implementation based on LEDBAT
/// (Low Extra Delay Background Transport) as specified in RFC 6817
pub struct CongestionControl {
    /// Current congestion window size in bytes (protected with triple redundancy)
    cwnd_bytes: [AtomicUsize; 3],

    /// Slow start threshold in bytes
    ssthresh_bytes: AtomicUsize,

    /// Flag indicating if we're in slow start phase
    in_slow_start: bool,

    /// Target one-way delay in microseconds (100ms by default)
    target_delay_micros: u32,

    /// Bytes currently in flight (sent but not acknowledged)
    bytes_in_flight: AtomicUsize,

    /// Queue of recent delay measurement samples in microseconds
    delay_samples: VecDeque<u32>,

    /// Base delay estimate (minimum observed one-way delay)
    base_delay_micros: u32,

    /// Last time the base delay was updated (for periodic resets)
    last_base_delay_update_time: u64,

    /// Current estimate of minimum RTT in microseconds
    current_min_rtt: u32,

    /// Our advertised receive window in bytes
    receive_window_bytes: usize,

    /// Packet loss count during current measurement period
    loss_count: usize,

    /// Last time window size was validated against actual usage
    last_window_validation_time: u64,

    /// Maximum observed sending rate in bytes per RTT
    max_bytes_per_rtt: usize,
}

impl CongestionControl {
    /// Creates a new congestion controller with default settings
    pub fn new() -> Self {
        let initial_window = DEFAULT_MAX_PACKET_SIZE * 2;

        Self {
            cwnd_bytes: [
                AtomicUsize::new(initial_window),
                AtomicUsize::new(initial_window),
                AtomicUsize::new(initial_window),
            ],
            ssthresh_bytes: AtomicUsize::new(INITIAL_SSTHRESH_BYTES),
            in_slow_start: true,
            target_delay_micros: DEFAULT_TARGET_DELAY_MICROS,
            bytes_in_flight: AtomicUsize::new(0),
            delay_samples: VecDeque::with_capacity(MAX_DELAY_SAMPLES),
            base_delay_micros: u32::MAX,
            last_base_delay_update_time: current_micros(),
            current_min_rtt: u32::MAX,
            receive_window_bytes: 1024 * 1024, // 1MB default receive window
            loss_count: 0,
            last_window_validation_time: current_micros(),
            max_bytes_per_rtt: 0,
        }
    }

    /// Returns current receive window size in bytes
    pub fn get_receive_window_size(&self) -> usize {
        self.receive_window_bytes
    }

    /// Returns current congestion window size in bytes using majority voting
    pub fn get_congestion_window_size(&self) -> usize {
        // Triple redundancy with majority voting for radiation hardening
        let cwnd0 = self.cwnd_bytes[0].load(Ordering::Relaxed);
        let cwnd1 = self.cwnd_bytes[1].load(Ordering::Relaxed);
        let cwnd2 = self.cwnd_bytes[2].load(Ordering::Relaxed);

        // Majority voting
        if cwnd0 == cwnd1 || cwnd0 == cwnd2 {
            cwnd0
        } else if cwnd1 == cwnd2 {
            cwnd1
        } else {
            // All values differ - take the median
            let mut values = [cwnd0, cwnd1, cwnd2];
            values.sort();
            values[1]
        }
    }

    /// Returns current bytes in flight (sent but not acknowledged)
    pub fn bytes_in_flight(&self) -> usize {
        self.bytes_in_flight.load(Ordering::Relaxed)
    }

    /// Checks if we can send a packet of the given size
    pub fn can_send(&self, packet_size: usize) -> bool {
        let in_flight = self.bytes_in_flight();
        let cwnd = self.get_congestion_window_size();

        in_flight + packet_size <= cwnd
    }

    /// Updates bytes in flight when a packet is sent
    pub fn on_packet_sent(&mut self, packet_size_bytes: usize) {
        let current = self.bytes_in_flight.load(Ordering::Relaxed);
        self.bytes_in_flight.store(current + packet_size_bytes, Ordering::Relaxed);

        // Track maximum usage for window validation
        self.max_bytes_per_rtt = max(self.max_bytes_per_rtt, self.bytes_in_flight());
    }

    /// Updates congestion window when an ACK is received
    ///
    /// # Arguments
    ///
    /// * `bytes_acked` - Number of bytes acknowledged by this ACK
    /// * `rtt_micros` - Round-trip time in microseconds for this ACK
    /// * `current_min_rtt_micros` - Current minimum RTT observed
    /// * `timestamp_micros` - Current timestamp from packet
    /// * `timestamp_diff_micros` - Timestamp difference from packet (one-way delay estimate)
    pub fn on_ack_received(
        &mut self,
        bytes_acked: usize,
        rtt_micros: u32,
        current_min_rtt_micros: u32,
        timestamp_micros: u32,
        timestamp_diff_micros: u32
    ) {
        // Update bytes in flight (with atomic operations for thread safety)
        let current_in_flight = self.bytes_in_flight.load(Ordering::Relaxed);
        self.bytes_in_flight.store(current_in_flight.saturating_sub(bytes_acked), Ordering::Relaxed);

        // Update current minimum RTT estimate
        if rtt_micros < self.current_min_rtt {
            self.current_min_rtt = rtt_micros;
        }

        // Update base delay measurements (LEDBAT)
        self.update_base_delay(timestamp_diff_micros);

        // Calculate queuing delay
        // In real uTP, this would use one-way delay from timestamp differences
        // For this implementation, we'll estimate from RTT differences
        let queuing_delay = self.calculate_queuing_delay(rtt_micros, current_min_rtt_micros);

        if self.in_slow_start {
            self.handle_slow_start(bytes_acked, queuing_delay);
        } else {
            self.handle_congestion_avoidance(bytes_acked, queuing_delay);
        }

        // Validate the congestion window size periodically
        self.validate_congestion_window();
    }

    /// Updates the base delay estimate based on timestamp differences
    fn update_base_delay(&mut self, delay_sample: u32) {
        // Store the delay sample for recent history
        if self.delay_samples.len() >= MAX_DELAY_SAMPLES {
            self.delay_samples.pop_front();
        }
        self.delay_samples.push_back(delay_sample);

        // Check if we need to reset base delay (every BASE_DELAY_RESET_MINUTES)
        let now = current_micros();
        if now - self.last_base_delay_update_time > BASE_DELAY_RESET_MINUTES * 60_000_000 {
            // Reset base delay to detect new route changes or clock drift
            self.base_delay_micros = u32::MAX;
            self.last_base_delay_update_time = now;
        }

        // Update base delay (minimum observed delay)
        if delay_sample < self.base_delay_micros {
            self.base_delay_micros = delay_sample;
        }
    }

    /// Calculates current queuing delay based on RTT measurements
    fn calculate_queuing_delay(&self, rtt_micros: u32, min_rtt_micros: u32) -> u32 {
        // Calculate queuing delay as current RTT minus base RTT
        // In real uTP, this would use one-way delay measurements
        rtt_micros.saturating_sub(min_rtt_micros)
    }

    /// Handles congestion window updates during slow start phase
    fn handle_slow_start(&mut self, bytes_acked: usize, queuing_delay: u32) {
        // If queuing delay exceeds 75% of target, exit slow start
        if queuing_delay > (self.target_delay_micros * 3) / 4 {
            self.in_slow_start = false;
            let current_cwnd = self.get_congestion_window_size();
            self.ssthresh_bytes.store(current_cwnd, Ordering::Relaxed);
            return;
        }

        // In slow start, increase window by bytes_acked
        let current_cwnd = self.get_congestion_window_size();
        let new_cwnd = min(current_cwnd + bytes_acked, MAX_CWND_BYTES);

        // Check if we've reached slow start threshold
        if new_cwnd >= self.ssthresh_bytes.load(Ordering::Relaxed) {
            self.in_slow_start = false;
        }

        // Update congestion window with triple redundancy
        self.update_cwnd(new_cwnd);
    }

    /// Handles congestion window updates during congestion avoidance (LEDBAT)
    fn handle_congestion_avoidance(&mut self, bytes_acked: usize, queuing_delay: u32) {
        let current_cwnd = self.get_congestion_window_size();

        // LEDBAT algorithm from RFC 6817
        let off_target = self.target_delay_micros as i64 - queuing_delay as i64;

        // Calculate window change factors
        let window_factor = bytes_acked as f64 / current_cwnd.max(1) as f64;
        let delay_factor = off_target as f64 / self.target_delay_micros.max(1) as f64;

        // Apply LEDBAT gain
        let gain = GAIN_FACTOR * MAX_CWND_INCREASE_BYTES_PER_RTT as f64 * window_factor * delay_factor;

        // Calculate new congestion window
        let mut new_cwnd = (current_cwnd as f64 + gain).round() as usize;

        // Apply bounds
        new_cwnd = clamp(new_cwnd, MIN_WINDOW_SIZE_BYTES, MAX_CWND_BYTES);

        // Update congestion window with triple redundancy
        self.update_cwnd(new_cwnd);
    }

    /// Updates the congestion window size with triple redundancy
    fn update_cwnd(&mut self, new_value: usize) {
        for cwnd in &self.cwnd_bytes {
            cwnd.store(new_value, Ordering::Relaxed);
        }
    }

    /// Validates the congestion window against actual usage
    fn validate_congestion_window(&mut self) {
        let now = current_micros();

        // Validate window size every RTT
        if now - self.last_window_validation_time < self.current_min_rtt as u64 {
            return;
        }

        let current_cwnd = self.get_congestion_window_size();
        let max_used = self.max_bytes_per_rtt;

        // If window is underutilized, gradually reduce it (RFC 7661)
        if max_used < current_cwnd / 2 && current_cwnd > MIN_WINDOW_SIZE_BYTES * 2 {
            // Reduce window size to max(max_used*2, MIN_WINDOW_SIZE)
            let new_cwnd = max(max_used * 2, MIN_WINDOW_SIZE_BYTES);
            self.update_cwnd(new_cwnd);
        }

        // Reset for next measurement period
        self.max_bytes_per_rtt = self.bytes_in_flight();
        self.last_window_validation_time = now;
    }

    /// Handles packet loss or timeout event
    pub fn on_timeout(&mut self) {
        // Increase loss counter
        self.loss_count += 1;

        // Enter slow start if multiple consecutive losses
        let should_reset = self.loss_count >= 3;

        if should_reset {
            // Reset to minimum window size on severe congestion
            self.update_cwnd(MIN_WINDOW_SIZE_BYTES);
            self.in_slow_start = true;
            self.loss_count = 0;
        } else {
            // Standard congestion response: halve the window
            let current_cwnd = self.get_congestion_window_size();
            let new_cwnd = max(current_cwnd / 2, MIN_WINDOW_SIZE_BYTES);
            self.update_cwnd(new_cwnd);

            // Update slow start threshold
            self.ssthresh_bytes.store(new_cwnd, Ordering::Relaxed);
            self.in_slow_start = false;
        }
    }

    /// Handles explicit congestion notification or triple duplicate ACKs
    pub fn on_congestion_event(&mut self) {
        // Similar to timeout but less aggressive
        let current_cwnd = self.get_congestion_window_size();
        let new_cwnd = max(current_cwnd * 3 / 4, MIN_WINDOW_SIZE_BYTES);

        self.update_cwnd(new_cwnd);
        self.ssthresh_bytes.store(new_cwnd, Ordering::Relaxed);
        self.in_slow_start = false;
    }

    /// Resets congestion control state
    pub fn reset(&mut self) {
        let initial_window = DEFAULT_MAX_PACKET_SIZE * 2;

        self.update_cwnd(initial_window);
        self.ssthresh_bytes.store(INITIAL_SSTHRESH_BYTES, Ordering::Relaxed);
        self.in_slow_start = true;
        self.bytes_in_flight.store(0, Ordering::Relaxed);
        self.delay_samples.clear();
        self.base_delay_micros = u32::MAX;
        self.last_base_delay_update_time = current_micros();
        self.current_min_rtt = u32::MAX;
        self.loss_count = 0;
        self.max_bytes_per_rtt = 0;
        self.last_window_validation_time = current_micros();
    }

    /// Updates the target delay for LEDBAT algorithm
    pub fn set_target_delay(&mut self, target_micros: u32) {
        self.target_delay_micros = max(target_micros, 1000); // Minimum 1ms
    }

    /// Updates the receive window size
    pub fn set_receive_window(&mut self, window_bytes: usize) {
        self.receive_window_bytes = window_bytes;
    }

    /// Gets current base delay estimate
    pub fn get_base_delay_micros(&self) -> u32 {
        self.base_delay_micros
    }

    /// Gets current queuing delay estimate
    pub fn get_current_queuing_delay(&self) -> u32 {
        if self.delay_samples.is_empty() {
            return 0;
        }

        // Return minimum of recent samples
        *self.delay_samples.iter().min().unwrap_or(&0)
    }

    /// Checks if we're currently in slow start phase
    pub fn is_in_slow_start(&self) -> bool {
        self.in_slow_start
    }

    /// Gets current slow start threshold
    pub fn get_slow_start_threshold(&self) -> usize {
        self.ssthresh_bytes.load(Ordering::Relaxed)
    }
}

// Default implementation
impl Default for CongestionControl {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_state() {
        let cc = CongestionControl::new();
        assert_eq!(cc.get_congestion_window_size(), DEFAULT_MAX_PACKET_SIZE * 2);
        assert_eq!(cc.bytes_in_flight(), 0);
        assert!(cc.is_in_slow_start());
    }

    #[test]
    fn test_triple_redundancy() {
        let cc = CongestionControl::new();
        let initial_cwnd = cc.get_congestion_window_size();

        // Corrupt one copy
        cc.cwnd_bytes[0].store(999, Ordering::Relaxed);

        // Majority voting should return the correct value
        assert_eq!(cc.get_congestion_window_size(), initial_cwnd);

        // Corrupt another copy differently
        cc.cwnd_bytes[1].store(1001, Ordering::Relaxed);

        // Median voting should return the middle value (1001)
        assert_eq!(cc.get_congestion_window_size(), 1001);
    }

    #[test]
    fn test_slow_start_growth() {
        let mut cc = CongestionControl::new();
        let initial_cwnd = cc.get_congestion_window_size();

        // ACK some data during slow start
        cc.on_packet_sent(1000);
        cc.on_ack_received(1000, 100_000, 100_000, 0, 0);

        // Window should increase by bytes_acked
        assert_eq!(cc.get_congestion_window_size(), initial_cwnd + 1000);
    }

    #[test]
    fn test_timeout_response() {
        let mut cc = CongestionControl::new();
        let initial_cwnd = cc.get_congestion_window_size();

        // Grow window first
        cc.on_packet_sent(10000);
        cc.on_ack_received(10000, 100_000, 100_000, 0, 0);

        let pre_timeout_cwnd = cc.get_congestion_window_size();
        assert!(pre_timeout_cwnd > initial_cwnd);

        // Handle timeout
        cc.on_timeout();

        // Window should be reduced
        assert!(cc.get_congestion_window_size() < pre_timeout_cwnd);
    }
}
