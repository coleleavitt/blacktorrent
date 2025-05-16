#![forbid(unsafe_code)]

use std::time::Instant;
use rand::Rng;

/// Protocol version constant
pub const UTP_VERSION: u8 = 1;

/// Packet types (from BEP-29 and libutp implementation)
pub const ST_DATA: u8 = 0;
pub const ST_FIN: u8 = 1;
pub const ST_STATE: u8 = 2;
pub const ST_RESET: u8 = 3;
pub const ST_SYN: u8 = 4;
pub const ST_NUM_STATES: u8 = 5;

/// Default protocol values
pub const DEFAULT_TARGET_DELAY_MICROS: u32 = 100_000;
pub const MAX_CWND_INCREASE_BYTES_PER_RTT: usize = 3000;
pub const MIN_WINDOW_SIZE_BYTES: usize = 150 * 2;
pub const INITIAL_RTO_MICROS: u32 = 1_000_000;
pub const MIN_RTO_MICROS: u32 = 500_000;
pub const MAX_RTO_MICROS: u32 = 60_000_000;

/// Network overhead constants
pub const UDP_IPV4_OVERHEAD: usize = 20 + 8;
pub const UDP_IPV6_OVERHEAD: usize = 40 + 8;
pub const DEFAULT_MAX_PACKET_SIZE: usize = 1400;

/// Bit masks for sequence numbers
pub const SEQ_NR_MASK: u16 = 0xFFFF;
pub const ACK_NR_MASK: u16 = 0xFFFF;
pub const TIMESTAMP_MASK: u32 = 0xFFFFFFFF;

/// Window management constants
pub const DUPLICATE_ACKS_BEFORE_RESEND: u32 = 3;
pub const ACK_NR_ALLOWED_WINDOW: u32 = DUPLICATE_ACKS_BEFORE_RESEND;
pub const MAX_WINDOW_DECAY: i64 = 100;

/// Timeout values
pub const TIMEOUT_CHECK_INTERVAL: u64 = 500;
pub const KEEPALIVE_INTERVAL: u64 = 29000;
pub const CONNECT_TIMEOUT: u64 = 6000;
pub const DELAYED_ACK_TIME: u64 = 20;

/// Buffer size limits
pub const REORDER_BUFFER_SIZE: usize = 32;
pub const REORDER_BUFFER_MAX_SIZE: usize = 1024;
pub const OUTGOING_BUFFER_MAX_SIZE: usize = 1024;

/// Connection States
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Uninitialized,
    Idle,
    SynSent,
    SynRecv,
    Connected,
    ConnectedFull,
    FinSent,
    FinRecv,
    Reset,
    Closed,
    Destroying,
}

impl ConnectionState {
    pub fn to_string(&self) -> &'static str {
        match self {
            ConnectionState::Uninitialized => "UNINITIALIZED",
            ConnectionState::Idle => "IDLE",
            ConnectionState::SynSent => "SYN_SENT",
            ConnectionState::SynRecv => "SYN_RECV",
            ConnectionState::Connected => "CONNECTED",
            ConnectionState::ConnectedFull => "CONNECTED_FULL",
            ConnectionState::FinSent => "FIN_SENT",
            ConnectionState::FinRecv => "FIN_RECV",
            ConnectionState::Reset => "RESET",
            ConnectionState::Closed => "CLOSED",
            ConnectionState::Destroying => "DESTROYING",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum UtpError {
    #[error("Connection timed out")]
    Timeout,
    #[error("Connection refused")]
    ConnectionRefused,
    #[error("Connection reset")]
    ConnectionReset,
    #[error("Network error: {0}")]
    Network(#[from] std::io::Error),
    #[error("Invalid packet format")]
    InvalidPacket,
    #[error("Invalid state for operation")]
    InvalidState,
    #[error("Address parse error")]
    AddressParse(#[from] std::net::AddrParseError),
    #[error("Internal error: {0}")]
    Internal(String),
    #[error("Maximum packet retransmissions reached")]
    MaxRetransmit,
    #[error("Window size too small")]
    WindowTooSmall,
}

/// Bandwidth types for statistics collection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BandwidthType {
    PayloadBandwidth,
    HeaderOverhead,
    AckOverhead,
    ConnectOverhead,
    CloseOverhead,
}

/// Microseconds timestamp with wrapping arithmetic
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Timestamp(pub u64);

impl Timestamp {
    pub fn now() -> Self {
        Timestamp(current_micros())
    }
    pub fn wrapping_sub(self, other: Self) -> u32 {
        (self.0.wrapping_sub(other.0) & 0xFFFFFFFF) as u32
    }
    pub fn as_millis(&self) -> u64 {
        self.0 / 1000
    }
}

pub type ConnectionId = u16;

/// Sequence number arithmetic (16-bit, wrapping)
pub fn seq_less_than(s1: u16, s2: u16) -> bool {
    ((s1 < s2) && (s2 - s1 < 32768)) || ((s1 > s2) && (s1 - s2 > 32768))
}
pub fn seq_greater_than(s1: u16, s2: u16) -> bool {
    seq_less_than(s2, s1)
}
pub fn seq_eq_or_greater_than(s1: u16, s2: u16) -> bool {
    s1 == s2 || seq_greater_than(s1, s2)
}

/// Clamp a value between min and max
pub fn clamp<T: PartialOrd>(val: T, min: T, max: T) -> T {
    if val < min {
        min
    } else if val > max {
        max
    } else {
        val
    }
}

/// Get current monotonic time in microseconds
pub fn current_micros() -> u64 {
    lazy_static::lazy_static! {
        static ref START_TIME: Instant = Instant::now();
    }
    START_TIME.elapsed().as_micros() as u64
}

/// Get current monotonic time in milliseconds
pub fn current_millis() -> u64 {
    current_micros() / 1000
}

/// Generate a random 16-bit number
pub fn random_u16() -> u16 {
    rand::random::<u16>()
}

/// Generate a random 32-bit number
pub fn random_u32() -> u32 {
    rand::random::<u32>()
}

/// Statistics for a uTP connection
#[derive(Debug, Default, Clone)]
pub struct UtpSocketStats {
    pub packets_received: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub bytes_sent: u64,
    pub packets_lost: u64,
    pub packets_retransmitted: u64,
    pub bytes_retransmitted: u64,
    pub duplicate_acks_received: u64,
    pub rtt_samples: u64,
    pub min_rtt: u32,
    pub max_rtt: u32,
    pub sum_rtt: u64,
}

impl UtpSocketStats {
    pub fn avg_rtt(&self) -> u32 {
        if self.rtt_samples == 0 {
            0
        } else {
            (self.sum_rtt / self.rtt_samples) as u32
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seq_arithmetic() {
        assert!(seq_less_than(10, 20));
        assert!(!seq_less_than(20, 10));
        assert!(seq_greater_than(20, 10));
        assert!(!seq_greater_than(10, 20));
        // Wrapping
        assert!(seq_less_than(65530, 5));
        assert!(seq_greater_than(5, 65530));
        assert!(seq_eq_or_greater_than(5, 65530));
        assert!(seq_eq_or_greater_than(65530, 65530));
    }

    #[test]
    fn test_clamp() {
        assert_eq!(clamp(5, 1, 10), 5);
        assert_eq!(clamp(0, 1, 10), 1);
        assert_eq!(clamp(15, 1, 10), 10);
    }

    #[test]
    fn test_timestamp_wrapping() {
        let t1 = Timestamp(10);
        let t2 = Timestamp(5);
        assert_eq!(t1.wrapping_sub(t2), 5);
        let t3 = Timestamp(u64::MAX);
        let t4 = Timestamp(1);
        assert_eq!(t4.wrapping_sub(t3), 2);
    }

    #[test]
    fn test_random_u16_u32() {
        let _v16 = random_u16();
        let _v32 = random_u32();
    }

    #[test]
    fn test_stats_avg_rtt() {
        let mut stats = UtpSocketStats {
            rtt_samples: 5,
            sum_rtt: 100,
            ..Default::default()
        };
        assert_eq!(stats.avg_rtt(), 20);
        stats.rtt_samples = 0;
        assert_eq!(stats.avg_rtt(), 0);
    }

    #[test]
    fn test_connection_state_to_string() {
        assert_eq!(ConnectionState::Connected.to_string(), "CONNECTED");
        assert_eq!(ConnectionState::FinSent.to_string(), "FIN_SENT");
    }
}
