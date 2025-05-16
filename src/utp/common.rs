// utp/common.rs

use std::time::Instant;
use rand::Rng; // Trait needed for .random() method

// Protocol version constant
pub const UTP_VERSION: u8 = 1;

// Packet types (from BEP-29 and libutp implementation)
pub const ST_DATA: u8 = 0;   // Regular data packet
pub const ST_FIN: u8 = 1;    // Finalize connection packet
pub const ST_STATE: u8 = 2;  // State packet (ACK)
pub const ST_RESET: u8 = 3;  // Connection reset packet
pub const ST_SYN: u8 = 4;    // Connection initiation packet
pub const ST_NUM_STATES: u8 = 5; // Total number of packet types

// Default protocol values
pub const DEFAULT_TARGET_DELAY_MICROS: u32 = 100_000; // 100ms target delay
pub const MAX_CWND_INCREASE_BYTES_PER_RTT: usize = 3000;
pub const MIN_WINDOW_SIZE_BYTES: usize = 150 * 2; // Roughly two MSS
pub const INITIAL_RTO_MICROS: u32 = 1_000_000; // 1 second RTO
pub const MIN_RTO_MICROS: u32 = 500_000; // Minimum RTO 500ms
pub const MAX_RTO_MICROS: u32 = 60_000_000; // Maximum RTO 60 seconds

// Network overhead constants
pub const UDP_IPV4_OVERHEAD: usize = 20 /* IP */ + 8 /* UDP */;
pub const UDP_IPV6_OVERHEAD: usize = 40 /* IP */ + 8 /* UDP */;
pub const DEFAULT_MAX_PACKET_SIZE: usize = 1400; // Common safe MTU payload size

// Bit masks for sequence numbers
pub const SEQ_NR_MASK: u16 = 0xFFFF;
pub const ACK_NR_MASK: u16 = 0xFFFF;
pub const TIMESTAMP_MASK: u32 = 0xFFFFFFFF;

// Window management constants
pub const DUPLICATE_ACKS_BEFORE_RESEND: u32 = 3;
pub const ACK_NR_ALLOWED_WINDOW: u32 = DUPLICATE_ACKS_BEFORE_RESEND;
pub const MAX_WINDOW_DECAY: i64 = 100; // ms

// Timeout values
pub const TIMEOUT_CHECK_INTERVAL: u64 = 500; // ms
pub const KEEPALIVE_INTERVAL: u64 = 29000; // 29 seconds
pub const CONNECT_TIMEOUT: u64 = 6000; // 6 seconds
pub const DELAYED_ACK_TIME: u64 = 20; // 20ms before sending delayed ACK

// Buffer size limits
pub const REORDER_BUFFER_SIZE: usize = 32;
pub const REORDER_BUFFER_MAX_SIZE: usize = 1024;
pub const OUTGOING_BUFFER_MAX_SIZE: usize = 1024;

// Connection States
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Uninitialized,       // Initial state
    Idle,                // Initialized but not in use
    SynSent,             // Connect sent
    SynRecv,             // Connect received
    Connected,           // Connection established
    ConnectedFull,       // Connection established, window full
    FinSent,             // FIN packet sent
    FinRecv,             // FIN packet received
    Reset,               // Connection reset
    Closed,              // Connection closed
    Destroying,          // Being torn down
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

/// Error types for the uTP protocol

#[derive(Debug, thiserror::Error)]
pub enum UtpError {
    #[error("Connection timed out")]
    Timeout,

    #[error("Connection refused")]
    ConnectionRefused,

    #[error("Connection reset")]
    ConnectionReset,

    #[error("Network error: {0}")]
    Network(#[from] std::io::Error),  // Remove from Clone derivation

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
    /// Get the current time as a microsecond timestamp
    pub fn now() -> Self {
        Timestamp(current_micros())
    }

    /// Subtract another timestamp with wrapping arithmetic
    pub fn wrapping_sub(self, other: Self) -> u32 {
        // Handle wrapping of 32-bit timestamps as used in the protocol
        (self.0.wrapping_sub(other.0) & 0xFFFFFFFF) as u32
    }

    /// Convert to milliseconds
    pub fn as_millis(&self) -> u64 {
        self.0 / 1000
    }
}

// Connection ID type
pub type ConnectionId = u16;

// Helper functions for sequence number arithmetic (16-bit, wrapping)
// Used for comparing sequence numbers with wrapping logic

/// Compares if s1 is less than s2, considering wrapping
pub fn seq_less_than(s1: u16, s2: u16) -> bool {
    ((s1 < s2) && (s2 - s1 < 32768)) || ((s1 > s2) && (s1 - s2 > 32768))
}

/// Compares if s1 is greater than s2, considering wrapping
pub fn seq_greater_than(s1: u16, s2: u16) -> bool {
    seq_less_than(s2, s1)
}

/// Compares if s1 is equal to or greater than s2, considering wrapping
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

/// Function to get current microseconds (monotonic)
pub fn current_micros() -> u64 {
    lazy_static::lazy_static! {
        static ref START_TIME: Instant = Instant::now();
    }
    START_TIME.elapsed().as_micros() as u64
}

/// Get current time in milliseconds (monotonic)
pub fn current_millis() -> u64 {
    current_micros() / 1000
}

/// Generate a random 16-bit number
pub fn random_u16() -> u16 {
    rand::rng().random::<u16>() // Updated to use .random()
}

/// Generate a random 32-bit number
pub fn random_u32() -> u32 {
    rand::rng().random::<u32>() // Updated to use .random()
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
    /// Calculate average RTT
    pub fn avg_rtt(&self) -> u32 {
        if self.rtt_samples == 0 {
            0
        } else {
            (self.sum_rtt / self.rtt_samples) as u32
        }
    }
}
