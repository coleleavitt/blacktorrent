// utp/packet.rs

use crate::utp::common::{ConnectionId, UTP_VERSION};
use std::net::SocketAddr;

// Base header size constant for MTU calculations
pub const BASE_HEADER_SIZE: usize = 20; // Size of UtpHeader struct

/// Based on PacketFormatV1 from libutp utp_internal.h
/// The UTP packet header format follows BEP-29 specification
#[repr(C, packed)]
#[derive(Clone)]
pub struct UtpHeader {
    pub type_version: u8,    // type (4 bits), version (4 bits)
    pub extension: u8,       // type of first extension
    pub connection_id: u16,  // network byte order (big-endian)
    pub timestamp_micros: u32, // network byte order
    pub timestamp_diff_micros: u32, // network byte order
    pub wnd_size: u32,       // receive window size, network byte order
    pub seq_nr: u16,         // sequence number, network byte order
    pub ack_nr: u16,         // ack number, network byte order
}

/// Selective ACK extension header
#[repr(C, packed)]
pub struct SackExtensionHeader {
    pub next_extension: u8,
    pub len: u8, // length of SACK data (e.g., 4 for 32 bits of SACK)
}

impl UtpHeader {
    pub fn new(
        packet_type: u8,
        connection_id: ConnectionId,
        timestamp_micros: u32,
        timestamp_diff_micros: u32,
        wnd_size: u32,
        seq_nr: u16,
        ack_nr: u16,
        extension: u8,
    ) -> Self {
        Self {
            type_version: (packet_type << 4) | (UTP_VERSION & 0x0F),
            extension,
            connection_id: connection_id.to_be(),
            timestamp_micros: timestamp_micros.to_be(),
            timestamp_diff_micros: timestamp_diff_micros.to_be(),
            wnd_size: wnd_size.to_be(),
            seq_nr: seq_nr.to_be(),
            ack_nr: ack_nr.to_be(),
        }
    }

    pub fn packet_type(&self) -> u8 {
        self.type_version >> 4
    }

    pub fn version(&self) -> u8 {
        self.type_version & 0x0F
    }

    pub fn connection_id(&self) -> ConnectionId {
        ConnectionId::from_be(self.connection_id)
    }

    pub fn timestamp_micros(&self) -> u32 {
        u32::from_be(self.timestamp_micros)
    }

    pub fn timestamp_diff_micros(&self) -> u32 {
        u32::from_be(self.timestamp_diff_micros)
    }

    pub fn wnd_size(&self) -> u32 {
        u32::from_be(self.wnd_size)
    }

    pub fn seq_nr(&self) -> u16 {
        u16::from_be(self.seq_nr)
    }

    pub fn ack_nr(&self) -> u16 {
        u16::from_be(self.ack_nr)
    }

    /// Safely serialize the header to a byte buffer
    pub fn serialize(&self, buffer: &mut [u8]) -> usize {
        let size = std::mem::size_of::<Self>();
        if buffer.len() < size {
            panic!("Buffer too small for UtpHeader");
        }
        // Safety: We're copying from a properly packed struct into a byte slice
        unsafe {
            std::ptr::copy_nonoverlapping(
                self as *const _ as *const u8,
                buffer.as_mut_ptr(),
                size,
            );
        }
        size
    }

    /// Safely deserialize a header from a byte buffer
    pub fn deserialize(buffer: &[u8]) -> Option<Self> {
        let size = std::mem::size_of::<Self>();
        if buffer.len() < size {
            return None;
        }

        // Safety: We validate buffer size above and use packed struct
        // Field alignment is guaranteed by the repr(C, packed) attribute
        let mut header = Self {
            type_version: 0,
            extension: 0,
            connection_id: 0,
            timestamp_micros: 0,
            timestamp_diff_micros: 0,
            wnd_size: 0,
            seq_nr: 0,
            ack_nr: 0,
        };

        unsafe {
            std::ptr::copy_nonoverlapping(
                buffer.as_ptr(),
                &mut header as *mut Self as *mut u8,
                size,
            );
        }

        Some(header)
    }
}

/// A complete UTP packet with header and payload
#[derive(Clone)]
pub struct UtpPacket {
    pub header: UtpHeader,
    pub payload: Vec<u8>,
    pub sack_data: Option<Vec<u8>>, // Selective ACK data
    pub remote_addr: SocketAddr, // Source/destination address
}

impl UtpPacket {
    /// Create a new UtpPacket from raw UDP data
    pub fn from_bytes(data: &[u8], remote_addr: SocketAddr) -> Result<Self, &'static str> {
        if data.len() < std::mem::size_of::<UtpHeader>() {
            return Err("Packet too short for header");
        }

        let header = match UtpHeader::deserialize(data) {
            Some(h) => h,
            None => return Err("Failed to deserialize header"),
        };

        // Basic validation
        if header.version() != UTP_VERSION {
            return Err("Unsupported uTP version");
        }

        let mut current_offset = std::mem::size_of::<UtpHeader>();
        let mut sack_data_option = None;

        // Process extensions
        if header.extension == 1 { // SACK extension
            if data.len() < current_offset + 2 {
                return Err("Packet too short for SACK extension header");
            }

            let _next_ext = data[current_offset];
            let sack_len = data[current_offset + 1] as usize;
            current_offset += 2;

            if data.len() < current_offset + sack_len {
                return Err("Packet too short for SACK data");
            }

            sack_data_option = Some(data[current_offset..current_offset + sack_len].to_vec());
            current_offset += sack_len;
            // Additional extensions would be handled here if _next_ext != 0
        }

        // Extract payload
        let payload = data[current_offset..].to_vec();

        Ok(UtpPacket {
            header,
            payload,
            sack_data: sack_data_option,
            remote_addr,
        })
    }

    /// Serialize the packet to a byte buffer 
    pub fn serialize(&self, buffer: &mut Vec<u8>) {
        buffer.clear();
        buffer.resize(std::mem::size_of::<UtpHeader>(), 0);
        self.header.serialize(buffer.as_mut_slice());

        if let Some(sack) = &self.sack_data {
            buffer.push(0); // next_extension (0 if no more)
            buffer.push(sack.len() as u8);
            buffer.extend_from_slice(sack);
        }

        buffer.extend_from_slice(&self.payload);
    }

    /// Get the size of the payload
    pub fn payload_size(&self) -> usize {
        self.payload.len()
    }
}
