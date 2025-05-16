// utp/packet.rs

use crate::utp::common::{ConnectionId, Timestamp, UTP_VERSION};
use std::net::SocketAddr;

// Based on PacketFormatV1 from libutp utp_internal.h[1]
// #pragma pack(push,1) implies byte alignment.
#[repr(C, packed)] // Ensure C-style packing, crucial for network protocols
pub struct UtpHeader {
    pub type_version: u8,    // type (4 bits), version (4 bits)
    pub extension: u8,       // type of first extension
    pub connection_id: u16,  // network byte order (big-endian)
    pub timestamp_micros: u32, // network byte order
    pub timestamp_diff_micros: u32, // network byte order
    pub wnd_size: u32,       // our receive window size, network byte order
    pub seq_nr: u16,         // sequence number, network byte order
    pub ack_nr: u16,         // ack number, network byte order
}

// Selective ACK extension header (example)
// Based on PacketFormatAckV1 from libutp utp_internal.h[1]
#[repr(C, packed)]
pub struct SackExtensionHeader {
    pub next_extension: u8,
    pub len: u8, // length of SACK data (e.g., 4 for 32 bits of SACK)
    // pub sack_bits: [u8; 4], // Example for 32 bits; actual size depends on len
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

    pub fn serialize(&self, buffer: &mut [u8]) -> usize {
        let size = std::mem::size_of::<Self>();
        if buffer.len() < size {
            panic!("Buffer too small for UtpHeader");
        }
        unsafe {
            std::ptr::copy_nonoverlapping(
                self as *const _ as *const u8,
                buffer.as_mut_ptr(),
                size,
            );
        }
        size
    }

    pub fn deserialize(buffer: &[u8]) -> Option<Self> {
        let size = std::mem::size_of::<Self>();
        if buffer.len() < size {
            return None;
        }
        // Safety: We are copying `size` bytes from `buffer` into a `UtpHeader`.
        // This is safe if `UtpHeader` is `repr(C, packed)` and buffer has enough data.
        // The fields will be in network byte order and need conversion for use.
        unsafe {
            let mut header = std::mem::MaybeUninit::<Self>::uninit();
            std::ptr::copy_nonoverlapping(
                buffer.as_ptr(),
                header.as_mut_ptr() as *mut u8,
                size,
            );
            Some(header.assume_init())
        }
    }
}

pub struct UtpPacket {
    pub header: UtpHeader,
    pub payload: Vec<u8>,
    // pub extensions: Vec<Box<dyn Extension>> // For a more extensible system
    pub sack_data: Option<Vec<u8>>, // Simplified SACK
    pub remote_addr: SocketAddr, // Keep track of where it came from or is going
}

impl UtpPacket {
    // Methods to parse and build packets
    pub fn from_bytes(data: &[u8], remote_addr: SocketAddr) -> Result<Self, &'static str> {
        if data.len() < std::mem::size_of::<UtpHeader>() {
            return Err("Packet too short for header");
        }
        let header = UtpHeader::deserialize(data).ok_or("Failed to deserialize header")?;

        // Basic validation
        if header.version() != UTP_VERSION {
            return Err("Unsupported uTP version");
        }

        let mut current_offset = std::mem::size_of::<UtpHeader>();
        let mut sack_data_option = None;

        if header.extension == 1 { // SACK extension
            if data.len() < current_offset + 2 { // Min SACK header size (next_ext, len)
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
            // Handle other extensions if `_next_ext` is not 0
        }

        let payload = data[current_offset..].to_vec();

        Ok(UtpPacket {
            header,
            payload,
            sack_data: sack_data_option,
            remote_addr,
        })
    }

    pub fn serialize(&self, buffer: &mut Vec<u8>) {
        buffer.clear();
        // Ensure buffer has enough space for header (can resize)
        buffer.resize(std::mem::size_of::<UtpHeader>(), 0);
        self.header.serialize(buffer.as_mut_slice());

        if let Some(sack) = &self.sack_data {
            // Assuming header.extension was set to 1
            buffer.push(0); // next_extension (0 if no more)
            buffer.push(sack.len() as u8);
            buffer.extend_from_slice(sack);
        }

        buffer.extend_from_slice(&self.payload);
    }
}
