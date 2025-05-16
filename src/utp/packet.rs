// utp/packet.rs

use crate::utp::common::{ConnectionId, UTP_VERSION, ST_DATA, ST_FIN, ST_STATE, ST_RESET, ST_SYN};
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

    /// Get the total size of the packet including header, extensions, and payload
    pub fn total_size(&self) -> usize {
        let base_size = std::mem::size_of::<UtpHeader>();
        let extension_size = match &self.sack_data {
            Some(sack) => 2 + sack.len(), // 2 bytes for extension header plus SACK data
            None => 0,
        };
        base_size + extension_size + self.payload.len()
    }

    /// Create a new packet with specified parameters
    pub fn new(
        packet_type: u8,
        connection_id: ConnectionId,
        seq_nr: u16,
        ack_nr: u16,
        timestamp_micros: u32,
        timestamp_diff_micros: u32,
        wnd_size: u32,
        payload: Vec<u8>,
        sack_data: Option<Vec<u8>>,
        remote_addr: SocketAddr,
    ) -> Self {
        let extension = if sack_data.is_some() { 1 } else { 0 };

        let header = UtpHeader::new(
            packet_type,
            connection_id,
            timestamp_micros,
            timestamp_diff_micros,
            wnd_size,
            seq_nr,
            ack_nr,
            extension,
        );

        Self {
            header,
            payload,
            sack_data,
            remote_addr,
        }
    }

    /// Creates a SYN packet
    pub fn create_syn(
        connection_id: ConnectionId,
        seq_nr: u16,
        timestamp_micros: u32,
        wnd_size: u32,
        remote_addr: SocketAddr,
    ) -> Self {
        Self::new(
            ST_SYN,
            connection_id,
            seq_nr,
            0, // ack_nr is 0 for SYN
            timestamp_micros,
            0, // No timestamp diff for initial SYN
            wnd_size,
            Vec::new(), // Empty payload
            None, // No SACK data
            remote_addr,
        )
    }

    /// Creates a DATA packet
    pub fn create_data(
        connection_id: ConnectionId,
        seq_nr: u16,
        ack_nr: u16,
        timestamp_micros: u32,
        timestamp_diff_micros: u32,
        wnd_size: u32,
        payload: Vec<u8>,
        sack_data: Option<Vec<u8>>,
        remote_addr: SocketAddr,
    ) -> Self {
        Self::new(
            ST_DATA,
            connection_id,
            seq_nr,
            ack_nr,
            timestamp_micros,
            timestamp_diff_micros,
            wnd_size,
            payload,
            sack_data,
            remote_addr,
        )
    }

    /// Creates an ACK (STATE) packet
    pub fn create_ack(
        connection_id: ConnectionId,
        seq_nr: u16,
        ack_nr: u16,
        timestamp_micros: u32,
        timestamp_diff_micros: u32,
        wnd_size: u32,
        sack_data: Option<Vec<u8>>,
        remote_addr: SocketAddr,
    ) -> Self {
        Self::new(
            ST_STATE,
            connection_id,
            seq_nr,
            ack_nr,
            timestamp_micros,
            timestamp_diff_micros,
            wnd_size,
            Vec::new(), // Empty payload
            sack_data,
            remote_addr,
        )
    }

    /// Creates a FIN packet
    pub fn create_fin(
        connection_id: ConnectionId,
        seq_nr: u16,
        ack_nr: u16,
        timestamp_micros: u32,
        timestamp_diff_micros: u32,
        wnd_size: u32,
        remote_addr: SocketAddr,
    ) -> Self {
        Self::new(
            ST_FIN,
            connection_id,
            seq_nr,
            ack_nr,
            timestamp_micros,
            timestamp_diff_micros,
            wnd_size,
            Vec::new(), // Empty payload
            None, // No SACK data
            remote_addr,
        )
    }

    /// Creates a RESET packet
    pub fn create_reset(
        connection_id: ConnectionId,
        seq_nr: u16,
        ack_nr: u16,
        timestamp_micros: u32,
        timestamp_diff_micros: u32,
        wnd_size: u32,
        remote_addr: SocketAddr,
    ) -> Self {
        Self::new(
            ST_RESET,
            connection_id,
            seq_nr,
            ack_nr,
            timestamp_micros,
            timestamp_diff_micros,
            wnd_size,
            Vec::new(), // Empty payload
            None, // No SACK data
            remote_addr,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    // Helper function to create a test socket address
    fn test_socket_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080)
    }

    #[test]
    fn test_header_create_and_serialize() {
        let conn_id = 12345;
        let seq_nr = 1;
        let ack_nr = 2;
        let ts = 1000000;
        let ts_diff = 50000;
        let wnd_size = 65535;

        let header = UtpHeader::new(
            ST_DATA,
            conn_id,
            ts,
            ts_diff,
            wnd_size,
            seq_nr,
            ack_nr,
            0,
        );

        // Verify the header fields
        assert_eq!(header.packet_type(), ST_DATA);
        assert_eq!(header.version(), UTP_VERSION);
        assert_eq!(header.connection_id(), conn_id);
        assert_eq!(header.seq_nr(), seq_nr);
        assert_eq!(header.ack_nr(), ack_nr);
        assert_eq!(header.timestamp_micros(), ts);
        assert_eq!(header.timestamp_diff_micros(), ts_diff);
        assert_eq!(header.wnd_size(), wnd_size);

        // Serialize the header
        let mut buffer = [0u8; BASE_HEADER_SIZE];
        header.serialize(&mut buffer);

        // Deserialize and verify
        let deserialized = UtpHeader::deserialize(&buffer).unwrap();
        assert_eq!(deserialized.packet_type(), ST_DATA);
        assert_eq!(deserialized.version(), UTP_VERSION);
        assert_eq!(deserialized.connection_id(), conn_id);
        assert_eq!(deserialized.seq_nr(), seq_nr);
        assert_eq!(deserialized.ack_nr(), ack_nr);
        assert_eq!(deserialized.timestamp_micros(), ts);
        assert_eq!(deserialized.timestamp_diff_micros(), ts_diff);
        assert_eq!(deserialized.wnd_size(), wnd_size);
    }

    #[test]
    fn test_packet_serialization_without_sack() {
        let remote_addr = test_socket_addr();
        let conn_id = 12345;
        let seq_nr = 1;
        let ack_nr = 2;
        let ts = 1000000;
        let ts_diff = 50000;
        let wnd_size = 65535;
        let payload = vec![1, 2, 3, 4, 5];

        let packet = UtpPacket::new(
            ST_DATA,
            conn_id,
            seq_nr,
            ack_nr,
            ts,
            ts_diff,
            wnd_size,
            payload.clone(),
            None, // No SACK data
            remote_addr,
        );

        // Verify packet fields
        assert_eq!(packet.header.packet_type(), ST_DATA);
        assert_eq!(packet.header.connection_id(), conn_id);
        assert_eq!(packet.header.seq_nr(), seq_nr);
        assert_eq!(packet.header.ack_nr(), ack_nr);
        assert_eq!(packet.payload, payload);
        assert_eq!(packet.sack_data, None);

        // Serialize the packet
        let mut buffer = Vec::new();
        packet.serialize(&mut buffer);

        // Expected size: header + payload
        assert_eq!(buffer.len(), BASE_HEADER_SIZE + payload.len());

        // Deserialize and verify
        let deserialized = UtpPacket::from_bytes(&buffer, remote_addr).unwrap();
        assert_eq!(deserialized.header.packet_type(), ST_DATA);
        assert_eq!(deserialized.header.connection_id(), conn_id);
        assert_eq!(deserialized.header.seq_nr(), seq_nr);
        assert_eq!(deserialized.header.ack_nr(), ack_nr);
        assert_eq!(deserialized.payload, payload);
        assert_eq!(deserialized.sack_data, None);
    }

    #[test]
    fn test_packet_serialization_with_sack() {
        let remote_addr = test_socket_addr();
        let conn_id = 12345;
        let seq_nr = 1;
        let ack_nr = 2;
        let ts = 1000000;
        let ts_diff = 50000;
        let wnd_size = 65535;
        let payload = vec![1, 2, 3, 4, 5];
        let sack_data = vec![0x0F, 0xF0, 0x55, 0xAA]; // Example SACK bits

        let packet = UtpPacket::new(
            ST_DATA,
            conn_id,
            seq_nr,
            ack_nr,
            ts,
            ts_diff,
            wnd_size,
            payload.clone(),
            Some(sack_data.clone()),
            remote_addr,
        );

        // Verify packet fields
        assert_eq!(packet.header.packet_type(), ST_DATA);
        assert_eq!(packet.header.connection_id(), conn_id);
        assert_eq!(packet.header.seq_nr(), seq_nr);
        assert_eq!(packet.header.ack_nr(), ack_nr);
        assert_eq!(packet.payload, payload);
        assert_eq!(packet.sack_data, Some(sack_data.clone()));
        assert_eq!(packet.header.extension, 1); // Extension type for SACK

        // Serialize the packet
        let mut buffer = Vec::new();
        packet.serialize(&mut buffer);

        // Expected size: header + extension header (2) + sack data + payload
        assert_eq!(buffer.len(), BASE_HEADER_SIZE + 2 + sack_data.len() + payload.len());

        // Deserialize and verify
        let deserialized = UtpPacket::from_bytes(&buffer, remote_addr).unwrap();
        assert_eq!(deserialized.header.packet_type(), ST_DATA);
        assert_eq!(deserialized.header.connection_id(), conn_id);
        assert_eq!(deserialized.header.seq_nr(), seq_nr);
        assert_eq!(deserialized.header.ack_nr(), ack_nr);
        assert_eq!(deserialized.payload, payload);
        assert_eq!(deserialized.sack_data, Some(sack_data));
        assert_eq!(deserialized.header.extension, 1);
    }

    #[test]
    fn test_packet_create_helper_functions() {
        let remote_addr = test_socket_addr();
        let conn_id = 12345;
        let seq_nr = 1;
        let ack_nr = 2;
        let ts = 1000000;
        let ts_diff = 50000;
        let wnd_size = 65535;
        let payload = vec![1, 2, 3, 4, 5];

        // Test SYN packet creation
        let syn = UtpPacket::create_syn(conn_id, seq_nr, ts, wnd_size, remote_addr);
        assert_eq!(syn.header.packet_type(), ST_SYN);
        assert_eq!(syn.header.seq_nr(), seq_nr);
        assert_eq!(syn.header.ack_nr(), 0); // Should be 0 for SYN
        assert!(syn.payload.is_empty());

        // Test DATA packet creation
        let data = UtpPacket::create_data(
            conn_id, seq_nr, ack_nr, ts, ts_diff, wnd_size, payload.clone(), None, remote_addr,
        );
        assert_eq!(data.header.packet_type(), ST_DATA);
        assert_eq!(data.payload, payload);

        // Test ACK packet creation
        let ack = UtpPacket::create_ack(
            conn_id, seq_nr, ack_nr, ts, ts_diff, wnd_size, None, remote_addr,
        );
        assert_eq!(ack.header.packet_type(), ST_STATE);
        assert!(ack.payload.is_empty());

        // Test FIN packet creation
        let fin = UtpPacket::create_fin(
            conn_id, seq_nr, ack_nr, ts, ts_diff, wnd_size, remote_addr,
        );
        assert_eq!(fin.header.packet_type(), ST_FIN);
        assert!(fin.payload.is_empty());

        // Test RESET packet creation
        let reset = UtpPacket::create_reset(
            conn_id, seq_nr, ack_nr, ts, ts_diff, wnd_size, remote_addr,
        );
        assert_eq!(reset.header.packet_type(), ST_RESET);
        assert!(reset.payload.is_empty());
    }

    #[test]
    fn test_packet_from_bytes_validation() {
        let remote_addr = test_socket_addr();

        // Test empty buffer
        let empty_result = UtpPacket::from_bytes(&[], remote_addr);
        assert!(empty_result.is_err());

        // Test buffer too short for header
        let short_buffer = vec![0; BASE_HEADER_SIZE - 1];
        let short_result = UtpPacket::from_bytes(&short_buffer, remote_addr);
        assert!(short_result.is_err());

        // Test invalid version
        let mut header = UtpHeader::new(ST_DATA, 1, 0, 0, 0, 0, 0, 0);
        header.type_version = (ST_DATA << 4) | 0x0F; // Invalid version
        let mut buffer = vec![0; BASE_HEADER_SIZE];
        header.serialize(&mut buffer);
        let version_result = UtpPacket::from_bytes(&buffer, remote_addr);
        assert!(version_result.is_err());

        // Test invalid SACK extension (too short)
        let mut header = UtpHeader::new(ST_DATA, 1, 0, 0, 0, 0, 0, 1); // With extension
        let mut buffer = vec![0; BASE_HEADER_SIZE + 1]; // Not enough space for extension header
        header.serialize(&mut buffer);
        let sack_short_result = UtpPacket::from_bytes(&buffer, remote_addr);
        assert!(sack_short_result.is_err());

        // Test invalid SACK data (too short)
        let mut header = UtpHeader::new(ST_DATA, 1, 0, 0, 0, 0, 0, 1); // With extension
        let mut buffer = vec![0; BASE_HEADER_SIZE + 2]; // Enough for extension header
        header.serialize(&mut buffer);
        buffer[BASE_HEADER_SIZE] = 0; // next_extension
        buffer[BASE_HEADER_SIZE + 1] = 10; // sack_len, but buffer doesn't have enough space
        let sack_data_short_result = UtpPacket::from_bytes(&buffer, remote_addr);
        assert!(sack_data_short_result.is_err());
    }

    #[test]
    fn test_total_size_calculation() {
        let remote_addr = test_socket_addr();

        // Packet without SACK
        let packet1 = UtpPacket::new(
            ST_DATA,
            1,
            1,
            0,
            0,
            0,
            0,
            vec![1, 2, 3, 4, 5],
            None,
            remote_addr,
        );

        // Expected size: header + payload
        assert_eq!(packet1.total_size(), BASE_HEADER_SIZE + 5);

        // Packet with SACK
        let packet2 = UtpPacket::new(
            ST_DATA,
            1,
            1,
            0,
            0,
            0,
            0,
            vec![1, 2, 3],
            Some(vec![0xFF, 0xFF, 0xFF, 0xFF]),
            remote_addr,
        );

        // Expected size: header + extension header (2) + sack data + payload
        assert_eq!(packet2.total_size(), BASE_HEADER_SIZE + 2 + 4 + 3);
    }
}
