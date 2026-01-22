// Copyright 2025 The dcSCTP Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::api::Options;
use crate::api::ZERO_CHECKSUM_ALTERNATE_ERROR_DETECTION_METHOD_NONE;
use crate::math::is_divisible_by_4;
use crate::math::round_down_to_4;
use crate::math::round_up_to_4;
use crate::packet::AsSerializableTlv;
use crate::packet::ChunkParseError;
use crate::packet::chunk::Chunk;
use crate::packet::chunk::RawChunk;
use crate::packet::crc32c::Crc32c;
use crate::packet::ensure;
use crate::packet::read_u16_be;
use crate::packet::read_u32_be;
use crate::packet::write_u16_be;
use crate::packet::write_u32_be;
use thiserror::Error;

pub const COMMON_HEADER_SIZE: usize = 12;
const CHUNK_TLV_SIZE: usize = 4;

/// A sensible limit of how large packets that can be received. The real value is much lower, as
/// SCTP over DTLS over IPv6 (without fragmentation) usually brings the value down to a little over
/// 1000 bytes. This value is just to avoid malicious usage.
const MAX_PACKET_SIZE: usize = 65535;

/// SCTP common header
///
/// See <https://datatracker.ietf.org/doc/html/rfc9260#section-3.1>.
///
/// ```txt
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |      Source Port Number       |    Destination Port Number    |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                       Verification Tag                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                           Checksum                            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
pub(crate) struct CommonHeader {
    pub source_port: u16,
    pub destination_port: u16,
    pub verification_tag: u32,
    pub checksum: u32,
}

pub(crate) struct SctpPacket {
    pub common_header: CommonHeader,
    pub chunks: Vec<Chunk>,
}

#[derive(Debug, Error, PartialEq)]
#[non_exhaustive]
pub(crate) enum PacketParseError {
    #[error("Invalid packet size")]
    InvalidPacketSize,
    #[error("Invalid packet checksum")]
    InvalidChecksum,
    #[error("Invalid chunk size")]
    InvalidChunkSize,
    #[error("Failed to parse chunk")]
    FailedParseChunk(ChunkParseError),
}

impl From<ChunkParseError> for PacketParseError {
    fn from(e: ChunkParseError) -> Self {
        Self::FailedParseChunk(e)
    }
}

impl SctpPacket {
    pub fn from_bytes(data: &[u8], options: &Options) -> Result<SctpPacket, PacketParseError> {
        ensure!(
            data.len() >= COMMON_HEADER_SIZE + CHUNK_TLV_SIZE && data.len() <= MAX_PACKET_SIZE,
            PacketParseError::InvalidPacketSize
        );

        let common_header = CommonHeader {
            source_port: read_u16_be!(&data[0..2]),
            destination_port: read_u16_be!(&data[2..4]),
            verification_tag: read_u32_be!(&data[4..8]),
            checksum: read_u32_be!(&data[8..12]),
        };

        if options.disable_checksum_verification
            || (options.zero_checksum_alternate_error_detection_method
                != ZERO_CHECKSUM_ALTERNATE_ERROR_DETECTION_METHOD_NONE
                && common_header.checksum == 0)
        {
            // From <https://datatracker.ietf.org/doc/html/rfc9653#section-5.3-1>:
            //
            //   If an endpoint has sent the Zero Checksum Acceptable Chunk Parameter indicating the
            //   support of an alternate error detection method in an INIT or INIT ACK chunk, in
            //   addition to SCTP packets containing the correct CRC32c checksum value it MUST
            //   accept SCTP packets that have an incorrect checksum value of zero and that fulfill
            //   the requirements of the announced alternate error detection method used for this
            //   association.
        } else {
            const FOUR_ZEROES: &[u8] = &[0, 0, 0, 0];
            // Verify the checksum. The checksum field must be zero when that's done.
            let mut crc = Crc32c::new();
            crc.digest(&data[0..8]);
            crc.digest(FOUR_ZEROES);
            crc.digest(&data[12..]);
            let checksum = crc.value().to_be();
            ensure!(checksum == common_header.checksum, PacketParseError::InvalidChecksum);
        }

        let mut chunks: Vec<Chunk> = Vec::with_capacity(4);
        let mut remaining = &data[COMMON_HEADER_SIZE..];

        while !remaining.is_empty() {
            let (raw, next_remaining) = RawChunk::from_bytes(remaining)?;
            let chunk = Chunk::try_from(raw)?;
            chunks.push(chunk);

            remaining = next_remaining;
        }

        Ok(SctpPacket { common_header, chunks })
    }
}

pub(crate) struct SctpPacketBuilder {
    verification_tag: u32,
    source_port: u16,
    dest_port: u16,
    max_packet_size: usize,
    write_checksum: bool,
    data: Vec<u8>,
}

impl SctpPacketBuilder {
    pub(crate) fn new(
        verification_tag: u32,
        source_port: u16,
        dest_port: u16,
        max_packet_size: usize,
    ) -> Self {
        Self {
            verification_tag,
            source_port,
            dest_port,
            max_packet_size: round_down_to_4!(max_packet_size),
            write_checksum: true,
            data: vec![],
        }
    }

    pub(crate) fn write_checksum(&mut self, enable: bool) -> &mut Self {
        self.write_checksum = enable;
        self
    }

    pub(crate) fn add(&mut self, chunk: &Chunk) -> &mut Self {
        if self.data.is_empty() {
            self.data.reserve(self.max_packet_size);
            self.data.resize(COMMON_HEADER_SIZE, 0);
            write_u16_be!(&mut self.data[0..2], self.source_port);
            write_u16_be!(&mut self.data[2..4], self.dest_port);
            write_u32_be!(&mut self.data[4..8], self.verification_tag);
            // Checksum is at offset 8 - written when calling `build()`.
        }
        debug_assert!(is_divisible_by_4!(self.data.len()));

        let chunk_offset = self.data.len();
        let chunk_size = chunk.as_serializable().serialized_size();
        self.data.resize(round_up_to_4!(self.data.len() + chunk_size), 0);
        chunk
            .as_serializable()
            .serialize_to(&mut self.data[chunk_offset..chunk_offset + chunk_size]);
        debug_assert!(is_divisible_by_4!(self.data.len()));
        debug_assert!(self.data.len() <= self.max_packet_size);
        self
    }

    pub fn bytes_remaining(&self) -> usize {
        if self.data.is_empty() {
            // The common packet header hasn't been written yet.
            return self.max_packet_size - COMMON_HEADER_SIZE;
        }
        self.max_packet_size - self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn build(&mut self) -> Vec<u8> {
        let mut out = Vec::<u8>::new();
        if self.write_checksum && !self.data.is_empty() {
            let mut crc = Crc32c::new();
            crc.digest(&self.data);
            let checksum = crc.value().to_be();
            write_u32_be!(&mut self.data[8..12], checksum);
        }
        std::mem::swap(&mut self.data, &mut out);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::PpId;
    use crate::api::StreamId;
    use crate::api::ZERO_CHECKSUM_ALTERNATE_ERROR_DETECTION_METHOD_LOWER_LAYER_DTLS;
    use crate::packet::abort_chunk::AbortChunk;
    use crate::packet::data::Data;
    use crate::packet::data_chunk;
    use crate::packet::data_chunk::DataChunk;
    use crate::packet::error_causes::ErrorCause;
    use crate::packet::init_chunk::InitChunk;
    use crate::packet::sack_chunk::GapAckBlock;
    use crate::packet::sack_chunk::SackChunk;
    use crate::packet::user_initiated_abort_error_cause::UserInitiatedAbortErrorCause;
    use crate::types::Ssn;
    use crate::types::StreamKey;
    use crate::types::Tsn;

    const VERIFICATION_TAG: u32 = 0x12345678;

    #[test]
    fn deserialize_simple_packet_from_capture() {
        // Stream Control Transmission Protocol
        //   Source port: 5000
        //   Destination port: 5000
        //   Verification tag: 0x00000000
        //   Checksum: 0xaa019d33 [unverified]
        //   INIT chunk (Outbound streams: 1000, inbound streams: 1000)
        //     Chunk type: INIT (1)
        //       Chunk flags: 0x00
        //       Chunk length: 90
        //       Initiate tag: 0x0eddca08
        //       Advertised receiver window credit (a_rwnd): 131072
        //       Number of outbound streams: 1000
        //       Number of inbound streams: 1000
        //       Initial TSN: 1426601527
        //       ECN parameter
        //         Parameter type: ECN (0x8000)
        //         Parameter length: 4
        //       Forward TSN supported parameter
        //         Parameter type: Forward TSN supported (0xc000)
        //         Parameter length: 4
        //       Supported Extensions parameter
        //         Parameter type: Supported Extensions (0x8008)
        //         Parameter length: 9
        //         Supported chunk type: FORWARD_TSN (192)
        //         Supported chunk type: AUTH (15)
        //         Supported chunk type: ASCONF (193)
        //         Supported chunk type: ASCONF_ACK (128)
        //         Supported chunk type: RE_CONFIG (130)
        //         Parameter padding: 000000
        //       Random parameter
        //         Parameter type: Random (0x8002)
        //         Parameter length: 36
        //         Random number: c5a86155090e6f420050634cc8d6b908dfd53e17c99...
        //       Requested HMAC Algorithm parameter
        //         Parameter type: Requested HMAC Algorithm (0x8004)
        //         Parameter length: 6
        //         HMAC identifier: SHA-1 (1)
        //         Parameter padding: 0000
        //       Authenticated Chunk list parameter
        //         Parameter type: Authenticated Chunk list (0x8003)
        //         Parameter length: 6
        //         Chunk type: ASCONF_ACK (128)
        //         Chunk type: ASCONF (193)
        //       Chunk padding: 0000
        let bytes: &[u8] = &[
            0x13, 0x88, 0x13, 0x88, 0x00, 0x00, 0x00, 0x00, 0xaa, 0x01, 0x9d, 0x33, 0x01, 0x00,
            0x00, 0x5a, 0x0e, 0xdd, 0xca, 0x08, 0x00, 0x02, 0x00, 0x00, 0x03, 0xe8, 0x03, 0xe8,
            0x55, 0x08, 0x36, 0x37, 0x80, 0x00, 0x00, 0x04, 0xc0, 0x00, 0x00, 0x04, 0x80, 0x08,
            0x00, 0x09, 0xc0, 0x0f, 0xc1, 0x80, 0x82, 0x00, 0x00, 0x00, 0x80, 0x02, 0x00, 0x24,
            0xc5, 0xa8, 0x61, 0x55, 0x09, 0x0e, 0x6f, 0x42, 0x00, 0x50, 0x63, 0x4c, 0xc8, 0xd6,
            0xb9, 0x08, 0xdf, 0xd5, 0x3e, 0x17, 0xc9, 0x9c, 0xb1, 0x43, 0x28, 0x4e, 0xaf, 0x64,
            0x68, 0x2a, 0xc2, 0x97, 0x80, 0x04, 0x00, 0x06, 0x00, 0x01, 0x00, 0x00, 0x80, 0x03,
            0x00, 0x06, 0x80, 0xc1, 0x00, 0x00,
        ];

        let packet = SctpPacket::from_bytes(bytes, &Options::default()).unwrap();
        assert_eq!(packet.common_header.source_port, 5000);
        assert_eq!(packet.common_header.destination_port, 5000);
        assert_eq!(packet.common_header.verification_tag, 0);
        assert_eq!(packet.common_header.checksum, 0xaa019d33);

        assert_eq!(packet.chunks.len(), 1);
        assert!(matches!(packet.chunks[0], Chunk::Init(_)));
        if let Chunk::Init(init) = &packet.chunks[0] {
            assert_eq!(init.initial_tsn, Tsn(1426601527));
        }
    }

    #[test]
    fn deserialize_packet_with_two_chunks() {
        // Stream Control Transmission Protocol, Src Port: 1234 (1234),
        //   Dst Port: 4321 (4321)
        //     Source port: 1234
        //     Destination port: 4321
        //     Verification tag: 0x697e3a4e
        //     [Association index: 3]
        //     Checksum: 0xc06e8b36 [unverified]
        //     [Checksum Status: Unverified]
        //     COOKIE_ACK chunk
        //         Chunk type: COOKIE_ACK (11)
        //         Chunk flags: 0x00
        //         Chunk length: 4
        //     SACK chunk (Cumulative TSN: 2930332242, a_rwnd: 131072,
        //       gaps: 0, duplicate TSNs: 0)
        //         Chunk type: SACK (3)
        //         Chunk flags: 0x00
        //         Chunk length: 16
        //         Cumulative TSN ACK: 2930332242
        //         Advertised receiver window credit (a_rwnd): 131072
        //         Number of gap acknowledgement blocks: 0
        //         Number of duplicated TSNs: 0
        let bytes: &[u8] = &[
            0x04, 0xd2, 0x10, 0xe1, 0x69, 0x7e, 0x3a, 0x4e, 0xc0, 0x6e, 0x8b, 0x36, 0x0b, 0x00,
            0x00, 0x04, 0x03, 0x00, 0x00, 0x10, 0xae, 0xa9, 0x52, 0x52, 0x00, 0x02, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];

        let packet = SctpPacket::from_bytes(bytes, &Options::default()).unwrap();
        assert_eq!(packet.common_header.source_port, 1234);
        assert_eq!(packet.common_header.destination_port, 4321);
        assert_eq!(packet.common_header.verification_tag, 0x697e3a4e);
        assert_eq!(packet.common_header.checksum, 0xc06e8b36);

        assert_eq!(packet.chunks.len(), 2);
        assert!(matches!(packet.chunks[0], Chunk::CookieAck(_)));
        assert!(matches!(packet.chunks[1], Chunk::Sack(_)));
    }

    #[test]
    fn deserialize_packet_with_wrong_checksum() {
        // Stream Control Transmission Protocol, Src Port: 5000 (5000),
        //   Dst Port: 5000 (5000)
        //     Source port: 5000
        //     Destination port: 5000
        //     Verification tag: 0x0eddca08
        //     [Association index: 1]
        //     Checksum: 0x2a81f531 [unverified]
        //     [Checksum Status: Unverified]
        //     SACK chunk (Cumulative TSN: 1426601536, a_rwnd: 131072,
        //       gaps: 0, duplicate TSNs: 0)
        //         Chunk type: SACK (3)
        //         Chunk flags: 0x00
        //         Chunk length: 16
        //         Cumulative TSN ACK: 1426601536
        //         Advertised receiver window credit (a_rwnd): 131072
        //         Number of gap acknowledgement blocks: 0
        //         Number of duplicated TSNs: 0
        let bytes: &[u8] = &[
            0x13, 0x88, 0x13, 0x88, 0x0e, 0xdd, 0xca, 0x08, 0x2a, 0x81, 0xf5, 0x31, 0x03, 0x00,
            0x00, 0x10, 0x55, 0x08, 0x36, 0x40, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let packet = SctpPacket::from_bytes(bytes, &Options::default());
        assert!(packet.is_err());
    }

    #[test]
    fn deserialize_packet_dont_validate_checksum() {
        // Stream Control Transmission Protocol, Src Port: 5000 (5000),
        //   Dst Port: 5000 (5000)
        //     Source port: 5000
        //     Destination port: 5000
        //     Verification tag: 0x0eddca08
        //     [Association index: 1]
        //     Checksum: 0x2a81f531 [unverified]
        //     [Checksum Status: Unverified]
        //     SACK chunk (Cumulative TSN: 1426601536, a_rwnd: 131072,
        //       gaps: 0, duplicate TSNs: 0)
        //         Chunk type: SACK (3)
        //         Chunk flags: 0x00
        //         Chunk length: 16
        //         Cumulative TSN ACK: 1426601536
        //         Advertised receiver window credit (a_rwnd): 131072
        //         Number of gap acknowledgement blocks: 0
        //         Number of duplicated TSNs: 0
        let bytes: &[u8] = &[
            0x13, 0x88, 0x13, 0x88, 0x0e, 0xdd, 0xca, 0x08, 0x2a, 0x81, 0xf5, 0x31, 0x03, 0x00,
            0x00, 0x10, 0x55, 0x08, 0x36, 0x40, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let options = &Options { disable_checksum_verification: true, ..Default::default() };
        let packet = SctpPacket::from_bytes(bytes, options).unwrap();

        assert_eq!(packet.common_header.source_port, 5000);
        assert_eq!(packet.common_header.destination_port, 5000);
        assert_eq!(packet.common_header.verification_tag, 0x0eddca08);
        assert_eq!(packet.common_header.checksum, 0x2a81f531);
    }

    #[test]
    fn serialize_and_deserialize_single_chunk() {
        let options: Options = Default::default();

        let mut b = SctpPacketBuilder::new(
            VERIFICATION_TAG,
            options.local_port,
            options.remote_port,
            options.mtu,
        );

        b.add(&Chunk::Init(InitChunk {
            initiate_tag: 123,
            a_rwnd: 456,
            nbr_outbound_streams: 65535,
            nbr_inbound_streams: 65534,
            initial_tsn: Tsn(789),
            parameters: vec![],
        }));
        let serialized = b.build();

        let packet = SctpPacket::from_bytes(&serialized, &Options::default()).unwrap();

        assert_eq!(packet.common_header.verification_tag, VERIFICATION_TAG);
        assert_eq!(packet.chunks.len(), 1);
        assert!(matches!(packet.chunks[0], Chunk::Init(_)));
        if let Chunk::Init(init) = &packet.chunks[0] {
            assert_eq!(init.initiate_tag, 123);
            assert_eq!(init.a_rwnd, 456);
            assert_eq!(init.nbr_outbound_streams, 65535);
            assert_eq!(init.nbr_inbound_streams, 65534);
            assert_eq!(init.initial_tsn, Tsn(789));
        } else {
            panic!();
        }
    }

    #[test]
    fn serialize_and_deserialize_three_chunks() {
        let options: Options = Default::default();
        let mut b = SctpPacketBuilder::new(
            VERIFICATION_TAG,
            options.local_port,
            options.remote_port,
            options.mtu,
        );
        b.add(&Chunk::Sack(SackChunk {
            cumulative_tsn_ack: Tsn(999),
            a_rwnd: 456,
            gap_ack_blocks: vec![GapAckBlock::new(2, 3)],
            duplicate_tsns: vec![Tsn(1), Tsn(2), Tsn(3)],
        }));
        b.add(&Chunk::Data(DataChunk {
            tsn: Tsn(123),
            data: Data {
                stream_key: StreamKey::Ordered(StreamId(456)),
                ssn: Ssn(789),
                ppid: PpId(9090),
                payload: vec![1, 2, 3, 4, 5],
                ..Default::default()
            },
        }));
        b.add(&Chunk::Data(DataChunk {
            tsn: Tsn(124),
            data: Data {
                stream_key: StreamKey::Ordered(StreamId(654)),
                ssn: Ssn(789),
                ppid: PpId(909),
                payload: vec![5, 4, 3, 2, 1],
                ..Default::default()
            },
        }));
        let serialized = b.build();

        let packet = SctpPacket::from_bytes(&serialized, &Options::default()).unwrap();

        assert_eq!(packet.common_header.verification_tag, VERIFICATION_TAG);
        assert_eq!(packet.chunks.len(), 3);
        assert!(matches!(packet.chunks[0], Chunk::Sack(_)));
        assert!(matches!(packet.chunks[1], Chunk::Data(_)));
        assert!(matches!(packet.chunks[2], Chunk::Data(_)));

        if let Chunk::Sack(sack) = &packet.chunks[0] {
            assert_eq!(sack.cumulative_tsn_ack, Tsn(999));
        }
        if let Chunk::Data(data) = &packet.chunks[1] {
            assert_eq!(data.tsn, Tsn(123));
        }
        if let Chunk::Data(data) = &packet.chunks[2] {
            assert_eq!(data.tsn, Tsn(124));
        }
    }

    #[test]
    fn parse_abort_with_empty_cause() {
        let options = Options::default();
        let bytes = SctpPacketBuilder::new(
            VERIFICATION_TAG,
            options.local_port,
            options.remote_port,
            options.mtu,
        )
        .add(&Chunk::Abort(AbortChunk {
            error_causes: vec![ErrorCause::UserInitiatedAbort(UserInitiatedAbortErrorCause {
                reason: "".to_string(),
            })],
        }))
        .build();

        let packet = SctpPacket::from_bytes(&bytes, &Default::default()).unwrap();
        assert_eq!(packet.chunks.len(), 1);
        let Chunk::Abort(abort) = &packet.chunks[0] else {
            panic!();
        };
        assert_eq!(abort.error_causes.len(), 1);
        let ErrorCause::UserInitiatedAbort(reason) = &abort.error_causes[0] else {
            panic!();
        };
        assert_eq!(reason.reason, "");
    }

    #[test]
    fn detect_packet_with_zero_size_chunk() {
        let bytes: &[u8] = &[
            0xff, 0xff, 0xff, 0xff, 0xff, 0x0a, 0x0a, 0x0a, 0x5c, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a,
            0x00, 0x00, 0x00,
        ];

        let packet = SctpPacket::from_bytes(bytes, &Options::default());
        assert!(packet.is_err());
    }

    #[test]
    fn returns_correct_space_available_to_stay_within_mtu() {
        // Chunks will be padded to an even 4 bytes, so the maximum packet size should be rounded
        // down.
        const MTU: usize = 1191;
        const SCTP_PACKET_HEADER_SIZE: usize = 12;
        const MAX_PACKET_SIZE: usize = round_down_to_4!(MTU);

        let options = Options { mtu: MTU, ..Default::default() };

        let mut builder = SctpPacketBuilder::new(
            VERIFICATION_TAG,
            options.local_port,
            options.remote_port,
            options.mtu,
        );

        assert_eq!(builder.bytes_remaining(), MAX_PACKET_SIZE - SCTP_PACKET_HEADER_SIZE);

        // Add a smaller chunk first.
        let payload = vec![0; 183];
        builder.add(&Chunk::Data(DataChunk {
            tsn: Tsn(1),
            data: Data { payload: payload.clone(), ..Default::default() },
        }));
        let chunk1_size = round_up_to_4!(data_chunk::HEADER_SIZE + payload.len());
        assert_eq!(
            builder.bytes_remaining(),
            MAX_PACKET_SIZE - SCTP_PACKET_HEADER_SIZE - chunk1_size
        );
        assert_eq!(builder.bytes_remaining(), 976);

        let payload = vec![0; 957];
        builder.add(&Chunk::Data(DataChunk {
            tsn: Tsn(2),
            data: Data { payload: payload.clone(), ..Default::default() },
        }));
        let chunk2_size = round_up_to_4!(data_chunk::HEADER_SIZE + payload.len());
        assert_eq!(
            builder.bytes_remaining(),
            MAX_PACKET_SIZE - SCTP_PACKET_HEADER_SIZE - chunk1_size - chunk2_size
        );
        assert_eq!(builder.bytes_remaining(), 0);
    }

    #[test]
    fn accepts_zero_set_zero_checksum() {
        // Stream Control Transmission Protocol, Src Port: 5000 (5000),
        //   Dst Port: 5000 (5000)
        //     Source port: 5000
        //     Destination port: 5000
        //     Verification tag: 0x0eddca08
        //     [Association index: 1]
        //     Checksum: 0x00000000 [unverified]
        //     [Checksum Status: Unverified]
        //     SACK chunk (Cumulative TSN: 1426601536, a_rwnd: 131072,
        //       gaps: 0, duplicate TSNs: 0)
        //         Chunk type: SACK (3)
        //         Chunk flags: 0x00
        //         Chunk length: 16
        //         Cumulative TSN ACK: 1426601536
        //         Advertised receiver window credit (a_rwnd): 131072
        //         Number of gap acknowledgement blocks: 0
        //         Number of duplicated TSNs: 0
        let bytes: &[u8] = &[
            0x13, 0x88, 0x13, 0x88, 0x0e, 0xdd, 0xca, 0x08, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00,
            0x00, 0x10, 0x55, 0x08, 0x36, 0x40, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let options = Options {
            disable_checksum_verification: false,
            zero_checksum_alternate_error_detection_method:
                ZERO_CHECKSUM_ALTERNATE_ERROR_DETECTION_METHOD_LOWER_LAYER_DTLS,
            ..Default::default()
        };
        let packet = SctpPacket::from_bytes(bytes, &options).unwrap();

        assert_eq!(packet.common_header.source_port, 5000);
        assert_eq!(packet.common_header.destination_port, 5000);
        assert_eq!(packet.common_header.verification_tag, 0x0eddca08);
        assert_eq!(packet.common_header.checksum, 0x00000000);
    }

    #[test]
    fn rejects_non_zero_incorrect_checksum_when_zero_checksum_is_active() {
        // Stream Control Transmission Protocol, Src Port: 5000 (5000),
        //   Dst Port: 5000 (5000)
        //     Source port: 5000
        //     Destination port: 5000
        //     Verification tag: 0x0eddca08
        //     [Association index: 1]
        //     Checksum: 0x00000001 [unverified]
        //     [Checksum Status: Unverified]
        //     SACK chunk (Cumulative TSN: 1426601536, a_rwnd: 131072,
        //       gaps: 0, duplicate TSNs: 0)
        //         Chunk type: SACK (3)
        //         Chunk flags: 0x00
        //         Chunk length: 16
        //         Cumulative TSN ACK: 1426601536
        //         Advertised receiver window credit (a_rwnd): 131072
        //         Number of gap acknowledgement blocks: 0
        //         Number of duplicated TSNs: 0
        let bytes: &[u8] = &[
            0x13, 0x88, 0x13, 0x88, 0x0e, 0xdd, 0xca, 0x08, 0x01, 0x00, 0x00, 0x00, 0x03, 0x00,
            0x00, 0x10, 0x55, 0x08, 0x36, 0x40, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let options = Options {
            disable_checksum_verification: false,
            zero_checksum_alternate_error_detection_method:
                ZERO_CHECKSUM_ALTERNATE_ERROR_DETECTION_METHOD_LOWER_LAYER_DTLS,
            ..Default::default()
        };
        assert!(SctpPacket::from_bytes(bytes, &options).is_err());
    }

    #[test]
    fn write_packet_with_calculated_checksum() {
        let options = Options::default();
        let mut b = SctpPacketBuilder::new(
            VERIFICATION_TAG,
            options.local_port,
            options.remote_port,
            options.mtu,
        );
        b.add(&Chunk::Sack(SackChunk {
            cumulative_tsn_ack: Tsn(999),
            a_rwnd: 456,
            gap_ack_blocks: vec![],
            duplicate_tsns: vec![],
        }));

        let bytes: &[u8] = &[
            0x13, 0x88, 0x13, 0x88, 0x12, 0x34, 0x56, 0x78, //
            0x07, 0xe8, 0x38, 0x77, // checksum
            0x03, 0x00, 0x00, 0x10, 0x00, 0x00, 0x03, 0xe7, 0x00, 0x00, 0x01, 0xc8, 0x00, 0x00,
            0x00, 0x00,
        ];
        assert_eq!(b.build(), bytes);
    }

    #[test]
    fn write_packet_with_zero_checksum() {
        let options = Options::default();
        let mut b = SctpPacketBuilder::new(
            VERIFICATION_TAG,
            options.local_port,
            options.remote_port,
            options.mtu,
        );
        b.write_checksum(false);
        b.add(&Chunk::Sack(SackChunk {
            cumulative_tsn_ack: Tsn(999),
            a_rwnd: 456,
            gap_ack_blocks: vec![],
            duplicate_tsns: vec![],
        }));

        let bytes: &[u8] = &[
            0x13, 0x88, 0x13, 0x88, 0x12, 0x34, 0x56, 0x78, //
            0x00, 0x00, 0x00, 0x00, // checksum
            0x03, 0x00, 0x00, 0x10, 0x00, 0x00, 0x03, 0xe7, 0x00, 0x00, 0x01, 0xc8, 0x00, 0x00,
            0x00, 0x00,
        ];
        assert_eq!(b.build(), bytes);
    }
}
