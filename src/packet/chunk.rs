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

use crate::math::round_up_to_4;
use crate::packet::AsSerializableTlv;
use crate::packet::ChunkParseError;
use crate::packet::SerializableTlv;
use crate::packet::TLV_HEADER_SIZE;
use crate::packet::abort_chunk;
use crate::packet::abort_chunk::AbortChunk;
use crate::packet::cookie_ack_chunk;
use crate::packet::cookie_ack_chunk::CookieAckChunk;
use crate::packet::cookie_echo_chunk;
use crate::packet::cookie_echo_chunk::CookieEchoChunk;
use crate::packet::data_chunk;
use crate::packet::data_chunk::DataChunk;
use crate::packet::ensure;
use crate::packet::error_chunk;
use crate::packet::error_chunk::ErrorChunk;
use crate::packet::forward_tsn_chunk;
use crate::packet::forward_tsn_chunk::ForwardTsnChunk;
use crate::packet::heartbeat_ack_chunk;
use crate::packet::heartbeat_ack_chunk::HeartbeatAckChunk;
use crate::packet::heartbeat_request_chunk;
use crate::packet::heartbeat_request_chunk::HeartbeatRequestChunk;
use crate::packet::idata_chunk;
use crate::packet::idata_chunk::IDataChunk;
use crate::packet::iforward_tsn_chunk;
use crate::packet::iforward_tsn_chunk::IForwardTsnChunk;
use crate::packet::init_ack_chunk;
use crate::packet::init_ack_chunk::InitAckChunk;
use crate::packet::init_chunk;
use crate::packet::init_chunk::InitChunk;
use crate::packet::re_config_chunk;
use crate::packet::re_config_chunk::ReConfigChunk;
use crate::packet::read_u16_be;
use crate::packet::sack_chunk;
use crate::packet::sack_chunk::SackChunk;
use crate::packet::shutdown_ack_chunk;
use crate::packet::shutdown_ack_chunk::ShutdownAckChunk;
use crate::packet::shutdown_chunk;
use crate::packet::shutdown_chunk::ShutdownChunk;
use crate::packet::shutdown_complete_chunk;
use crate::packet::shutdown_complete_chunk::ShutdownCompleteChunk;
use crate::packet::unknown_chunk::UnknownChunk;
use crate::packet::write_u16_be;
use std::cmp;

/// Intermediate representation of a chunk for which the type hasn't been fully discriminated, see
/// <https://datatracker.ietf.org/doc/html/rfc9260#section-3.2>.
///
/// ```txt
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  Chunk Type   |  Chunk Flags  |         Chunk Length          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// \                                                               \
/// /                          Chunk Value                          /
/// \                                                               \
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug)]
pub(crate) struct RawChunk<'a> {
    pub(crate) typ: u8,
    pub(crate) flags: u8,
    pub(crate) value: &'a [u8],
}

impl<'a> RawChunk<'a> {
    /// Reads a chunk from `bytes` and returns a raw representation of the frame and the remaining
    /// data that was not consumed when reading this chunk.
    pub(crate) fn from_bytes(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), ChunkParseError> {
        ensure!(bytes.len() >= TLV_HEADER_SIZE, ChunkParseError::InvalidLength);

        let length = read_u16_be!(&bytes[2..4]) as usize;
        ensure!(length >= TLV_HEADER_SIZE && length <= bytes.len(), ChunkParseError::InvalidLength);

        let padded_length = round_up_to_4!(length);
        let end_offset = cmp::min(padded_length, bytes.len());

        Ok((
            Self { typ: bytes[0], flags: bytes[1], value: &bytes[TLV_HEADER_SIZE..length] },
            &bytes[end_offset..],
        ))
    }
}

/// Writes a chunk header with the provided arguments and returns the remaining part of the chunk
/// (its value) that may be filled in by the caller with additional data.
#[inline]
pub fn write_chunk_header(typ: u8, flags: u8, value_size: usize, output: &mut [u8]) -> &mut [u8] {
    let serialized_size = TLV_HEADER_SIZE + value_size;
    assert!(output.len() >= serialized_size);
    output[0] = typ;
    output[1] = flags;
    write_u16_be!(&mut output[2..4], serialized_size as u16);
    &mut output[TLV_HEADER_SIZE..serialized_size]
}

/// Enumerating all supported (and unknown) chunks.
#[derive(Debug)]
pub enum Chunk {
    Data(DataChunk),
    Init(InitChunk),
    InitAck(InitAckChunk),
    Sack(SackChunk),
    HeartbeatRequest(HeartbeatRequestChunk),
    HeartbeatAck(HeartbeatAckChunk),
    Abort(AbortChunk),
    Shutdown(ShutdownChunk),
    ShutdownAck(ShutdownAckChunk),
    Error(ErrorChunk),
    CookieEcho(CookieEchoChunk),
    CookieAck(CookieAckChunk),
    ShutdownComplete(ShutdownCompleteChunk),
    ReConfig(ReConfigChunk),
    ForwardTsn(ForwardTsnChunk),
    IData(IDataChunk),
    IForwardTsn(IForwardTsnChunk),
    Unknown(UnknownChunk),
}

impl TryFrom<RawChunk<'_>> for Chunk {
    type Error = ChunkParseError;

    fn try_from(raw: RawChunk<'_>) -> Result<Self, ChunkParseError> {
        match raw.typ {
            data_chunk::CHUNK_TYPE => DataChunk::try_from(raw).map(Chunk::Data),
            init_chunk::CHUNK_TYPE => InitChunk::try_from(raw).map(Chunk::Init),
            init_ack_chunk::CHUNK_TYPE => InitAckChunk::try_from(raw).map(Chunk::InitAck),
            sack_chunk::CHUNK_TYPE => SackChunk::try_from(raw).map(Chunk::Sack),
            heartbeat_request_chunk::CHUNK_TYPE => {
                HeartbeatRequestChunk::try_from(raw).map(Chunk::HeartbeatRequest)
            }
            heartbeat_ack_chunk::CHUNK_TYPE => {
                HeartbeatAckChunk::try_from(raw).map(Chunk::HeartbeatAck)
            }
            abort_chunk::CHUNK_TYPE => AbortChunk::try_from(raw).map(Chunk::Abort),
            shutdown_chunk::CHUNK_TYPE => ShutdownChunk::try_from(raw).map(Chunk::Shutdown),
            shutdown_ack_chunk::CHUNK_TYPE => {
                ShutdownAckChunk::try_from(raw).map(Chunk::ShutdownAck)
            }
            error_chunk::CHUNK_TYPE => ErrorChunk::try_from(raw).map(Chunk::Error),
            cookie_echo_chunk::CHUNK_TYPE => CookieEchoChunk::try_from(raw).map(Chunk::CookieEcho),
            cookie_ack_chunk::CHUNK_TYPE => CookieAckChunk::try_from(raw).map(Chunk::CookieAck),
            shutdown_complete_chunk::CHUNK_TYPE => {
                ShutdownCompleteChunk::try_from(raw).map(Chunk::ShutdownComplete)
            }
            re_config_chunk::CHUNK_TYPE => ReConfigChunk::try_from(raw).map(Chunk::ReConfig),
            forward_tsn_chunk::CHUNK_TYPE => ForwardTsnChunk::try_from(raw).map(Chunk::ForwardTsn),
            idata_chunk::CHUNK_TYPE => IDataChunk::try_from(raw).map(Chunk::IData),
            iforward_tsn_chunk::CHUNK_TYPE => {
                IForwardTsnChunk::try_from(raw).map(Chunk::IForwardTsn)
            }
            _ => UnknownChunk::try_from(raw).map(Chunk::Unknown),
        }
    }
}

impl AsSerializableTlv for Chunk {
    fn as_serializable(&self) -> &dyn SerializableTlv {
        match self {
            Chunk::Data(s) => s,
            Chunk::Init(s) => s,
            Chunk::InitAck(s) => s,
            Chunk::Sack(s) => s,
            Chunk::HeartbeatRequest(s) => s,
            Chunk::HeartbeatAck(s) => s,
            Chunk::Abort(s) => s,
            Chunk::Shutdown(s) => s,
            Chunk::ShutdownAck(s) => s,
            Chunk::Error(s) => s,
            Chunk::CookieEcho(s) => s,
            Chunk::CookieAck(s) => s,
            Chunk::ShutdownComplete(s) => s,
            Chunk::ReConfig(s) => s,
            Chunk::ForwardTsn(s) => s,
            Chunk::IData(s) => s,
            Chunk::IForwardTsn(s) => s,
            Chunk::Unknown(s) => s,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::read_u32_be;
    use crate::packet::write_u32_be;

    // A test chunk that has a single u32 in its header, following the common chunk header.
    #[derive(Debug)]
    pub(crate) struct TestChunk {
        additional_data: u32,
    }
    const CHUNK_TYPE: u8 = 0x42;

    impl TryFrom<RawChunk<'_>> for TestChunk {
        type Error = ChunkParseError;

        fn try_from(raw: RawChunk<'_>) -> Result<Self, ChunkParseError> {
            ensure!(raw.typ == CHUNK_TYPE, ChunkParseError::InvalidType);
            ensure!(raw.value.len() == 4, ChunkParseError::InvalidLength);

            Ok(TestChunk { additional_data: read_u32_be!(&raw.value[0..4]) })
        }
    }

    impl SerializableTlv for TestChunk {
        fn serialize_to(&self, output: &mut [u8]) {
            let value = write_chunk_header(CHUNK_TYPE, 0, self.value_size(), output);
            write_u32_be!(&mut value[0..4], self.additional_data);
        }

        fn value_size(&self) -> usize {
            4
        }
    }

    #[test]
    fn parse_success() {
        const BYTES: &[u8] = &[0x42, 0x00, 0x00, 0x08, 0x01, 0x02, 0x03, 0x04];
        let desc = RawChunk::from_bytes(BYTES).unwrap().0;
        let parsed = TestChunk::try_from(desc).unwrap();
        assert_eq!(parsed.additional_data, 0x01020304);
    }

    #[test]
    fn serialize() {
        let chunk = TestChunk { additional_data: 31337 };
        assert_eq!(chunk.serialized_size(), 8);
        let mut output = vec![0; chunk.serialized_size()];
        chunk.serialize_to(&mut output);

        assert_eq!(output, &[0x42, 0x00, 0x00, 0x08, 0x00, 0x00, 0x7a, 0x69]);
    }

    #[test]
    fn parse_insufficient_size() {
        const BYTES: &[u8] = &[0x42, 0x00, 0x00];
        assert_eq!(RawChunk::from_bytes(BYTES).unwrap_err(), ChunkParseError::InvalidLength);
    }

    #[test]
    fn parse_invalid_type() {
        const BYTES: &[u8] = &[0x41, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(
            TestChunk::try_from(RawChunk::from_bytes(BYTES).unwrap().0).unwrap_err(),
            ChunkParseError::InvalidType,
        );
    }

    #[test]
    fn parse_invalid_length() {
        const BYTES: &[u8] = &[0x42, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(
            TestChunk::try_from(RawChunk::from_bytes(BYTES).unwrap().0).unwrap_err(),
            ChunkParseError::InvalidLength,
        );
    }

    #[test]
    fn parse_multiple_chunks() {
        // COOKIE_ACK chunk
        //     Chunk type: COOKIE_ACK (11)
        //     Chunk flags: 0x00
        //     Chunk length: 4
        // DATA chunk (ordered,
        //             complete segment,
        //             TSN: 3479146723,
        //             SID: 111,
        //             SSN: 0,
        //             PPID: 50,
        //             payload length: 41 bytes)
        //     Chunk type: DATA (0)
        //     Chunk flags: 0x03
        //     Chunk length: 57
        //     Transmission sequence number (absolute): 3479146723
        //     Stream identifier: 0x006f
        //     Stream sequence number: 0
        //     Payload protocol identifier: WebRTC Control (50)
        //     Chunk padding: 000000
        const BYTES: &[u8] = &[
            0x0b, 0x00, 0x00, 0x04, 0x00, 0x03, 0x00, 0x39, 0xcf, 0x5f, 0x90, 0xe3, 0x00, 0x6f,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x32, 0x03, 0x82, 0x00, 0x00, 0x00, 0x00, 0x9c, 0x40,
            0x00, 0x0b, 0x00, 0x12, 0x63, 0x6f, 0x6c, 0x6c, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e,
            0x73, 0x77, 0x65, 0x62, 0x72, 0x74, 0x63, 0x2d, 0x64, 0x61, 0x74, 0x61, 0x63, 0x68,
            0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x00, 0x00, 0x00,
        ];
        const DATA_HEADER_SIZE: usize = 16;
        let (chunk, remaining) = RawChunk::from_bytes(BYTES).unwrap();
        assert_eq!(chunk.typ, 0x0b);
        assert!(chunk.value.is_empty());
        assert_eq!(remaining.len(), round_up_to_4!(DATA_HEADER_SIZE + 41));

        let (chunk, remaining) = RawChunk::from_bytes(remaining).unwrap();
        assert_eq!(chunk.typ, 0x00);
        assert_eq!(chunk.value.len(), DATA_HEADER_SIZE - TLV_HEADER_SIZE + 41);
        assert!(remaining.is_empty());
    }

    #[test]
    fn serialize_parsed_chunks() {
        // COOKIE_ACK chunk
        //     Chunk type: COOKIE_ACK (11)
        //     Chunk flags: 0x00
        //     Chunk length: 4
        // DATA chunk (ordered,
        //             complete segment,
        //             TSN: 3479146723,
        //             SID: 111,
        //             SSN: 0,
        //             PPID: 50,
        //             payload length: 41 bytes)
        //     Chunk type: DATA (0)
        //     Chunk flags: 0x03
        //     Chunk length: 57
        //     Transmission sequence number (absolute): 3479146723
        //     Stream identifier: 0x006f
        //     Stream sequence number: 0
        //     Payload protocol identifier: WebRTC Control (50)
        //     Chunk padding: 000000
        const BYTES: &[u8] = &[
            0x0b, 0x00, 0x00, 0x04, 0x00, 0x03, 0x00, 0x39, 0xcf, 0x5f, 0x90, 0xe3, 0x00, 0x6f,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x32, 0x03, 0x82, 0x00, 0x00, 0x00, 0x00, 0x9c, 0x40,
            0x00, 0x0b, 0x00, 0x12, 0x63, 0x6f, 0x6c, 0x6c, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e,
            0x73, 0x77, 0x65, 0x62, 0x72, 0x74, 0x63, 0x2d, 0x64, 0x61, 0x74, 0x61, 0x63, 0x68,
            0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x00, 0x00, 0x00,
        ];
        const DATA_HEADER_SIZE: usize = 16;
        let (raw_chunk, remaining) = RawChunk::from_bytes(BYTES).unwrap();
        let chunk = Chunk::try_from(raw_chunk).unwrap();
        assert!(matches!(chunk, Chunk::CookieAck { .. }));
        assert_eq!(chunk.as_serializable().serialized_size(), 4);
        let mut data1 = vec![0; 4];
        chunk.as_serializable().serialize_to(&mut data1);
        assert_eq!(data1, BYTES[0..4]);

        let (raw_chunk, _remaining) = RawChunk::from_bytes(remaining).unwrap();
        let chunk = Chunk::try_from(raw_chunk).unwrap();
        assert!(matches!(chunk, Chunk::Data { .. }));
        assert_eq!(chunk.as_serializable().serialized_size(), 57);
        let mut data2 = vec![0; 57];
        chunk.as_serializable().serialize_to(&mut data2);
        assert_eq!(data2, BYTES[4..4 + 57]);
    }
}
