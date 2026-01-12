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

use crate::api::PpId;
use crate::api::StreamId;
use crate::packet::ChunkParseError;
use crate::packet::SerializableTlv;
use crate::packet::chunk::RawChunk;
use crate::packet::chunk::write_chunk_header;
use crate::packet::data::Data;
use crate::packet::read_u16_be;
use crate::packet::read_u32_be;
use crate::packet::write_u16_be;
use crate::packet::write_u32_be;
use crate::types::Fsn;
use crate::types::Mid;
use crate::types::StreamKey;
use crate::types::Tsn;
use anyhow::Error;
use anyhow::ensure;
use std::fmt;

pub(crate) const CHUNK_TYPE: u8 = 64;

// The size of the I-DATA chunk header.
pub(crate) const HEADER_SIZE: usize = 20;

/// Payload Data supporting Interleaving (I-DATA) chunk
///
/// See <https://datatracker.ietf.org/doc/html/rfc8260#section-2.1>.
///
/// ```txt
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   Type = 64   |  Res  |I|U|B|E|       Length = Variable       |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                              TSN                              |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |        Stream Identifier      |           Reserved            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                      Message Identifier                       |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |    Payload Protocol Identifier / Fragment Sequence Number     |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// \                                                               \
/// /                           User Data                           /
/// \                                                               \
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug)]
pub struct IDataChunk {
    pub tsn: Tsn,
    pub data: Data,
}

const FLAGS_BIT_END: i8 = 0;
const FLAGS_BIT_BEGINNING: i8 = 1;
const FLAGS_BIT_UNORDERED: i8 = 2;

impl TryFrom<RawChunk<'_>> for IDataChunk {
    type Error = Error;

    fn try_from(raw: RawChunk<'_>) -> Result<Self, Error> {
        ensure!(raw.typ == CHUNK_TYPE, ChunkParseError::InvalidType);
        ensure!(raw.value.len() > 16, ChunkParseError::InvalidLength);

        let tsn = Tsn(read_u32_be!(&raw.value[0..4]));
        let ppid_or_fsn = read_u32_be!(&raw.value[12..16]);
        let is_beginning = (raw.flags & (1 << FLAGS_BIT_BEGINNING)) != 0;
        let (ppid, fsn) = match is_beginning {
            true => (ppid_or_fsn, 0),
            false => (0, ppid_or_fsn),
        };
        let stream_id = StreamId(read_u16_be!(&raw.value[4..6]));
        let is_unordered = (raw.flags & (1 << FLAGS_BIT_UNORDERED)) != 0;
        let data = Data {
            stream_key: StreamKey::from(is_unordered, stream_id),
            mid: Mid(read_u32_be!(&raw.value[8..12])),
            ppid: PpId(ppid),
            fsn: Fsn(fsn),
            payload: raw.value[16..].to_vec(),
            is_beginning,
            is_end: (raw.flags & (1 << FLAGS_BIT_END)) != 0,
            ..Default::default()
        };

        Ok(Self { tsn, data })
    }
}

impl SerializableTlv for IDataChunk {
    fn serialize_to(&self, output: &mut [u8]) {
        let mut flags: u8 = 0b0000_0000;
        if self.data.is_end {
            flags |= 1 << FLAGS_BIT_END;
        }
        if self.data.is_beginning {
            flags |= 1 << FLAGS_BIT_BEGINNING;
        }
        if self.data.stream_key.is_unordered() {
            flags |= 1 << FLAGS_BIT_UNORDERED;
        }
        let value = write_chunk_header(CHUNK_TYPE, flags, self.value_size(), output);
        let ppid_or_fsn = match self.data.is_beginning {
            true => self.data.ppid.0,
            false => self.data.fsn.0,
        };
        write_u32_be!(&mut value[0..4], self.tsn.0);
        write_u16_be!(&mut value[4..6], self.data.stream_key.id().0);
        write_u16_be!(&mut value[6..8], 0);
        write_u32_be!(&mut value[8..12], self.data.mid.0);
        write_u32_be!(&mut value[12..16], ppid_or_fsn);
        value[16..].copy_from_slice(&self.data.payload);
    }

    fn value_size(&self) -> usize {
        16 + self.data.payload.len()
    }
}

impl fmt::Display for IDataChunk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "I-DATA, type={}::{}, tsn={}, mid={}, ssn={}, ppid={}, length={}",
            match self.data.stream_key {
                StreamKey::Unordered(_) => "unordered",
                StreamKey::Ordered(_) => "ordered",
            },
            match (self.data.is_beginning, self.data.is_end) {
                (true, true) => "complete",
                (true, false) => "first",
                (false, true) => "last",
                (false, false) => "middle",
            },
            self.tsn,
            self.data.stream_key.id(),
            self.data.mid,
            self.data.ppid,
            self.data.payload.len()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn at_beginning_from_capture() {
        // I_DATA chunk(ordered, first segment, TSN: 2487901653, SID: 1, MID: 0,
        //   payload length: 1180 bytes)
        //     Chunk type: I_DATA (64)
        //     Chunk flags: 0x02
        //     Chunk length: 1200
        //     Transmission sequence number: 2487901653
        //     Stream identifier: 0x0001
        //     Reserved: 0
        //     Message identifier: 0
        //     Payload protocol identifier: WebRTC Binary (53)
        //     Reassembled Message in frame: 39
        const BYTES: &[u8] = &[
            0x40, 0x02, 0x00, 0x15, 0x94, 0x4a, 0x5d, 0xd5, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x35, 0x01, 0x00, 0x00, 0x00,
        ];
        let c = IDataChunk::try_from(RawChunk::from_bytes(BYTES).unwrap().0).unwrap();
        assert_eq!(c.tsn, Tsn(2487901653));
        assert_eq!(c.data.stream_key, StreamKey::Ordered(StreamId(1)));
        assert_eq!(c.data.mid, Mid(0));
        assert_eq!(c.data.ppid, PpId(53));
        assert_eq!(c.data.fsn, Fsn(0));
        assert!(c.data.is_beginning);
        assert!(!c.data.is_end);
        assert_eq!(c.data.payload, vec![1]);
    }

    #[test]
    fn at_beginning_serialize_and_deserialize() {
        let chunk = IDataChunk {
            tsn: Tsn(123),
            data: Data {
                stream_key: StreamKey::Ordered(StreamId(456)),
                mid: Mid(789),
                ppid: PpId(9090),
                payload: vec![1, 2, 3, 4, 5],
                is_beginning: true,
                ..Default::default()
            },
        };
        let mut serialized = vec![0; chunk.serialized_size()];
        chunk.serialize_to(&mut serialized);

        let deserialized =
            IDataChunk::try_from(RawChunk::from_bytes(&serialized).unwrap().0).unwrap();
        assert_eq!(deserialized.tsn, Tsn(123));
        assert_eq!(deserialized.data.stream_key, StreamKey::Ordered(StreamId(456)));
        assert_eq!(deserialized.data.mid, Mid(789));
        assert_eq!(deserialized.data.ppid, PpId(9090));
        assert_eq!(deserialized.data.payload, vec![1, 2, 3, 4, 5]);

        assert_eq!(
            deserialized.to_string(),
            "I-DATA, type=ordered::first, tsn=123, mid=456, ssn=789, ppid=9090, length=5"
        );
    }

    #[test]
    fn in_middle_from_capture() {
        // I_DATA chunk(ordered, last segment, TSN: 2487901706, SID: 3, MID: 1,
        //   FSN: 8, payload length: 560 bytes)
        //     Chunk type: I_DATA (64)
        //     Chunk flags: 0x01
        //     Chunk length: 580
        //     Transmission sequence number: 2487901706
        //     Stream identifier: 0x0003
        //     Reserved: 0
        //     Message identifier: 1
        //     Fragment sequence number: 8
        //     Reassembled SCTP Fragments (10000 bytes, 9 fragments):
        const BYTES: &[u8] = &[
            0x40, 0x01, 0x00, 0x15, 0x94, 0x4a, 0x5e, 0x0a, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00,
        ];
        let c = IDataChunk::try_from(RawChunk::from_bytes(BYTES).unwrap().0).unwrap();
        assert_eq!(c.tsn, Tsn(2487901706));
        assert_eq!(c.data.stream_key, StreamKey::Ordered(StreamId(3)));
        assert_eq!(c.data.mid, Mid(1));
        assert_eq!(c.data.ppid, PpId(0));
        assert_eq!(c.data.fsn, Fsn(8));
        assert!(!c.data.is_beginning);
        assert!(c.data.is_end);
        assert_eq!(c.data.payload, vec![1]);
    }

    #[test]
    fn in_middle_serialize_and_deserialize() {
        let chunk = IDataChunk {
            tsn: Tsn(123),
            data: Data {
                stream_key: StreamKey::Ordered(StreamId(456)),
                mid: Mid(789),
                fsn: Fsn(10),
                payload: vec![1, 2, 3, 4, 5],
                ..Default::default()
            },
        };
        let mut serialized = vec![0; chunk.serialized_size()];
        chunk.serialize_to(&mut serialized);

        let deserialized =
            IDataChunk::try_from(RawChunk::from_bytes(&serialized).unwrap().0).unwrap();
        assert_eq!(deserialized.tsn, Tsn(123));
        assert_eq!(deserialized.data.stream_key, StreamKey::Ordered(StreamId(456)));
        assert_eq!(deserialized.data.mid, Mid(789));
        assert_eq!(deserialized.data.ppid, PpId(0));
        assert_eq!(deserialized.data.fsn, Fsn(10));
        assert_eq!(deserialized.data.payload, vec![1, 2, 3, 4, 5]);

        assert_eq!(
            deserialized.to_string(),
            "I-DATA, type=ordered::middle, tsn=123, mid=456, ssn=789, ppid=0, length=5"
        );
    }
}
