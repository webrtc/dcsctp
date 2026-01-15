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
use crate::types::Ssn;
use crate::types::StreamKey;
use crate::types::Tsn;
use anyhow::Error;
use anyhow::ensure;
use std::fmt;

pub(crate) const CHUNK_TYPE: u8 = 0;

// The size of the DATA chunk header.
pub(crate) const HEADER_SIZE: usize = 16;

/// Payload Data (DATA) chunk
///
/// See <https://datatracker.ietf.org/doc/html/rfc9260#section-3.3.1>.
///
/// ```txt
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   Type = 0    |  Res  |I|U|B|E|            Length             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                              TSN                              |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |      Stream Identifier S      |   Stream Sequence Number n    |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                  Payload Protocol Identifier                  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// \                                                               \
/// /                 User Data (seq n of Stream S)                 /
/// \                                                               \
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug)]
pub struct DataChunk {
    pub tsn: Tsn,
    pub data: Data,
}

const FLAGS_BIT_END: i8 = 0;
const FLAGS_BIT_BEGINNING: i8 = 1;
const FLAGS_BIT_UNORDERED: i8 = 2;

impl TryFrom<RawChunk<'_>> for DataChunk {
    type Error = Error;

    fn try_from(raw: RawChunk<'_>) -> Result<Self, Error> {
        ensure!(raw.typ == CHUNK_TYPE, ChunkParseError::InvalidType);
        ensure!(raw.value.len() > 12, ChunkParseError::InvalidLength);

        let tsn = Tsn(read_u32_be!(&raw.value[0..4]));
        let is_unordered = raw.flags & (1 << FLAGS_BIT_UNORDERED) != 0;
        let stream_key = StreamKey::new(is_unordered, StreamId(read_u16_be!(&raw.value[4..6])));
        let data = Data {
            stream_key,
            ssn: Ssn(read_u16_be!(&raw.value[6..8])),
            ppid: PpId(read_u32_be!(&raw.value[8..12])),
            payload: raw.value[12..].to_vec(),
            is_beginning: (raw.flags & (1 << FLAGS_BIT_BEGINNING)) != 0,
            is_end: (raw.flags & (1 << FLAGS_BIT_END)) != 0,
            ..Default::default()
        };

        Ok(Self { tsn, data })
    }
}

impl SerializableTlv for DataChunk {
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
        write_u32_be!(&mut value[0..4], self.tsn.0);
        write_u16_be!(&mut value[4..6], self.data.stream_key.id().0);
        write_u16_be!(&mut value[6..8], self.data.ssn.0);
        write_u32_be!(&mut value[8..12], self.data.ppid.0);
        value[12..].copy_from_slice(&self.data.payload);
    }

    fn value_size(&self) -> usize {
        12 + self.data.payload.len()
    }
}

impl fmt::Display for DataChunk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DATA, type={}::{}, tsn={}, sid={}, ssn={}, ppid={}, length={}",
            match self.data.stream_key {
                StreamKey::Ordered(_) => "ordered",
                StreamKey::Unordered(_) => "unordered",
            },
            match (self.data.is_beginning, self.data.is_end) {
                (true, true) => "complete",
                (true, false) => "first",
                (false, true) => "last",
                (false, false) => "middle",
            },
            self.tsn,
            self.data.stream_key.id(),
            self.data.ssn,
            self.data.ppid,
            self.data.payload.len()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_capture() {
        // DATA chunk(ordered, complete segment, TSN: 1426601532, SID: 2, SSN: 1,
        //   PPID: 53, payload length: 4 bytes)
        //     Chunk type: DATA (0)
        //     Chunk flags: 0x03
        //     Chunk length: 20
        //     Transmission sequence number: 1426601532
        //     Stream identifier: 0x0002
        //     Stream sequence number: 1
        //     Payload protocol identifier: WebRTC Binary (53)
        const BYTES: &[u8] = &[
            0x00, 0x03, 0x00, 0x14, 0x55, 0x08, 0x36, 0x3c, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x35, 0x00, 0x01, 0x02, 0x03,
        ];
        let c = DataChunk::try_from(RawChunk::from_bytes(BYTES).unwrap().0).unwrap();
        assert_eq!(c.tsn, Tsn(1426601532));
        assert_eq!(c.data.stream_key, StreamKey::Ordered(StreamId(2)));
        assert_eq!(c.data.ssn, Ssn(1));
        assert_eq!(c.data.ppid, PpId(53));
        assert!(c.data.is_beginning);
        assert!(c.data.is_end);
        assert_eq!(c.data.payload, vec![0, 1, 2, 3]);
    }

    #[test]
    fn serialize_and_deserialize() {
        let chunk = DataChunk {
            tsn: Tsn(123),
            data: Data {
                stream_key: StreamKey::Ordered(StreamId(456)),
                ssn: Ssn(789),
                ppid: PpId(9090),
                payload: vec![1, 2, 3, 4, 5],
                ..Default::default()
            },
        };
        let mut serialized = vec![0; chunk.serialized_size()];
        chunk.serialize_to(&mut serialized);

        let deserialized =
            DataChunk::try_from(RawChunk::from_bytes(&serialized).unwrap().0).unwrap();
        assert_eq!(deserialized.tsn, Tsn(123));
        assert_eq!(deserialized.data.stream_key, StreamKey::Ordered(StreamId(456)));
        assert_eq!(deserialized.data.ssn, Ssn(789));
        assert_eq!(deserialized.data.ppid, PpId(9090));
        assert_eq!(deserialized.data.payload, vec![1, 2, 3, 4, 5]);

        assert_eq!(
            deserialized.to_string(),
            "DATA, type=ordered::middle, tsn=123, sid=456, ssn=789, ppid=9090, length=5"
        );
    }
}
