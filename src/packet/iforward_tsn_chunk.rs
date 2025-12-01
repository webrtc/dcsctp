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

use crate::api::StreamId;
use crate::packet::chunk::write_chunk_header;
use crate::packet::chunk::RawChunk;
use crate::packet::read_u16_be;
use crate::packet::read_u32_be;
use crate::packet::write_u16_be;
use crate::packet::write_u32_be;
use crate::packet::ChunkParseError;
use crate::packet::SerializableTlv;
use crate::packet::SkippedStream;
use crate::types::Mid;
use crate::types::StreamKey;
use crate::types::Tsn;
use anyhow::ensure;
use anyhow::Error;
use std::fmt;

pub(crate) const CHUNK_TYPE: u8 = 194;

/// I-FORWARD-TSN chunk
///
/// See <https://datatracker.ietf.org/doc/html/rfc8260#section-2.3.1>.
///
/// ```txt
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   Type = 194  | Flags = 0x00  |      Length = Variable        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                       New Cumulative TSN                      |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |       Stream Identifier       |          Reserved           |U|
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                       Message Identifier                      |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// \                                                               \
/// /                                                               /
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |       Stream Identifier       |          Reserved           |U|
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                       Message Identifier                      |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug)]
pub struct IForwardTsnChunk {
    pub new_cumulative_tsn: Tsn,
    pub skipped_streams: Vec<SkippedStream>,
}

impl TryFrom<RawChunk<'_>> for IForwardTsnChunk {
    type Error = Error;

    fn try_from(raw: RawChunk<'_>) -> Result<Self, Error> {
        ensure!(raw.typ == CHUNK_TYPE, ChunkParseError::InvalidType);
        ensure!(
            raw.value.len() >= 4 && (raw.value.len() - 4).is_multiple_of(8),
            ChunkParseError::InvalidLength
        );

        let new_cumulative_tsn = Tsn(read_u32_be!(&raw.value[0..4]));

        let skipped_streams = raw.value[4..]
            .chunks_exact(8)
            .map(|c| {
                let stream_id = StreamId(read_u16_be!(&c[0..2]));
                let is_unordered = (c[3] & 1) != 0;
                let mid = Mid(read_u32_be!(&c[4..8]));
                SkippedStream::IForwardTsn(StreamKey::from(is_unordered, stream_id), mid)
            })
            .collect();

        Ok(Self { new_cumulative_tsn, skipped_streams })
    }
}

impl SerializableTlv for IForwardTsnChunk {
    fn serialize_to(&self, output: &mut [u8]) {
        let value = write_chunk_header(CHUNK_TYPE, 0, self.value_size(), output);
        write_u32_be!(&mut value[0..4], self.new_cumulative_tsn.0);

        let mut chunks = value[4..].chunks_exact_mut(8);
        for (skipped, chunk) in self.skipped_streams.iter().zip(&mut chunks) {
            match skipped {
                SkippedStream::IForwardTsn(stream_key, mid) => {
                    write_u16_be!(&mut chunk[0..2], stream_key.id().0);
                    chunk[2] = 0;
                    chunk[3] = if stream_key.is_unordered() { 1 } else { 0 };
                    write_u32_be!(&mut chunk[4..8], mid.0);
                }
                _ => panic!("Unsupported skipped stream"),
            }
        }
    }

    fn value_size(&self) -> usize {
        4 + self.skipped_streams.len() * 8
    }
}

impl fmt::Display for IForwardTsnChunk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "I-FORWARD-TSN, new_cumulative_tsn={}", self.new_cumulative_tsn)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_capture() {
        // I_FORWARD_TSN chunk(Cumulative TSN: 3094631148)
        //   Chunk type: I_FORWARD_TSN (194)
        //   Chunk flags: 0x00
        //   Chunk length: 16
        //   New cumulative TSN: 3094631148
        //   Stream identifier: 1
        //   Flags: 0x0000
        //   Message identifier: 2
        const BYTES: &[u8] = &[
            0xc2, 0x00, 0x00, 0x10, 0xb8, 0x74, 0x52, 0xec, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x02,
        ];
        let c = IForwardTsnChunk::try_from(RawChunk::from_bytes(BYTES).unwrap().0).unwrap();
        assert_eq!(c.new_cumulative_tsn, Tsn(3094631148));
        assert_eq!(
            c.skipped_streams,
            vec![SkippedStream::IForwardTsn(StreamKey::Ordered(StreamId(1)), Mid(2))]
        );
    }

    #[test]
    fn serialize_and_deserialize() {
        let chunk = IForwardTsnChunk {
            new_cumulative_tsn: Tsn(123),
            skipped_streams: vec![
                SkippedStream::IForwardTsn(StreamKey::Unordered(StreamId(1)), Mid(23)),
                SkippedStream::IForwardTsn(StreamKey::Ordered(StreamId(42)), Mid(99)),
            ],
        };

        let mut serialized = vec![0; chunk.serialized_size()];
        chunk.serialize_to(&mut serialized);

        let deserialized =
            IForwardTsnChunk::try_from(RawChunk::from_bytes(&serialized).unwrap().0).unwrap();

        assert_eq!(deserialized.new_cumulative_tsn, Tsn(123));
        assert_eq!(deserialized.skipped_streams.len(), 2);
        assert_eq!(
            deserialized.skipped_streams[0],
            SkippedStream::IForwardTsn(StreamKey::Unordered(StreamId(1)), Mid(23))
        );
        assert_eq!(
            deserialized.skipped_streams[1],
            SkippedStream::IForwardTsn(StreamKey::Ordered(StreamId(42)), Mid(99))
        );

        assert_eq!(deserialized.to_string(), "I-FORWARD-TSN, new_cumulative_tsn=123");
    }
}
