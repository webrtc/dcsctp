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
use crate::types::Ssn;
use crate::types::Tsn;
use anyhow::ensure;
use anyhow::Error;
use std::fmt;

pub(crate) const CHUNK_TYPE: u8 = 192;

/// Forward TSN chunk
///
/// See <https://datatracker.ietf.org/doc/html/rfc3758#section-3.2>.
///
/// ```txt
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   Type = 192  |  Flags = 0x00 |        Length = Variable      |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                      New Cumulative TSN                       |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |         Stream-1              |       Stream Sequence-1       |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// \                                                               /
/// /                                                               \
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |         Stream-N              |       Stream Sequence-N       |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug)]
pub struct ForwardTsnChunk {
    pub new_cumulative_tsn: Tsn,
    pub skipped_streams: Vec<SkippedStream>,
}

impl TryFrom<RawChunk<'_>> for ForwardTsnChunk {
    type Error = Error;

    fn try_from(raw: RawChunk<'_>) -> Result<Self, Error> {
        ensure!(raw.typ == CHUNK_TYPE, ChunkParseError::InvalidType);
        ensure!(raw.value.len() >= 4 && (raw.value.len() % 4) == 0, ChunkParseError::InvalidLength);

        let new_cumulative_tsn = Tsn(read_u32_be!(&raw.value[0..4]));
        let num_skipped = (raw.value.len() - 4) / 4;

        let mut skipped_streams = Vec::<SkippedStream>::with_capacity(num_skipped);
        let mut offset = 4;
        for _ in 0..num_skipped {
            let stream_id = StreamId(read_u16_be!(&raw.value[offset..offset + 2]));
            let ssn = Ssn(read_u16_be!(&raw.value[offset + 2..offset + 4]));
            skipped_streams.push(SkippedStream::ForwardTsn(stream_id, ssn));
            offset += 4;
        }

        Ok(Self { new_cumulative_tsn, skipped_streams })
    }
}

impl SerializableTlv for ForwardTsnChunk {
    fn serialize_to(&self, output: &mut [u8]) {
        let value = write_chunk_header(CHUNK_TYPE, 0, self.value_size(), output);
        write_u32_be!(&mut value[0..4], self.new_cumulative_tsn.0);

        let mut offset = 4;
        for skipped in &self.skipped_streams {
            match skipped {
                SkippedStream::ForwardTsn(stream_id, ssn) => {
                    write_u16_be!(&mut value[offset..offset + 2], stream_id.0);
                    write_u16_be!(&mut value[offset + 2..offset + 4], ssn.0);
                }
                _ => panic!("Unsupported skipped stream"),
            }
            offset += 4;
        }
    }

    fn value_size(&self) -> usize {
        4 + self.skipped_streams.len() * 4
    }
}

impl fmt::Display for ForwardTsnChunk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FORWARD-TSN, new_cumulative_tsn={}", self.new_cumulative_tsn)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_capture() {
        // FORWARD_TSN chunk(Cumulative TSN: 1905748778)
        //     Chunk type: FORWARD_TSN (192)
        //     Chunk flags: 0x00
        //     Chunk length: 8
        //     New cumulative TSN: 1905748778
        const BYTES: &[u8] = &[0xc0, 0x00, 0x00, 0x08, 0x71, 0x97, 0x6b, 0x2a];
        let c = ForwardTsnChunk::try_from(RawChunk::from_bytes(BYTES).unwrap().0).unwrap();
        assert_eq!(c.new_cumulative_tsn, Tsn(1905748778));
    }

    #[test]
    fn serialize_and_deserialize() {
        let chunk = ForwardTsnChunk {
            new_cumulative_tsn: Tsn(123),
            skipped_streams: vec![
                SkippedStream::ForwardTsn(StreamId(1), Ssn(23)),
                SkippedStream::ForwardTsn(StreamId(42), Ssn(99)),
            ],
        };

        let mut serialized = vec![0; chunk.serialized_size()];
        chunk.serialize_to(&mut serialized);

        let deserialized =
            ForwardTsnChunk::try_from(RawChunk::from_bytes(&serialized).unwrap().0).unwrap();

        assert_eq!(deserialized.new_cumulative_tsn, Tsn(123));
        assert_eq!(deserialized.skipped_streams.len(), 2);
        assert_eq!(
            deserialized.skipped_streams[0],
            SkippedStream::ForwardTsn(StreamId(1), Ssn(23))
        );
        assert_eq!(
            deserialized.skipped_streams[1],
            SkippedStream::ForwardTsn(StreamId(42), Ssn(99))
        );

        assert_eq!(deserialized.to_string(), "FORWARD-TSN, new_cumulative_tsn=123");
    }
}
