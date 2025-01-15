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

use crate::packet::chunk::write_chunk_header;
use crate::packet::chunk::RawChunk;
use crate::packet::read_u16_be;
use crate::packet::read_u32_be;
use crate::packet::write_u16_be;
use crate::packet::write_u32_be;
use crate::packet::ChunkParseError;
use crate::packet::SerializableTlv;
use crate::types::Tsn;
use anyhow::ensure;
use anyhow::Error;
use std::fmt;

pub(crate) const CHUNK_TYPE: u8 = 3;

/// Selective Acknowledgement (SACK) chunk
///
/// See <https://datatracker.ietf.org/doc/html/rfc9260#section-3.3.4>.
///
/// ```txt
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   Type = 3    |  Chunk Flags  |         Chunk Length          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                      Cumulative TSN Ack                       |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |          Advertised Receiver Window Credit (a_rwnd)           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | Number of Gap Ack Blocks = N  |  Number of Duplicate TSNs = M |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |    Gap Ack Block #1 Start     |     Gap Ack Block #1 End      |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// /                                                               /
/// \                              ...                              \
/// /                                                               /
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |    Gap Ack Block #N Start     |     Gap Ack Block #N End      |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                        Duplicate TSN 1                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// /                                                               /
/// \                              ...                              \
/// /                                                               /
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                        Duplicate TSN M                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Clone, Debug, PartialEq)]
pub struct GapAckBlock {
    pub start: u16,
    pub end: u16,
}

impl GapAckBlock {
    pub fn new(start: u16, end: u16) -> Self {
        Self { start, end }
    }
}

#[derive(Debug)]
pub struct SackChunk {
    pub cumulative_tsn_ack: Tsn,
    pub a_rwnd: u32,
    pub gap_ack_blocks: Vec<GapAckBlock>,
    pub duplicate_tsns: Vec<Tsn>,
}

impl TryFrom<RawChunk<'_>> for SackChunk {
    type Error = Error;

    fn try_from(raw: RawChunk<'_>) -> Result<Self, Error> {
        ensure!(raw.typ == CHUNK_TYPE, ChunkParseError::InvalidType);
        ensure!(raw.value.len() >= 12, ChunkParseError::InvalidLength);

        let cumulative_tsn_ack = Tsn(read_u32_be!(&raw.value[0..4]));
        let a_rwnd = read_u32_be!(&raw.value[4..8]);
        let nbr_of_gap_blocks = read_u16_be!(&raw.value[8..10]) as usize;
        let nbr_of_dup_tsns = read_u16_be!(&raw.value[10..12]) as usize;

        ensure!(
            raw.value.len() == 12 + nbr_of_gap_blocks * 4 + nbr_of_dup_tsns * 4,
            ChunkParseError::InvalidLength
        );

        let mut gap_ack_blocks = Vec::<GapAckBlock>::with_capacity(nbr_of_gap_blocks);
        let mut offset = 12;
        for _ in 0..nbr_of_gap_blocks {
            let start = read_u16_be!(&raw.value[offset..offset + 2]);
            let end = read_u16_be!(&raw.value[offset + 2..offset + 4]);
            gap_ack_blocks.push(GapAckBlock { start, end });
            offset += 4;
        }

        let mut duplicate_tsns = Vec::<Tsn>::with_capacity(nbr_of_dup_tsns);
        for _ in 0..nbr_of_dup_tsns {
            duplicate_tsns.push(Tsn(read_u32_be!(&raw.value[offset..offset + 4])));
            offset += 4;
        }

        Ok(Self { cumulative_tsn_ack, a_rwnd, gap_ack_blocks, duplicate_tsns })
    }
}

impl SerializableTlv for SackChunk {
    fn serialize_to(&self, output: &mut [u8]) {
        let value = write_chunk_header(CHUNK_TYPE, 0, self.value_size(), output);
        write_u32_be!(&mut value[0..4], self.cumulative_tsn_ack.0);
        write_u32_be!(&mut value[4..8], self.a_rwnd);
        write_u16_be!(&mut value[8..10], self.gap_ack_blocks.len() as u16);
        write_u16_be!(&mut value[10..12], self.duplicate_tsns.len() as u16);

        let mut offset = 12;
        for block in &self.gap_ack_blocks {
            write_u16_be!(&mut value[offset..offset + 2], block.start);
            write_u16_be!(&mut value[offset + 2..offset + 4], block.end);
            offset += 4;
        }

        for dup_tsn in &self.duplicate_tsns {
            write_u32_be!(&mut value[offset..offset + 4], dup_tsn.0);
            offset += 4;
        }
    }

    fn value_size(&self) -> usize {
        12 + self.gap_ack_blocks.len() * 4 + self.duplicate_tsns.len() * 4
    }
}

impl fmt::Display for SackChunk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SACK, cum_ack_tsn={}, a_rwnd={}", self.cumulative_tsn_ack, self.a_rwnd)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_capture() {
        const BYTES: &[u8] = &[
            0x03, 0x00, 0x00, 0x1c, 0x36, 0x9d, 0xd0, 0x0b, 0x00, 0x01, 0xed, 0x73, 0x00, 0x02,
            0x00, 0x01, 0x00, 0x02, 0x00, 0x06, 0x00, 0x08, 0x00, 0x08, 0x36, 0x9d, 0xd0, 0x11,
        ];
        let c = SackChunk::try_from(RawChunk::from_bytes(BYTES).unwrap().0).unwrap();

        let cum_ack_tsn = 916312075;
        assert_eq!(c.cumulative_tsn_ack, Tsn(cum_ack_tsn));
        assert_eq!(c.a_rwnd, 126323);
        assert_eq!(c.gap_ack_blocks.len(), 2);
        assert_eq!(c.gap_ack_blocks[0].start, (916312077 - cum_ack_tsn) as u16);
        assert_eq!(c.gap_ack_blocks[0].end, (916312081 - cum_ack_tsn) as u16);
        assert_eq!(c.gap_ack_blocks[1].start, (916312083 - cum_ack_tsn) as u16);
        assert_eq!(c.gap_ack_blocks[1].end, (916312083 - cum_ack_tsn) as u16);
        assert_eq!(c.duplicate_tsns.len(), 1);
        assert_eq!(c.duplicate_tsns[0], Tsn(916312081));
    }

    #[test]
    fn serialize_and_deserialize() {
        let chunk = SackChunk {
            cumulative_tsn_ack: Tsn(123),
            a_rwnd: 456,
            gap_ack_blocks: vec![GapAckBlock { start: 2, end: 3 }],
            duplicate_tsns: vec![Tsn(1), Tsn(2), Tsn(3)],
        };

        let mut serialized = vec![0; chunk.serialized_size()];
        chunk.serialize_to(&mut serialized);

        let deserialized =
            SackChunk::try_from(RawChunk::from_bytes(&serialized).unwrap().0).unwrap();

        assert_eq!(deserialized.cumulative_tsn_ack, Tsn(123));
        assert_eq!(deserialized.a_rwnd, 456);
        assert_eq!(deserialized.gap_ack_blocks.len(), 1);
        assert_eq!(deserialized.gap_ack_blocks[0].start, 2);
        assert_eq!(deserialized.gap_ack_blocks[0].end, 3);
        assert_eq!(deserialized.duplicate_tsns.len(), 3);
        assert_eq!(deserialized.duplicate_tsns[0], Tsn(1));
        assert_eq!(deserialized.duplicate_tsns[1], Tsn(2));
        assert_eq!(deserialized.duplicate_tsns[2], Tsn(3));
    }
}
