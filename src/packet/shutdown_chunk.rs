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

use crate::packet::ChunkParseError;
use crate::packet::SerializableTlv;
use crate::packet::chunk::RawChunk;
use crate::packet::chunk::write_chunk_header;
use crate::packet::read_u32_be;
use crate::packet::write_u32_be;
use crate::types::Tsn;
use anyhow::Error;
use anyhow::ensure;
use std::fmt;

pub(crate) const CHUNK_TYPE: u8 = 7;

/// Shutdown (SHUTDOWN) chunk
///
/// See <https://datatracker.ietf.org/doc/html/rfc9260#section-3.3.8>.
///
/// ```txt
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   Type = 7    |  Chunk Flags  |          Length = 8           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                      Cumulative TSN Ack                       |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug)]
pub struct ShutdownChunk {
    pub cumulative_tsn_ack: Tsn,
}

impl TryFrom<RawChunk<'_>> for ShutdownChunk {
    type Error = Error;

    fn try_from(raw: RawChunk<'_>) -> Result<Self, Error> {
        ensure!(raw.typ == CHUNK_TYPE, ChunkParseError::InvalidType);
        ensure!(raw.value.len() == 4, ChunkParseError::InvalidLength);

        Ok(Self { cumulative_tsn_ack: Tsn(read_u32_be!(&raw.value[0..4])) })
    }
}

impl SerializableTlv for ShutdownChunk {
    fn serialize_to(&self, output: &mut [u8]) {
        write_chunk_header(CHUNK_TYPE, 0, self.value_size(), output);
        write_u32_be!(&mut output[4..8], self.cumulative_tsn_ack.0);
    }

    fn value_size(&self) -> usize {
        4
    }
}

impl fmt::Display for ShutdownChunk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SHUTDOWN cumulative_tsn_ack={}", self.cumulative_tsn_ack)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_capture() {
        // SHUTDOWN chunk (Cumulative TSN ack: 101831101)
        //  Chunk type: SHUTDOWN (7)
        //  Chunk flags: 0x00
        //  Chunk length: 8
        //  Cumulative TSN Ack: 101831101
        const BYTES: &[u8] = &[0x07, 0x00, 0x00, 0x08, 0x06, 0x11, 0xd1, 0xbd];
        let c = ShutdownChunk::try_from(RawChunk::from_bytes(BYTES).unwrap().0).unwrap();
        assert_eq!(c.cumulative_tsn_ack, Tsn(101831101));
    }

    #[test]
    fn serialize_and_deserialize() {
        let chunk = ShutdownChunk { cumulative_tsn_ack: Tsn(12345678) };

        let mut serialized = vec![0; chunk.serialized_size()];
        chunk.serialize_to(&mut serialized);

        let deserialized =
            ShutdownChunk::try_from(RawChunk::from_bytes(&serialized).unwrap().0).unwrap();

        assert_eq!(deserialized.cumulative_tsn_ack, Tsn(12345678));
        assert_eq!(deserialized.to_string(), "SHUTDOWN cumulative_tsn_ack=12345678");
    }
}
