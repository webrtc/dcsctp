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
use crate::packet::ChunkParseError;
use crate::packet::SerializableTlv;
use anyhow::ensure;
use anyhow::Error;
use std::fmt;

pub(crate) const CHUNK_TYPE: u8 = 8;

/// Shutdown Acknowledgement (SHUTDOWN ACK) chunk
///
/// See <https://datatracker.ietf.org/doc/html/rfc9260#section-3.3.9>.
///
/// ```txt
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   Type = 8    |  Chunk Flags  |          Length = 4           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug)]
pub struct ShutdownAckChunk {}

impl TryFrom<RawChunk<'_>> for ShutdownAckChunk {
    type Error = Error;

    fn try_from(raw: RawChunk<'_>) -> Result<Self, Error> {
        ensure!(raw.typ == CHUNK_TYPE, ChunkParseError::InvalidType);
        ensure!(raw.value.is_empty(), ChunkParseError::InvalidLength);
        Ok(Self {})
    }
}

impl SerializableTlv for ShutdownAckChunk {
    fn serialize_to(&self, output: &mut [u8]) {
        write_chunk_header(CHUNK_TYPE, 0, self.value_size(), output);
    }

    fn value_size(&self) -> usize {
        0
    }
}

impl fmt::Display for ShutdownAckChunk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SHUTDOWN-ACK")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_from_capture() {
        // SHUTDOWN_ACK chunk
        //  Chunk type: SHUTDOWN_ACK (8)
        //  Chunk flags: 0x00
        //  Chunk length: 4
        const BYTES: &[u8] = &[0x08, 0x00, 0x00, 0x04];
        ShutdownAckChunk::try_from(RawChunk::from_bytes(BYTES).unwrap().0).unwrap();
    }

    #[test]
    fn serialize_and_deserialize() {
        let chunk = ShutdownAckChunk {};

        let mut serialized = vec![0; chunk.serialized_size()];
        chunk.serialize_to(&mut serialized);
        ShutdownAckChunk::try_from(RawChunk::from_bytes(&serialized).unwrap().0).unwrap();
    }

    #[test]
    fn display() {
        let chunk = ShutdownAckChunk {};
        assert_eq!(chunk.to_string(), "SHUTDOWN-ACK");
    }
}
