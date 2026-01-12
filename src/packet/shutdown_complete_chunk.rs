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
use anyhow::Error;
use anyhow::ensure;
use std::fmt;

pub(crate) const CHUNK_TYPE: u8 = 14;

/// Shutdown Complete (SHUTDOWN COMPLETE) chunk
///
/// See <https://datatracker.ietf.org/doc/html/rfc9260#section-3.3.13>.
///
/// ```txt
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   Type = 14   |  Reserved   |T|          Length = 4           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug)]
pub struct ShutdownCompleteChunk {
    pub tag_reflected: bool,
}

impl TryFrom<RawChunk<'_>> for ShutdownCompleteChunk {
    type Error = Error;

    fn try_from(raw: RawChunk<'_>) -> Result<Self, Error> {
        ensure!(raw.typ == CHUNK_TYPE, ChunkParseError::InvalidType);
        ensure!(raw.value.is_empty(), ChunkParseError::InvalidLength);
        Ok(Self { tag_reflected: (raw.flags & 0x01) != 0 })
    }
}

impl SerializableTlv for ShutdownCompleteChunk {
    fn serialize_to(&self, output: &mut [u8]) {
        let flags = if self.tag_reflected { 1 } else { 0 };
        write_chunk_header(CHUNK_TYPE, flags, self.value_size(), output);
    }

    fn value_size(&self) -> usize {
        0
    }
}

impl fmt::Display for ShutdownCompleteChunk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SHUTDOWN-COMPLETE, tag_reflected={}", self.tag_reflected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_from_capture() {
        // SHUTDOWN_COMPLETE chunk
        //  Chunk type: SHUTDOWN_COMPLETE (14)
        //  Chunk flags: 0x00
        //  Chunk length: 4
        const BYTES: &[u8] = &[0x0e, 0x00, 0x00, 0x04];
        ShutdownCompleteChunk::try_from(RawChunk::from_bytes(BYTES).unwrap().0).unwrap();
    }

    #[test]
    fn serialize_and_deserialize() {
        let chunk = ShutdownCompleteChunk { tag_reflected: true };

        let mut serialized = vec![0; chunk.serialized_size()];
        chunk.serialize_to(&mut serialized);
        let deserialized =
            ShutdownCompleteChunk::try_from(RawChunk::from_bytes(&serialized).unwrap().0).unwrap();
        assert_eq!(chunk.tag_reflected, deserialized.tag_reflected);
    }

    #[test]
    fn display() {
        let chunk = ShutdownCompleteChunk { tag_reflected: true };
        assert_eq!(chunk.to_string(), "SHUTDOWN-COMPLETE, tag_reflected=true");
    }
}
