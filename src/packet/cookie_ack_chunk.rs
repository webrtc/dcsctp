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

pub(crate) const CHUNK_TYPE: u8 = 11;

/// Cookie Acknowledgement (COOKIE ACK)
///
/// See <https://datatracker.ietf.org/doc/html/rfc9260#section-3.3.12>.
///
/// ```txt
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   Type = 11   |  Chunk Flags  |          Length = 4           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug)]
pub struct CookieAckChunk {}

impl TryFrom<RawChunk<'_>> for CookieAckChunk {
    type Error = Error;

    fn try_from(raw: RawChunk<'_>) -> Result<Self, Error> {
        ensure!(raw.typ == CHUNK_TYPE, ChunkParseError::InvalidType);
        ensure!(raw.value.is_empty(), ChunkParseError::InvalidLength);
        Ok(Self {})
    }
}

impl SerializableTlv for CookieAckChunk {
    fn serialize_to(&self, output: &mut [u8]) {
        write_chunk_header(CHUNK_TYPE, 0, self.value_size(), output);
    }

    fn value_size(&self) -> usize {
        0
    }
}

impl fmt::Display for CookieAckChunk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "COOKIE-ACK")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_from_capture() {
        // COOKIE_ACK chunk
        //   Chunk type: COOKIE_ACK (11)
        //   Chunk flags: 0x00
        //   Chunk length: 4
        const BYTES: &[u8] = &[0x0b, 0x00, 0x00, 0x04];
        CookieAckChunk::try_from(RawChunk::from_bytes(BYTES).unwrap().0).unwrap();
    }

    #[test]
    fn serialize_and_deserialize() {
        let chunk = CookieAckChunk {};

        let mut serialized = vec![0; chunk.serialized_size()];
        chunk.serialize_to(&mut serialized);
        CookieAckChunk::try_from(RawChunk::from_bytes(&serialized).unwrap().0).unwrap();
    }

    #[test]
    fn display() {
        let chunk = CookieAckChunk {};
        assert_eq!(chunk.to_string(), "COOKIE-ACK");
    }
}
