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
use crate::packet::ensure;
use std::fmt;

pub(crate) const CHUNK_TYPE: u8 = 10;

/// State Cookie (COOKIE ECHO) chunk
///
/// See <https://datatracker.ietf.org/doc/html/rfc9260#section-3.3.11>.
///
/// ```txt
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   Type = 10   |  Chunk Flags  |            Length             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// /                            Cookie                             /
/// \                                                               \
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Clone, Debug, Default)]
pub struct CookieEchoChunk {
    pub cookie: Vec<u8>,
}

impl TryFrom<RawChunk<'_>> for CookieEchoChunk {
    type Error = ChunkParseError;

    fn try_from(raw: RawChunk<'_>) -> Result<Self, ChunkParseError> {
        ensure!(raw.typ == CHUNK_TYPE, ChunkParseError::InvalidType);
        ensure!(!raw.value.is_empty(), ChunkParseError::InvalidLength);

        let cookie = raw.value.to_vec();
        Ok(Self { cookie })
    }
}

impl SerializableTlv for CookieEchoChunk {
    fn serialize_to(&self, output: &mut [u8]) {
        let value = write_chunk_header(CHUNK_TYPE, 0, self.value_size(), output);
        value.copy_from_slice(&self.cookie);
    }

    fn value_size(&self) -> usize {
        self.cookie.len()
    }
}

impl fmt::Display for CookieEchoChunk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "COOKIE-ECHO, cookie={} bytes", self.cookie.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_from_capture() {
        const BYTES: &[u8] = &[0x0a, 0x00, 0x00, 0x08, 0x12, 0x34, 0x56, 0x78];
        let c = CookieEchoChunk::try_from(RawChunk::from_bytes(BYTES).unwrap().0).unwrap();

        assert_eq!(c.cookie, vec![0x12, 0x34, 0x56, 0x78]);
    }

    #[test]
    fn serialize_and_deserialize() {
        let chunk = CookieEchoChunk { cookie: vec![1, 2, 3, 4, 5] };

        let mut serialized = vec![0; chunk.serialized_size()];
        chunk.serialize_to(&mut serialized);

        let deserialized =
            CookieEchoChunk::try_from(RawChunk::from_bytes(&serialized).unwrap().0).unwrap();

        assert_eq!(deserialized.cookie, vec![1, 2, 3, 4, 5]);
    }
}
