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
use crate::packet::error_causes::error_cause_from_bytes;
use crate::packet::error_causes::ErrorCause;
use crate::packet::parameter::parameters_serialize_to;
use crate::packet::parameter::parameters_serialized_size;
use crate::packet::ChunkParseError;
use crate::packet::SerializableTlv;
use anyhow::ensure;
use anyhow::Error;
use std::fmt;

pub(crate) const CHUNK_TYPE: u8 = 6;

/// Abort (ABORT) chunk
///
/// See <https://datatracker.ietf.org/doc/html/rfc9260#section-3.3.7>.
///
/// ```txt
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   Type = 6    |  Reserved   |T|            Length             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// \                                                               \
/// /                   zero or more Error Causes                   /
/// \                                                               \
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Default)]
pub struct AbortChunk {
    pub error_causes: Vec<ErrorCause>,
}

impl TryFrom<RawChunk<'_>> for AbortChunk {
    type Error = Error;

    fn try_from(raw: RawChunk<'_>) -> Result<Self, Error> {
        ensure!(raw.typ == CHUNK_TYPE, ChunkParseError::InvalidType);

        let error_causes = error_cause_from_bytes(raw.value)?;
        Ok(Self { error_causes })
    }
}

impl SerializableTlv for AbortChunk {
    fn serialize_to(&self, output: &mut [u8]) {
        let value = write_chunk_header(CHUNK_TYPE, 0, self.value_size(), output);
        parameters_serialize_to(&self.error_causes, value);
    }

    fn value_size(&self) -> usize {
        parameters_serialized_size(&self.error_causes)
    }
}

impl fmt::Display for AbortChunk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ABORT")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::protocol_violation_error_cause::ProtocolViolationErrorCause;

    #[test]
    fn init_from_capture() {
        // ABORT chunk
        //     Chunk type: ABORT (6)
        //     Chunk flags: 0x00
        //     Chunk length: 8
        //     User initiated ABORT cause
        const BYTES: &[u8] = &[0x06, 0x00, 0x00, 0x08, 0x00, 0x0c, 0x00, 0x04];
        let abort = AbortChunk::try_from(RawChunk::from_bytes(BYTES).unwrap().0).unwrap();
        assert_eq!(abort.error_causes.len(), 1);
        match &abort.error_causes[0] {
            ErrorCause::UserInitiatedAbort(c) => {
                assert!(c.reason.is_empty());
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn serialize_and_deserialize() {
        let chunk = AbortChunk {
            error_causes: vec![ErrorCause::ProtocolViolation(ProtocolViolationErrorCause {
                information: "Invalid foo".into(),
            })],
        };

        let mut serialized = vec![0; chunk.serialized_size()];
        chunk.serialize_to(&mut serialized);
        AbortChunk::try_from(RawChunk::from_bytes(&serialized).unwrap().0).unwrap();
    }
}
