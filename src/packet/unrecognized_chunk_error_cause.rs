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
use crate::packet::parameter::RawParameter;
use crate::packet::parameter::write_parameter_header;
use anyhow::Error;
use anyhow::ensure;
use std::fmt;

pub(crate) const CAUSE_CODE: u16 = 6;

/// Unrecognized Chunk Type error cause
///
/// See <https://datatracker.ietf.org/doc/html/rfc9260#section-3.3.10.6>.
///
/// ```txt
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |        Cause Code = 6         |         Cause Length          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// /                      Unrecognized Chunk                       /
/// \                                                               \
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug)]
pub struct UnrecognizedChunkErrorCause {
    pub chunk: Vec<u8>,
}

impl TryFrom<RawParameter<'_>> for UnrecognizedChunkErrorCause {
    type Error = Error;

    fn try_from(raw: RawParameter<'_>) -> Result<Self, Error> {
        ensure!(raw.typ == CAUSE_CODE, ChunkParseError::InvalidType);
        let chunk = raw.value.to_vec();
        Ok(Self { chunk })
    }
}

impl SerializableTlv for UnrecognizedChunkErrorCause {
    fn serialize_to(&self, output: &mut [u8]) {
        let value = write_parameter_header(CAUSE_CODE, self.value_size(), output);
        value.copy_from_slice(&self.chunk);
    }

    fn value_size(&self) -> usize {
        self.chunk.len()
    }
}

impl fmt::Display for UnrecognizedChunkErrorCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Unrecognized Chunk Type")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_and_deserialize() {
        let cause = UnrecognizedChunkErrorCause { chunk: vec![1, 2] };

        let mut serialized = vec![0; cause.serialized_size()];
        cause.serialize_to(&mut serialized);
        UnrecognizedChunkErrorCause::try_from(RawParameter::from_bytes(&serialized).unwrap().0)
            .unwrap();
    }
}
