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
use crate::packet::ensure;
use crate::packet::parameter::RawParameter;
use crate::packet::parameter::write_parameter_header;
use std::fmt;

pub(crate) const PARAMETER_TYPE: u16 = 0x8008;

/// Supported Extensions parameter
///
/// See <https://datatracker.ietf.org/doc/html/rfc5061#section-4.2.7>.
///
/// ```txt
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Parameter Type = 0x8008   |      Parameter Length         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | CHUNK TYPE 1  |  CHUNK TYPE 2 |  CHUNK TYPE 3 |  CHUNK TYPE 4 |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                             ....                              |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | CHUNK TYPE N  |      PAD      |      PAD      |      PAD      |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug)]
pub struct SupportedExtensionsParameter {
    pub(crate) chunk_types: Vec<u8>,
}

impl TryFrom<RawParameter<'_>> for SupportedExtensionsParameter {
    type Error = ChunkParseError;

    fn try_from(raw: RawParameter<'_>) -> Result<Self, ChunkParseError> {
        ensure!(raw.typ == PARAMETER_TYPE, ChunkParseError::InvalidType);
        let chunk_types = raw.value.to_vec();
        Ok(Self { chunk_types })
    }
}

impl SerializableTlv for SupportedExtensionsParameter {
    fn serialize_to(&self, output: &mut [u8]) {
        let value = write_parameter_header(PARAMETER_TYPE, self.value_size(), output);
        value.copy_from_slice(&self.chunk_types);
    }

    fn value_size(&self) -> usize {
        self.chunk_types.len()
    }
}

impl fmt::Display for SupportedExtensionsParameter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Supported extensions, chunks={}",
            self.chunk_types.iter().map(|c| c.to_string()).collect::<Vec<_>>().join(",")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_and_deserialize() {
        let cause = SupportedExtensionsParameter { chunk_types: vec![1, 2, 3, 4] };

        let mut serialized = vec![0; cause.serialized_size()];
        cause.serialize_to(&mut serialized);

        let error = SupportedExtensionsParameter::try_from(
            RawParameter::from_bytes(&serialized).unwrap().0,
        )
        .unwrap();
        assert_eq!(error.chunk_types, vec![1, 2, 3, 4]);
    }
}
