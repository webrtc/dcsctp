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

pub(crate) const PARAMETER_TYPE: u16 = 0xC000;

/// Forward TSN supported parameter
///
/// See <https://datatracker.ietf.org/doc/html/rfc3758#section-3.1>.
///
/// ```txt
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |    Parameter Type = 49152     |  Parameter Length = 4         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug)]
pub struct ForwardTsnSupportedParameter {}

impl TryFrom<RawParameter<'_>> for ForwardTsnSupportedParameter {
    type Error = Error;

    fn try_from(raw: RawParameter<'_>) -> Result<Self, Error> {
        ensure!(raw.typ == PARAMETER_TYPE, ChunkParseError::InvalidType);
        ensure!(raw.value.is_empty(), ChunkParseError::InvalidLength);
        Ok(Self {})
    }
}

impl SerializableTlv for ForwardTsnSupportedParameter {
    fn serialize_to(&self, output: &mut [u8]) {
        write_parameter_header(PARAMETER_TYPE, self.value_size(), output);
    }

    fn value_size(&self) -> usize {
        0
    }
}

impl fmt::Display for ForwardTsnSupportedParameter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Forward-TSN supported")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_and_deserialize() {
        let cause = ForwardTsnSupportedParameter {};

        let mut serialized = vec![0; cause.serialized_size()];
        cause.serialize_to(&mut serialized);

        ForwardTsnSupportedParameter::try_from(RawParameter::from_bytes(&serialized).unwrap().0)
            .unwrap();
    }
}
