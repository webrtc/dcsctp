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

use crate::api::ZeroChecksumAlternateErrorDetectionMethod;
use crate::packet::ChunkParseError;
use crate::packet::SerializableTlv;
use crate::packet::parameter::RawParameter;
use crate::packet::parameter::write_parameter_header;
use crate::packet::read_u32_be;
use crate::packet::write_u32_be;
use anyhow::Error;
use anyhow::ensure;
use std::fmt;

pub(crate) const PARAMETER_TYPE: u16 = 0x8001;

/// Zero Checksum Acceptable parameter
///
/// See <https://datatracker.ietf.org/doc/html/rfc9653#section-4>.
///
/// ```txt
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |          Type = 0x8001        |          Length = 8           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |           Error Detection Method Identifier (EDMID)           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug)]
pub struct ZeroChecksumAcceptableParameter {
    pub(crate) method: ZeroChecksumAlternateErrorDetectionMethod,
}

impl TryFrom<RawParameter<'_>> for ZeroChecksumAcceptableParameter {
    type Error = Error;

    fn try_from(raw: RawParameter<'_>) -> Result<Self, Error> {
        ensure!(raw.typ == PARAMETER_TYPE, ChunkParseError::InvalidType);
        ensure!(raw.value.len() == 4, ChunkParseError::InvalidLength);

        Ok(Self {
            method: ZeroChecksumAlternateErrorDetectionMethod(read_u32_be!(&raw.value[0..4])),
        })
    }
}

impl SerializableTlv for ZeroChecksumAcceptableParameter {
    fn serialize_to(&self, output: &mut [u8]) {
        let value = write_parameter_header(PARAMETER_TYPE, self.value_size(), output);
        write_u32_be!(&mut value[0..4], self.method.0);
    }

    fn value_size(&self) -> usize {
        4
    }
}

impl fmt::Display for ZeroChecksumAcceptableParameter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Zero Checksum Acceptable, method={}", self.method.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_and_deserialize() {
        let cause = ZeroChecksumAcceptableParameter {
            method: ZeroChecksumAlternateErrorDetectionMethod(42),
        };

        let mut serialized = vec![0; cause.serialized_size()];
        cause.serialize_to(&mut serialized);

        let error = ZeroChecksumAcceptableParameter::try_from(
            RawParameter::from_bytes(&serialized).unwrap().0,
        )
        .unwrap();
        assert_eq!(error.method, ZeroChecksumAlternateErrorDetectionMethod(42));
    }
}
