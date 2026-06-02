// Copyright 2026 The dcSCTP Authors
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
use crate::packet::read_u16_be;
use crate::packet::read_u32_be;
use crate::packet::write_u16_be;
use crate::packet::write_u32_be;
use std::fmt;

pub(crate) const CAUSE_CODE: u16 = 2;

/// Missing Mandatory Parameter error cause
///
/// See <https://datatracker.ietf.org/doc/html/rfc9260#section-3.3.10.2>.
///
/// ```txt
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Cause Code=2              |      Cause Length=8+N*2       |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                   Number of missing params=N                  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   Missing Param Type #1       |   Missing Param Type #2       |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   Missing Param Type #N-1     |   Missing Param Type #N       |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissingMandatoryParameterErrorCause {
    pub(crate) missing_parameters: Vec<u16>,
}

impl MissingMandatoryParameterErrorCause {
    pub(crate) fn new(missing_parameters: Vec<u16>) -> Self {
        Self { missing_parameters }
    }
}

impl TryFrom<RawParameter<'_>> for MissingMandatoryParameterErrorCause {
    type Error = ChunkParseError;

    fn try_from(raw: RawParameter<'_>) -> Result<Self, ChunkParseError> {
        ensure!(raw.typ == CAUSE_CODE, ChunkParseError::InvalidType);
        ensure!(raw.value.len() >= 4, ChunkParseError::InvalidLength);

        let num_params = read_u32_be!(&raw.value[0..4]) as usize;
        ensure!(raw.value.len() == 4 + num_params * 2, ChunkParseError::InvalidLength);

        let missing_parameters = raw.value[4..].chunks_exact(2).map(|c| read_u16_be!(c)).collect();
        Ok(Self { missing_parameters })
    }
}

impl SerializableTlv for MissingMandatoryParameterErrorCause {
    fn serialize_to(&self, output: &mut [u8]) {
        let value = write_parameter_header(CAUSE_CODE, self.value_size(), output);
        write_u32_be!(&mut value[0..4], self.missing_parameters.len() as u32);
        let chunks = value[4..].chunks_exact_mut(2);
        for (&param_type, chunk) in self.missing_parameters.iter().zip(chunks) {
            write_u16_be!(chunk, param_type);
        }
    }

    fn value_size(&self) -> usize {
        4 + self.missing_parameters.len() * 2
    }
}

impl fmt::Display for MissingMandatoryParameterErrorCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Missing Mandatory Parameter, missing_parameters={:?}", self.missing_parameters)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_and_deserialize() {
        let cause = MissingMandatoryParameterErrorCause { missing_parameters: vec![7, 13] };

        let mut serialized = vec![0; cause.serialized_size()];
        cause.serialize_to(&mut serialized);

        let error = MissingMandatoryParameterErrorCause::try_from(
            RawParameter::from_bytes(&serialized).unwrap().0,
        )
        .unwrap();
        assert_eq!(error.missing_parameters, vec![7, 13]);
    }
}
