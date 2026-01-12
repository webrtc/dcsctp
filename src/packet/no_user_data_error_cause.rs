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
use crate::packet::read_u32_be;
use crate::packet::write_u32_be;
use crate::types::Tsn;
use anyhow::Error;
use anyhow::ensure;
use std::fmt;

pub(crate) const CAUSE_CODE: u16 = 9;

/// No User Data error cause
///
/// See <https://datatracker.ietf.org/doc/html/rfc9260#section-3.3.10.9>.
///
/// ```txt
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |        Cause Code = 9         |       Cause Length = 8        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                              TSN                              |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug)]
pub struct NoUserDataErrorCause {
    pub tsn: Tsn,
}

impl TryFrom<RawParameter<'_>> for NoUserDataErrorCause {
    type Error = Error;

    fn try_from(raw: RawParameter<'_>) -> Result<Self, Error> {
        ensure!(raw.typ == CAUSE_CODE, ChunkParseError::InvalidType);
        ensure!(raw.value.len() == 4, ChunkParseError::InvalidLength);
        let tsn = Tsn(read_u32_be!(&raw.value[0..4]));
        Ok(Self { tsn })
    }
}

impl SerializableTlv for NoUserDataErrorCause {
    fn serialize_to(&self, output: &mut [u8]) {
        let value = write_parameter_header(CAUSE_CODE, self.value_size(), output);
        write_u32_be!(&mut value[0..4], self.tsn.0);
    }

    fn value_size(&self) -> usize {
        4
    }
}

impl fmt::Display for NoUserDataErrorCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "No User Data, tsn={}", self.tsn)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_and_deserialize() {
        let cause = NoUserDataErrorCause { tsn: Tsn(123) };

        let mut serialized = vec![0; cause.serialized_size()];
        cause.serialize_to(&mut serialized);
        let deserialized =
            NoUserDataErrorCause::try_from(RawParameter::from_bytes(&serialized).unwrap().0)
                .unwrap();
        assert_eq!(deserialized.tsn, Tsn(123));
    }
}
