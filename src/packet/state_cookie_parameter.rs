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

pub(crate) const PARAMETER_TYPE: u16 = 7;

/// State Cookie parameter
///
/// See <https://datatracker.ietf.org/doc/html/rfc9260#section-3.3.3.1.1>.
///
/// ```txt
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |           Type = 7            |            Length             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// /                            Cookie                             /
/// \                                                               \
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug)]
pub struct StateCookieParameter {
    pub(crate) cookie: Vec<u8>,
}

impl TryFrom<RawParameter<'_>> for StateCookieParameter {
    type Error = Error;

    fn try_from(raw: RawParameter<'_>) -> Result<Self, Error> {
        ensure!(raw.typ == PARAMETER_TYPE, ChunkParseError::InvalidType);
        let cookie = raw.value.to_vec();
        Ok(Self { cookie })
    }
}

impl SerializableTlv for StateCookieParameter {
    fn serialize_to(&self, output: &mut [u8]) {
        let value = write_parameter_header(PARAMETER_TYPE, self.value_size(), output);
        value.copy_from_slice(&self.cookie);
    }

    fn value_size(&self) -> usize {
        self.cookie.len()
    }
}

impl fmt::Display for StateCookieParameter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "State cookie, cookie_length={}", self.cookie.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_and_deserialize() {
        let cause = StateCookieParameter { cookie: vec![1, 2, 3, 4] };

        let mut serialized = vec![0; cause.serialized_size()];
        cause.serialize_to(&mut serialized);

        let error =
            StateCookieParameter::try_from(RawParameter::from_bytes(&serialized).unwrap().0)
                .unwrap();
        assert_eq!(error.cookie, vec![1, 2, 3, 4]);
    }
}
