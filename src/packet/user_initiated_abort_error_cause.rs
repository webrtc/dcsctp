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

use crate::packet::parameter::write_parameter_header;
use crate::packet::parameter::RawParameter;
use crate::packet::ChunkParseError;
use crate::packet::SerializableTlv;
use anyhow::ensure;
use anyhow::Error;
use std::fmt;

pub(crate) const CAUSE_CODE: u16 = 12;

/// User-Initiated Abort error cause
///
/// See <https://datatracker.ietf.org/doc/html/rfc9260#section-3.3.10.12>.
///
/// ```txt
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |        Cause Code = 12        |         Cause Length          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// /                   Upper Layer Abort Reason                    /
/// \                                                               \
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug)]
pub struct UserInitiatedAbortErrorCause {
    pub(crate) reason: String,
}

impl TryFrom<RawParameter<'_>> for UserInitiatedAbortErrorCause {
    type Error = Error;

    fn try_from(raw: RawParameter<'_>) -> Result<Self, Error> {
        ensure!(raw.typ == CAUSE_CODE, ChunkParseError::InvalidType);

        let reason = String::from_utf8(raw.value.to_vec())
            .unwrap_or_else(|_| "Failed to parse abort reason".into());
        Ok(Self { reason })
    }
}

impl SerializableTlv for UserInitiatedAbortErrorCause {
    fn serialize_to(&self, output: &mut [u8]) {
        let value = write_parameter_header(CAUSE_CODE, self.value_size(), output);
        value.copy_from_slice(self.reason.as_bytes());
    }

    fn value_size(&self) -> usize {
        self.reason.len()
    }
}

impl fmt::Display for UserInitiatedAbortErrorCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "User-Initiated Abort, reason={}", self.reason)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_and_deserialize() {
        let cause = UserInitiatedAbortErrorCause { reason: "abracadabra".into() };

        let mut serialized = vec![0; cause.serialized_size()];
        cause.serialize_to(&mut serialized);

        let error = UserInitiatedAbortErrorCause::try_from(
            RawParameter::from_bytes(&serialized).unwrap().0,
        )
        .unwrap();
        assert_eq!(error.reason, "abracadabra");
    }
}
