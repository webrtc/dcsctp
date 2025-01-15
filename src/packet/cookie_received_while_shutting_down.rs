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

pub(crate) const CAUSE_CODE: u16 = 10;

/// Cookie Received While Shutting Down error cause
///
/// See <https://datatracker.ietf.org/doc/html/rfc9260#section-3.3.10.10>.
///
/// ```txt
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |        Cause Code = 10        |       Cause Length = 4        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug)]
pub struct CookieReceivedWhileShuttingDownErrorCause {}

impl TryFrom<RawParameter<'_>> for CookieReceivedWhileShuttingDownErrorCause {
    type Error = Error;

    fn try_from(raw: RawParameter<'_>) -> Result<Self, Error> {
        ensure!(raw.typ == CAUSE_CODE, ChunkParseError::InvalidType);
        ensure!(raw.value.is_empty(), ChunkParseError::InvalidLength);
        Ok(Self {})
    }
}

impl SerializableTlv for CookieReceivedWhileShuttingDownErrorCause {
    fn serialize_to(&self, output: &mut [u8]) {
        write_parameter_header(CAUSE_CODE, self.value_size(), output);
    }

    fn value_size(&self) -> usize {
        0
    }
}

impl fmt::Display for CookieReceivedWhileShuttingDownErrorCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Cookie Received While Shutting Down")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_and_deserialize() {
        let cause = CookieReceivedWhileShuttingDownErrorCause {};

        let mut serialized = vec![0; cause.serialized_size()];
        cause.serialize_to(&mut serialized);

        CookieReceivedWhileShuttingDownErrorCause::try_from(
            RawParameter::from_bytes(&serialized).unwrap().0,
        )
        .unwrap();
    }
}
