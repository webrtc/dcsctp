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
use crate::packet::read_u32_be;
use crate::packet::write_u32_be;
use crate::packet::ChunkParseError;
use crate::packet::SerializableTlv;
use crate::types::Tsn;
use anyhow::ensure;
use anyhow::Error;
use core::fmt;

pub(crate) const PARAMETER_TYPE: u16 = 16;

/// Re-configuration Response parameter
///
/// See <https://datatracker.ietf.org/doc/html/rfc6525#section-4.4>.
///
/// ```txt
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Parameter Type = 16       |      Parameter Length         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |         Re-configuration Response Sequence Number             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                            Result                             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                   Sender's Next TSN (optional)                |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                  Receiver's Next TSN (optional)               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconfigurationResponseResult {
    SuccessNothingToDo = 0,
    SuccessPerformed = 1,
    Denied = 2,
    ErrorWrongSSN = 3,
    ErrorRequestAlreadyInProgress = 4,
    ErrorBadSequenceNumber = 5,
    InProgress = 6,
}

impl TryFrom<u32> for ReconfigurationResponseResult {
    type Error = ChunkParseError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(ReconfigurationResponseResult::SuccessNothingToDo),
            1 => Ok(ReconfigurationResponseResult::SuccessPerformed),
            2 => Ok(ReconfigurationResponseResult::Denied),
            3 => Ok(ReconfigurationResponseResult::ErrorWrongSSN),
            4 => Ok(ReconfigurationResponseResult::ErrorRequestAlreadyInProgress),
            5 => Ok(ReconfigurationResponseResult::ErrorBadSequenceNumber),
            6 => Ok(ReconfigurationResponseResult::InProgress),
            _ => Err(ChunkParseError::InvalidValue),
        }
    }
}

#[derive(Debug)]
pub struct ReconfigurationResponseParameter {
    pub(crate) response_seq_nbr: u32,
    pub(crate) result: ReconfigurationResponseResult,
    pub(crate) sender_next_tsn: Option<Tsn>,
    pub(crate) receiver_next_tsn: Option<Tsn>,
}

impl TryFrom<RawParameter<'_>> for ReconfigurationResponseParameter {
    type Error = Error;

    fn try_from(raw: RawParameter<'_>) -> Result<Self, Error> {
        ensure!(raw.typ == PARAMETER_TYPE, ChunkParseError::InvalidType);
        let has_next_tsn = raw.value.len() == 16;
        ensure!(raw.value.len() == 8 || has_next_tsn, ChunkParseError::InvalidLength);

        let response_seq_nbr = read_u32_be!(&raw.value[0..4]);
        let result = ReconfigurationResponseResult::try_from(read_u32_be!(&raw.value[4..8]))?;
        let sender_next_tsn = has_next_tsn.then(|| Tsn(read_u32_be!(&raw.value[8..12])));
        let receiver_next_tsn = has_next_tsn.then(|| Tsn(read_u32_be!(&raw.value[12..16])));

        Ok(Self { response_seq_nbr, result, sender_next_tsn, receiver_next_tsn })
    }
}

impl SerializableTlv for ReconfigurationResponseParameter {
    fn serialize_to(&self, output: &mut [u8]) {
        let value = write_parameter_header(PARAMETER_TYPE, self.value_size(), output);
        write_u32_be!(&mut value[0..4], self.response_seq_nbr);
        write_u32_be!(&mut value[4..8], self.result as u32);
        if let (Some(sender_val), Some(receiver_val)) =
            (self.sender_next_tsn, self.receiver_next_tsn)
        {
            write_u32_be!(&mut value[8..12], sender_val.0);
            write_u32_be!(&mut value[12..16], receiver_val.0);
        }
    }

    fn value_size(&self) -> usize {
        match (self.sender_next_tsn, self.receiver_next_tsn) {
            (Some(_), Some(_)) => 16,
            _ => 8,
        }
    }
}

impl fmt::Display for ReconfigurationResponseParameter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Reconfig Response, seq={}", self.response_seq_nbr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_and_deserialize() {
        let cause = ReconfigurationResponseParameter {
            response_seq_nbr: 1,
            result: ReconfigurationResponseResult::SuccessPerformed,
            sender_next_tsn: Some(Tsn(2)),
            receiver_next_tsn: Some(Tsn(3)),
        };

        let mut serialized = vec![0; cause.serialized_size()];
        cause.serialize_to(&mut serialized);

        let param = ReconfigurationResponseParameter::try_from(
            RawParameter::from_bytes(&serialized).unwrap().0,
        )
        .unwrap();
        assert_eq!(param.response_seq_nbr, 1);
        assert_eq!(param.result, ReconfigurationResponseResult::SuccessPerformed);
        assert_eq!(param.sender_next_tsn, Some(Tsn(2)));
        assert_eq!(param.receiver_next_tsn, Some(Tsn(3)));
    }
}
