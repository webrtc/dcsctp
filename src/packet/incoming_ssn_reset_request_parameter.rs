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

use crate::api::StreamId;
use crate::packet::parameter::write_parameter_header;
use crate::packet::parameter::RawParameter;
use crate::packet::read_u16_be;
use crate::packet::read_u32_be;
use crate::packet::write_u16_be;
use crate::packet::write_u32_be;
use crate::packet::ChunkParseError;
use crate::packet::SerializableTlv;
use anyhow::ensure;
use anyhow::Error;
use core::fmt;

pub(crate) const PARAMETER_TYPE: u16 = 14;

/// Incoming SSN Reset Request parameter
///
/// See <https://datatracker.ietf.org/doc/html/rfc6525#section-4.2>.
///
/// ```txt
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Parameter Type = 14       |  Parameter Length = 8 + 2 * N |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |          Re-configuration Request Sequence Number             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  Stream Number 1 (optional)   |    Stream Number 2 (optional) |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// /                            ......                             /
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  Stream Number N-1 (optional) |    Stream Number N (optional) |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug)]
pub struct IncomingSsnResetRequestParameter {
    pub(crate) request_seq_nbr: u32,
    pub(crate) streams: Vec<StreamId>,
}

impl TryFrom<RawParameter<'_>> for IncomingSsnResetRequestParameter {
    type Error = Error;

    fn try_from(raw: RawParameter<'_>) -> Result<Self, Error> {
        ensure!(raw.typ == PARAMETER_TYPE, ChunkParseError::InvalidType);
        ensure!(
            raw.value.len() >= 4 && raw.value.len().is_multiple_of(2),
            ChunkParseError::InvalidLength
        );

        let request_seq_nbr = read_u32_be!(&raw.value[0..4]);
        let streams = raw.value[4..].chunks_exact(2).map(|c| StreamId(read_u16_be!(c))).collect();

        Ok(Self { request_seq_nbr, streams })
    }
}

impl SerializableTlv for IncomingSsnResetRequestParameter {
    fn serialize_to(&self, output: &mut [u8]) {
        let value = write_parameter_header(PARAMETER_TYPE, self.value_size(), output);
        write_u32_be!(&mut value[0..4], self.request_seq_nbr);
        let mut chunks = value[4..].chunks_exact_mut(2);
        for (stream_id, chunk) in self.streams.iter().zip(&mut chunks) {
            write_u16_be!(chunk, stream_id.0);
        }
    }

    fn value_size(&self) -> usize {
        4 + self.streams.len() * 2
    }
}

impl fmt::Display for IncomingSsnResetRequestParameter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Incoming SSN Reset Request, req_seq_nbr={}", self.request_seq_nbr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_and_deserialize() {
        let cause = IncomingSsnResetRequestParameter {
            request_seq_nbr: 1,
            streams: vec![StreamId(2), StreamId(3), StreamId(4)],
        };

        let mut serialized = vec![0; cause.serialized_size()];
        cause.serialize_to(&mut serialized);

        let param = IncomingSsnResetRequestParameter::try_from(
            RawParameter::from_bytes(&serialized).unwrap().0,
        )
        .unwrap();
        assert_eq!(param.request_seq_nbr, 1);
        assert_eq!(param.streams, vec![StreamId(2), StreamId(3), StreamId(4)]);
    }
}
