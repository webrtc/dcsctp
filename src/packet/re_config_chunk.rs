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
use crate::packet::chunk::RawChunk;
use crate::packet::chunk::write_chunk_header;
use crate::packet::parameter::Parameter;
use crate::packet::parameter::parameters_from_bytes;
use crate::packet::parameter::parameters_serialize_to;
use crate::packet::parameter::parameters_serialized_size;
use anyhow::Error;
use anyhow::ensure;
use std::fmt;

pub(crate) const CHUNK_TYPE: u8 = 130;

/// Re-configuration Chunk (RE-CONFIG) chunk
///
/// See <https://datatracker.ietf.org/doc/html/rfc6525#section-3.1>.
///
/// ```txt
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | Type = 130    |  Chunk Flags  |      Chunk Length             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// \                                                               \
/// /                  Re-configuration Parameter                   /
/// \                                                               \
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// \                                                               \
/// /             Re-configuration Parameter (optional)             /
/// \                                                               \
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Default)]
pub struct ReConfigChunk {
    pub parameters: Vec<Parameter>,
}

impl TryFrom<RawChunk<'_>> for ReConfigChunk {
    type Error = Error;

    fn try_from(raw: RawChunk<'_>) -> Result<Self, Error> {
        ensure!(raw.typ == CHUNK_TYPE, ChunkParseError::InvalidType);
        let parameters = parameters_from_bytes(raw.value)?;
        Ok(Self { parameters })
    }
}

impl SerializableTlv for ReConfigChunk {
    fn serialize_to(&self, output: &mut [u8]) {
        let value = write_chunk_header(CHUNK_TYPE, 0, self.value_size(), output);
        parameters_serialize_to(&self.parameters, value);
    }

    fn value_size(&self) -> usize {
        parameters_serialized_size(&self.parameters)
    }
}

impl fmt::Display for ReConfigChunk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RE-CONFIG")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::StreamId;
    use crate::packet::outgoing_ssn_reset_request_parameter::OutgoingSsnResetRequestParameter;
    use crate::types::Tsn;

    #[test]
    fn from_capture() {
        // RE_CONFIG chunk
        //     Chunk type: RE_CONFIG (130)
        //     Chunk flags: 0x00
        //     Chunk length: 22
        //     Outgoing SSN reset request parameter
        //         Parameter type: Outgoing SSN reset request (0x000d)
        //         Parameter length: 18
        //         Re-configuration request sequence number: 2270550051
        //         Re-configuration response sequence number: 1905748638
        //         Senders last assigned TSN: 2270550066
        //         Stream Identifier: 6
        //     Chunk padding: 0000
        const BYTES: &[u8] = &[
            0x82, 0x00, 0x00, 0x16, 0x00, 0x0d, 0x00, 0x12, 0x87, 0x55, 0xd8, 0x23, 0x71, 0x97,
            0x6a, 0x9e, 0x87, 0x55, 0xd8, 0x32, 0x00, 0x06, 0x00, 0x00,
        ];
        let chunk = ReConfigChunk::try_from(RawChunk::from_bytes(BYTES).unwrap().0).unwrap();
        assert_eq!(chunk.parameters.len(), 1);
        match chunk.parameters[0] {
            Parameter::OutgoingSsnResetRequest(ref i) => {
                assert_eq!(i.request_seq_nbr, 2270550051);
                assert_eq!(i.response_seq_nbr, 1905748638);
                assert_eq!(i.sender_last_assigned_tsn, Tsn(2270550066));
                assert_eq!(i.streams, vec![StreamId(6)]);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn serialize_and_deserialize() {
        let chunk = ReConfigChunk {
            parameters: vec![Parameter::OutgoingSsnResetRequest(
                OutgoingSsnResetRequestParameter {
                    request_seq_nbr: 123,
                    response_seq_nbr: 456,
                    sender_last_assigned_tsn: Tsn(789),
                    streams: vec![StreamId(42), StreamId(43)],
                },
            )],
        };

        let mut serialized = vec![0; chunk.serialized_size()];
        chunk.serialize_to(&mut serialized);

        let deserialized =
            ReConfigChunk::try_from(RawChunk::from_bytes(&serialized).unwrap().0).unwrap();
        match deserialized.parameters[0] {
            Parameter::OutgoingSsnResetRequest(ref i) => {
                assert_eq!(i.request_seq_nbr, 123);
                assert_eq!(i.response_seq_nbr, 456);
                assert_eq!(i.sender_last_assigned_tsn, Tsn(789));
                assert_eq!(i.streams, vec![StreamId(42), StreamId(43)]);
            }
            _ => panic!(),
        }
    }
}
