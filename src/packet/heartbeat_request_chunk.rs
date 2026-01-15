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

pub(crate) const CHUNK_TYPE: u8 = 4;

/// Heartbeat Request (HEARTBEAT) chunk
///
/// See <https://datatracker.ietf.org/doc/html/rfc9260#section-3.3.5>.
///
/// ```txt
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   Type = 4    |  Chunk Flags  |       Heartbeat Length        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// \                                                               \
/// /          Heartbeat Information TLV (Variable-Length)          /
/// \                                                               \
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Default)]
pub struct HeartbeatRequestChunk {
    pub parameters: Vec<Parameter>,
}

impl TryFrom<RawChunk<'_>> for HeartbeatRequestChunk {
    type Error = Error;

    fn try_from(raw: RawChunk<'_>) -> Result<Self, Error> {
        ensure!(raw.typ == CHUNK_TYPE, ChunkParseError::InvalidType);

        let parameters = parameters_from_bytes(raw.value)?;
        Ok(Self { parameters })
    }
}

impl SerializableTlv for HeartbeatRequestChunk {
    fn serialize_to(&self, output: &mut [u8]) {
        let value = write_chunk_header(CHUNK_TYPE, 0, self.value_size(), output);
        parameters_serialize_to(&self.parameters, value);
    }

    fn value_size(&self) -> usize {
        parameters_serialized_size(&self.parameters)
    }
}

impl fmt::Display for HeartbeatRequestChunk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HEARTBEAT-REQ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::heartbeat_info_parameter::HeartbeatInfoParameter;

    #[test]
    fn from_capture() {
        // HEARTBEAT chunk (Information: 40 bytes)
        //     Chunk type: HEARTBEAT (4)
        //     Chunk flags: 0x00
        //     Chunk length: 44
        //     Heartbeat info parameter (Information: 36 bytes)
        //         Parameter type: Heartbeat info (0x0001)
        //         Parameter length: 40
        //         Heartbeat information: ad2436603726070000000000000000007b10000001…
        const BYTES: &[u8] = &[
            0x04, 0x00, 0x00, 0x2c, 0x00, 0x01, 0x00, 0x28, 0xad, 0x24, 0x36, 0x60, 0x37, 0x26,
            0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7b, 0x10, 0x00, 0x00,
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        let chunk =
            HeartbeatRequestChunk::try_from(RawChunk::from_bytes(BYTES).unwrap().0).unwrap();
        assert_eq!(chunk.parameters.len(), 1);

        const HEARTBEAT_INFO_BYTES: &[u8] = &[
            0xad, 0x24, 0x36, 0x60, 0x37, 0x26, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x7b, 0x10, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        match chunk.parameters[0] {
            Parameter::HeartbeatInfo(ref i) if i.info == HEARTBEAT_INFO_BYTES => {}
            _ => panic!(),
        }
    }

    #[test]
    fn serialize_and_deserialize() {
        let info: Vec<u8> = vec![1, 2, 3, 4];

        let chunk = HeartbeatRequestChunk {
            parameters: vec![Parameter::HeartbeatInfo(HeartbeatInfoParameter {
                info: info.clone(),
            })],
        };

        let mut serialized = vec![0; chunk.serialized_size()];
        chunk.serialize_to(&mut serialized);
        let deserialized =
            HeartbeatRequestChunk::try_from(RawChunk::from_bytes(&serialized).unwrap().0).unwrap();

        match deserialized.parameters[0] {
            Parameter::HeartbeatInfo(ref i) if i.info == info => {}
            _ => panic!(),
        }
    }
}
