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
use crate::packet::read_u16_be;
use crate::packet::read_u32_be;
use crate::packet::write_u16_be;
use crate::packet::write_u32_be;
use crate::types::Tsn;
use anyhow::Error;
use anyhow::ensure;
use std::fmt;

pub(crate) const CHUNK_TYPE: u8 = 1;

/// Initiation (INIT) chunk
///
/// See <https://datatracker.ietf.org/doc/html/rfc9260#section-3.3.2>.
///
/// ```txt
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   Type = 1    |  Chunk Flags  |      Chunk Length             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                         Initiate Tag                          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |          Advertised Receiver Window Credit (a_rwnd)           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  Number of Outbound Streams   |   Number of Inbound Streams   |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                          Initial TSN                          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// \                                                               \
/// /              Optional/Variable-Length Parameters              /
/// \                                                               \
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug)]
pub struct InitChunk {
    pub initiate_tag: u32,
    pub a_rwnd: u32,
    pub nbr_outbound_streams: u16,
    pub nbr_inbound_streams: u16,
    pub initial_tsn: Tsn,
    pub parameters: Vec<Parameter>,
}

impl TryFrom<RawChunk<'_>> for InitChunk {
    type Error = Error;

    fn try_from(raw: RawChunk<'_>) -> Result<Self, Error> {
        ensure!(raw.typ == CHUNK_TYPE, ChunkParseError::InvalidType);
        ensure!(raw.value.len() >= 16, ChunkParseError::InvalidLength);

        let initiate_tag = read_u32_be!(&raw.value[0..4]);
        let a_rwnd = read_u32_be!(&raw.value[4..8]);
        let nbr_outbound_streams = read_u16_be!(&raw.value[8..10]);
        let nbr_inbound_streams = read_u16_be!(&raw.value[10..12]);
        let initial_tsn = Tsn(read_u32_be!(&raw.value[12..16]));
        let parameters = parameters_from_bytes(&raw.value[16..])?;

        Ok(Self {
            initiate_tag,
            a_rwnd,
            nbr_outbound_streams,
            nbr_inbound_streams,
            initial_tsn,
            parameters,
        })
    }
}

impl SerializableTlv for InitChunk {
    fn serialize_to(&self, output: &mut [u8]) {
        let value = write_chunk_header(CHUNK_TYPE, 0, self.value_size(), output);
        write_u32_be!(&mut value[0..4], self.initiate_tag);
        write_u32_be!(&mut value[4..8], self.a_rwnd);
        write_u16_be!(&mut value[8..10], self.nbr_outbound_streams);
        write_u16_be!(&mut value[10..12], self.nbr_inbound_streams);
        write_u32_be!(&mut value[12..16], self.initial_tsn.0);
        parameters_serialize_to(&self.parameters, &mut value[16..]);
    }

    fn value_size(&self) -> usize {
        16 + parameters_serialized_size(&self.parameters)
    }
}

impl fmt::Display for InitChunk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "INIT, initiate_tag={}, initial_tsn={}", self.initiate_tag, self.initial_tsn)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::forward_tsn_supported_parameter::ForwardTsnSupportedParameter;
    use crate::packet::supported_extensions_parameter::SupportedExtensionsParameter;

    #[test]
    fn init_from_capture() {
        const BYTES: &[u8] = &[
            0x01, 0x00, 0x00, 0x5a, 0xde, 0x7a, 0x16, 0x90, 0x00, 0x02, 0x00, 0x00, 0x03, 0xe8,
            0x03, 0xe8, 0x25, 0x0d, 0x37, 0xe8, 0x80, 0x00, 0x00, 0x04, 0xc0, 0x00, 0x00, 0x04,
            0x80, 0x08, 0x00, 0x09, 0xc0, 0x0f, 0xc1, 0x80, 0x82, 0x00, 0x00, 0x00, 0x80, 0x02,
            0x00, 0x24, 0xab, 0x31, 0x44, 0x62, 0x12, 0x1a, 0x15, 0x13, 0xfd, 0x5a, 0x5f, 0x69,
            0xef, 0xaa, 0x06, 0xe9, 0xab, 0xd7, 0x48, 0xcc, 0x3b, 0xd1, 0x4b, 0x60, 0xed, 0x7f,
            0xa6, 0x44, 0xce, 0x4d, 0xd2, 0xad, 0x80, 0x04, 0x00, 0x06, 0x00, 0x01, 0x00, 0x00,
            0x80, 0x03, 0x00, 0x06, 0x80, 0xc1, 0x00, 0x00,
        ];
        let c = InitChunk::try_from(RawChunk::from_bytes(BYTES).unwrap().0).unwrap();

        assert_eq!(c.initiate_tag, 0xde7a1690);
        assert_eq!(c.a_rwnd, 131072);
        assert_eq!(c.nbr_outbound_streams, 1000);
        assert_eq!(c.nbr_inbound_streams, 1000);
        assert_eq!(c.initial_tsn, Tsn(621623272));
        assert_eq!(c.parameters.len(), 6);
        assert!(matches!(&c.parameters[1], Parameter::ForwardTsnSupported { .. }));
        assert!(matches!(&c.parameters[2], Parameter::SupportedExtensions { .. }));
    }

    #[test]
    fn serialize_and_deserialize() {
        let parameters = vec![
            Parameter::ForwardTsnSupported(ForwardTsnSupportedParameter {}),
            Parameter::SupportedExtensions(SupportedExtensionsParameter {
                chunk_types: vec![1, 2],
            }),
        ];

        let chunk = InitChunk {
            initiate_tag: 123,
            a_rwnd: 456,
            nbr_outbound_streams: 65535,
            nbr_inbound_streams: 65534,
            initial_tsn: Tsn(789),
            parameters,
        };

        let mut serialized = vec![0; chunk.serialized_size()];
        chunk.serialize_to(&mut serialized);

        let deserialized =
            InitChunk::try_from(RawChunk::from_bytes(&serialized).unwrap().0).unwrap();

        assert_eq!(deserialized.initiate_tag, 123);
        assert_eq!(deserialized.a_rwnd, 456);
        assert_eq!(deserialized.nbr_outbound_streams, 65535);
        assert_eq!(deserialized.nbr_inbound_streams, 65534);
        assert_eq!(deserialized.initial_tsn, Tsn(789));
        assert_eq!(deserialized.parameters.len(), 2);
    }
}
