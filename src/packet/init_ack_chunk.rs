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
use crate::packet::ensure;
use crate::packet::parameter::Parameter;
use crate::packet::parameter::parameters_from_bytes;
use crate::packet::parameter::parameters_serialize_to;
use crate::packet::parameter::parameters_serialized_size;
use crate::packet::read_u16_be;
use crate::packet::read_u32_be;
use crate::packet::write_u16_be;
use crate::packet::write_u32_be;
use crate::types::Tsn;
use std::fmt;

pub(crate) const CHUNK_TYPE: u8 = 2;

/// Initiation Acknowledgement (INIT ACK) chunk
///
/// See <https://datatracker.ietf.org/doc/html/rfc9260#section-3.3.3>.
///
/// ```txt
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   Type = 2    |  Chunk Flags  |         Chunk Length          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                         Initiate Tag                          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |               Advertised Receiver Window Credit               |
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
pub struct InitAckChunk {
    pub initiate_tag: u32,
    pub a_rwnd: u32,
    pub nbr_outbound_streams: u16,
    pub nbr_inbound_streams: u16,
    pub initial_tsn: Tsn,
    pub parameters: Vec<Parameter>,
}

impl TryFrom<RawChunk<'_>> for InitAckChunk {
    type Error = ChunkParseError;

    fn try_from(raw: RawChunk<'_>) -> Result<Self, ChunkParseError> {
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

impl SerializableTlv for InitAckChunk {
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

impl fmt::Display for InitAckChunk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "INIT-ACK, initiate_tag={}, initial_tsn={}",
            self.initiate_tag, self.initial_tsn.0
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::state_cookie_parameter::StateCookieParameter;

    #[test]
    fn init_ack_from_capture() {
        const BYTES: &[u8] = &[
            0x02, 0x00, 0x01, 0x24, 0x57, 0x9c, 0x2f, 0x98, 0x00, 0x02, 0x00, 0x00, 0x03, 0xe8,
            0x08, 0x00, 0x63, 0x96, 0x8e, 0xc7, 0xc0, 0x00, 0x00, 0x04, 0x80, 0x08, 0x00, 0x06,
            0xc0, 0x82, 0x00, 0x00, 0x00, 0x07, 0x01, 0x04, 0x4b, 0x41, 0x4d, 0x45, 0x2d, 0x42,
            0x53, 0x44, 0x20, 0x31, 0x2e, 0x31, 0x00, 0x00, 0x00, 0x00, 0x96, 0xb8, 0x38, 0x60,
            0x00, 0x00, 0x00, 0x00, 0x52, 0x5a, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x60, 0xea,
            0x00, 0x00, 0xb5, 0xaa, 0x19, 0xea, 0x31, 0xef, 0xa4, 0x2b, 0x90, 0x16, 0x7a, 0xde,
            0x57, 0x9c, 0x2f, 0x98, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13, 0x88, 0x13, 0x88, 0x00, 0x00, 0x01, 0x00,
            0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x5a, 0xde, 0x7a,
            0x16, 0x90, 0x00, 0x02, 0x00, 0x00, 0x03, 0xe8, 0x03, 0xe8, 0x25, 0x0d, 0x37, 0xe8,
            0x80, 0x00, 0x00, 0x04, 0xc0, 0x00, 0x00, 0x04, 0x80, 0x08, 0x00, 0x09, 0xc0, 0x0f,
            0xc1, 0x80, 0x82, 0x00, 0x00, 0x00, 0x80, 0x02, 0x00, 0x24, 0xab, 0x31, 0x44, 0x62,
            0x12, 0x1a, 0x15, 0x13, 0xfd, 0x5a, 0x5f, 0x69, 0xef, 0xaa, 0x06, 0xe9, 0xab, 0xd7,
            0x48, 0xcc, 0x3b, 0xd1, 0x4b, 0x60, 0xed, 0x7f, 0xa6, 0x44, 0xce, 0x4d, 0xd2, 0xad,
            0x80, 0x04, 0x00, 0x06, 0x00, 0x01, 0x00, 0x00, 0x80, 0x03, 0x00, 0x06, 0x80, 0xc1,
            0x00, 0x00, 0x02, 0x00, 0x01, 0x24, 0x57, 0x9c, 0x2f, 0x98, 0x00, 0x02, 0x00, 0x00,
            0x03, 0xe8, 0x08, 0x00, 0x63, 0x96, 0x8e, 0xc7, 0xc0, 0x00, 0x00, 0x04, 0x80, 0x08,
            0x00, 0x06, 0xc0, 0x82, 0x00, 0x00, 0x51, 0x95, 0x01, 0x88, 0x0d, 0x80, 0x7b, 0x19,
            0xe7, 0xf9, 0xc6, 0x18, 0x5c, 0x4a, 0xbf, 0x39, 0x32, 0xe5, 0x63, 0x8e,
        ];
        let c = InitAckChunk::try_from(RawChunk::from_bytes(BYTES).unwrap().0).unwrap();

        assert_eq!(c.initiate_tag, 0x579c2f98);
        assert_eq!(c.a_rwnd, 131072);
        assert_eq!(c.nbr_outbound_streams, 1000);
        assert_eq!(c.nbr_inbound_streams, 2048);
        assert_eq!(c.initial_tsn, Tsn(1670811335));
        assert_eq!(c.parameters.len(), 3);
        assert!(matches!(&c.parameters[0], Parameter::ForwardTsnSupported { .. }));
        assert!(matches!(&c.parameters[1], Parameter::SupportedExtensions { .. }));
        assert!(matches!(&c.parameters[2], Parameter::StateCookie { .. }));
    }

    #[test]
    fn serialize_and_deserialize() {
        let parameters =
            vec![Parameter::StateCookie(StateCookieParameter { cookie: vec![1, 2, 3, 4, 5] })];

        let chunk = InitAckChunk {
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
            InitAckChunk::try_from(RawChunk::from_bytes(&serialized).unwrap().0).unwrap();

        assert_eq!(deserialized.initiate_tag, 123);
        assert_eq!(deserialized.a_rwnd, 456);
        assert_eq!(deserialized.nbr_outbound_streams, 65535);
        assert_eq!(deserialized.nbr_inbound_streams, 65534);
        assert_eq!(deserialized.initial_tsn, Tsn(789));
        assert_eq!(deserialized.parameters.len(), 1);
    }
}
