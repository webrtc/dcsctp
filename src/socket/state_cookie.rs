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

use crate::packet::read_u16_be;
use crate::packet::read_u32_be;
use crate::packet::read_u64_be;
use crate::packet::write_u16_be;
use crate::packet::write_u32_be;
use crate::packet::write_u64_be;
use crate::socket::capabilities::Capabilities;
use crate::types::Tsn;

const COOKIE_SIZE: usize = 44;
const MAGIC_1: u32 = 1684230979;
const MAGIC_2: u32 = 1414558256;

pub struct StateCookie {
    pub peer_tag: u32,
    pub my_tag: u32,
    pub peer_initial_tsn: Tsn,
    pub my_initial_tsn: Tsn,
    pub a_rwnd: u32,
    pub tie_tag: u64,
    pub capabilities: Capabilities,
}

impl StateCookie {
    pub fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() != COOKIE_SIZE {
            return Err("Invalid state cookie size");
        }

        let magic1 = read_u32_be!(&data[0..4]);
        let magic2 = read_u32_be!(&data[4..8]);
        if magic1 != MAGIC_1 || magic2 != MAGIC_2 {
            return Err("Invalid state cookie magic");
        }

        Ok(StateCookie {
            peer_tag: read_u32_be!(&data[8..12]),
            my_tag: read_u32_be!(&data[12..16]),
            peer_initial_tsn: Tsn(read_u32_be!(&data[16..20])),
            my_initial_tsn: Tsn(read_u32_be!(&data[20..24])),
            a_rwnd: read_u32_be!(&data[24..28]),
            tie_tag: read_u64_be!(&data[28..36]),
            capabilities: Capabilities {
                partial_reliability: data[36] != 0,
                message_interleaving: data[37] != 0,
                reconfig: data[38] != 0,
                zero_checksum: data[39] != 0,
                negotiated_maximum_incoming_streams: read_u16_be!(&data[40..42]),
                negotiated_maximum_outgoing_streams: read_u16_be!(&data[42..44]),
            },
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut data: Vec<u8> = vec![0; COOKIE_SIZE];
        write_u32_be!(&mut data[0..4], MAGIC_1);
        write_u32_be!(&mut data[4..8], MAGIC_2);
        write_u32_be!(&mut data[8..12], self.peer_tag);
        write_u32_be!(&mut data[12..16], self.my_tag);
        write_u32_be!(&mut data[16..20], self.peer_initial_tsn.0);
        write_u32_be!(&mut data[20..24], self.my_initial_tsn.0);
        write_u32_be!(&mut data[24..28], self.a_rwnd);
        write_u64_be!(&mut data[28..36], self.tie_tag);
        data[36] = self.capabilities.partial_reliability as u8;
        data[37] = self.capabilities.message_interleaving as u8;
        data[38] = self.capabilities.reconfig as u8;
        data[39] = self.capabilities.zero_checksum as u8;
        write_u16_be!(&mut data[40..42], self.capabilities.negotiated_maximum_incoming_streams);
        write_u16_be!(&mut data[42..44], self.capabilities.negotiated_maximum_outgoing_streams);
        data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_deserialize() {
        let s = StateCookie {
            peer_tag: 123,
            my_tag: 321,
            peer_initial_tsn: Tsn(456),
            my_initial_tsn: Tsn(654),
            a_rwnd: 789,
            tie_tag: 1020304050,
            capabilities: Capabilities {
                partial_reliability: true,
                message_interleaving: false,
                reconfig: true,
                zero_checksum: true,
                negotiated_maximum_incoming_streams: 123,
                negotiated_maximum_outgoing_streams: 234,
            },
        };

        let serialized = s.serialize();
        assert_eq!(serialized.len(), COOKIE_SIZE);
        let deserialized = StateCookie::from_bytes(&serialized).unwrap();
        assert_eq!(deserialized.peer_tag, 123);
        assert_eq!(deserialized.my_tag, 321);
        assert_eq!(deserialized.peer_initial_tsn, Tsn(456));
        assert_eq!(deserialized.my_initial_tsn, Tsn(654));
        assert_eq!(deserialized.a_rwnd, 789);
        assert_eq!(deserialized.tie_tag, 1020304050);
        assert!(deserialized.capabilities.partial_reliability);
        assert!(!deserialized.capabilities.message_interleaving);
        assert!(deserialized.capabilities.reconfig);
        assert!(deserialized.capabilities.zero_checksum);
        assert_eq!(deserialized.capabilities.negotiated_maximum_incoming_streams, 123);
        assert_eq!(deserialized.capabilities.negotiated_maximum_outgoing_streams, 234);
    }
}
