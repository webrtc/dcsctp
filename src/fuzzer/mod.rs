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

use crate::api::Options;
use crate::packet::error_causes::error_cause_from_bytes;
use crate::packet::parameter::parameters_from_bytes;
use crate::packet::sctp_packet::SctpPacket;

pub fn parse_parameters(data: &[u8]) {
    let _ = parameters_from_bytes(data);
}

pub fn parse_error_causes(data: &[u8]) {
    let _ = error_cause_from_bytes(data);
}

pub fn parse_packet(data: &[u8]) {
    let options = Options { disable_checksum_verification: true, ..Default::default() };
    let _ = SctpPacket::from_bytes(data, &options);
}
