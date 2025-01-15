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

use crate::api::PpId;
use crate::api::StreamId;
use crate::packet::data::Data;
use crate::types::Fsn;
use crate::types::Mid;
use crate::types::Ssn;
use crate::types::StreamKey;

pub struct DataGenerator {
    stream_id: StreamId,
    message_id: Mid,
    fsn: Fsn,
}

impl DataGenerator {
    pub fn new(stream_id: StreamId) -> Self {
        DataGenerator { stream_id, message_id: Mid(0), fsn: Fsn(0) }
    }
    pub fn ordered(&mut self, payload: &str, flags: &str) -> Data {
        let is_beginning = flags.contains("B");
        let is_end = flags.contains("E");
        if is_beginning {
            self.fsn = Fsn(0);
        } else {
            self.fsn = Fsn(self.fsn.0 + 1);
        }
        let data = Data {
            stream_key: StreamKey::Ordered(self.stream_id),
            ssn: Ssn(self.message_id.0 as u16),
            mid: self.message_id,
            fsn: self.fsn,
            ppid: PpId(53),
            payload: payload.as_bytes().to_vec(),
            is_beginning,
            is_end,
        };
        if is_end {
            self.message_id = Mid(self.message_id.0 + 1);
        }
        data
    }

    pub fn unordered(&mut self, payload: &str, flags: &str) -> Data {
        let is_beginning = flags.contains("B");
        let is_end = flags.contains("E");
        if is_beginning {
            self.fsn = Fsn(0);
        } else {
            self.fsn = Fsn(self.fsn.0 + 1);
        }
        let data = Data {
            stream_key: StreamKey::Unordered(self.stream_id),
            ssn: Ssn(0),
            mid: self.message_id,
            fsn: self.fsn,
            ppid: PpId(53),
            payload: payload.as_bytes().to_vec(),
            is_beginning,
            is_end,
        };
        if is_end {
            self.message_id = Mid(self.message_id.0 + 1);
        }
        data
    }
}
