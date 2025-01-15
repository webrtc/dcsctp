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
use crate::types::Fsn;
use crate::types::Mid;
use crate::types::Ssn;
use crate::types::StreamKey;

/// Represents data that is either received and extracted from a DATA/I-DATA chunk, or data that is
/// supposed to be sent, and wrapped in a DATA/I-DATA chunk (depending on peer capabilities).
///
/// The data wrapped in this structure is actually the same as the DATA/I-DATA chunk (actually the
/// union of them), but to avoid having all components be aware of the implementation details of the
/// different chunks, this abstraction is used instead. A notable difference is also that it doesn't
/// carry a transmission sequence number (TSN), as that is not known when a chunk is created
/// (assigned late, just when sending).
#[derive(Clone, Debug)]
pub(crate) struct Data {
    pub stream_key: StreamKey,
    pub ssn: Ssn,
    pub mid: Mid,
    pub fsn: Fsn,
    pub ppid: PpId,
    pub payload: Vec<u8>,
    pub is_beginning: bool,
    pub is_end: bool,
}

impl Default for Data {
    fn default() -> Self {
        Self {
            stream_key: StreamKey::Ordered(StreamId(0)),
            ssn: Ssn(0),
            mid: Mid(0),
            fsn: Fsn(0),
            ppid: PpId(0),
            payload: Default::default(),
            is_beginning: false,
            is_end: false,
        }
    }
}
