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

/// Indicates what the association supports, meaning that both parties support it and that feature
/// can be used.
#[derive(Default)]
pub struct Capabilities {
    /// RFC 3758 Partial Reliability Extension
    pub partial_reliability: bool,

    /// RFC 8260 Stream Schedulers and User Message Interleaving
    pub message_interleaving: bool,

    /// RFC 6525 Stream Reconfiguration
    pub reconfig: bool,

    /// RFC 9653 Zero Checksum
    pub zero_checksum: bool,

    /// Negotiated maximum incoming stream count.
    pub negotiated_maximum_incoming_streams: u16,

    /// Negotiated maximum outgoing stream count.
    pub negotiated_maximum_outgoing_streams: u16,
}
