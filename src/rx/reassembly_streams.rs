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

use crate::api::handover::HandoverReadiness;
use crate::api::handover::SocketHandoverState;
use crate::api::Message;
use crate::api::StreamId;
use crate::packet::data::Data;
use crate::packet::SkippedStream;
use crate::types::Tsn;

/// Implementations of this interface will be called when data is received, when data should be
/// skipped/forgotten or when sequence number should be reset.
///
/// As a result of these operations - mainly when data is received - the implementations of this
/// interface should notify when a message has been assembled, by calling the provided callback of
/// type `OnAssembledMessage`. How it assembles messages will depend on e.g. if a message was sent
/// on an ordered or unordered stream.
///
/// Implementations will - for each operation - indicate how much additional memory that has been
/// used as a result of performing the operation. This is used to limit the maximum amount of memory
/// used, to prevent out-of-memory situations.
pub trait ReassemblyStreams {
    /// Adds a data chunk to a stream as identified in `data`. If it was the last remaining chunk in
    /// a message, reassemble one (or several, in case of ordered chunks) messages.
    ///
    /// Returns the additional number of bytes added to the queue as a result of performing this
    /// operation. If this addition resulted in messages being assembled and delivered, this may be
    /// negative.
    fn add(&mut self, tsn: Tsn, data: Data, on_reassembled: &mut dyn FnMut(Message)) -> isize;

    /// Called for incoming FORWARD-TSN/I-FORWARD-TSN chunks - when the sender wishes the received
    /// to skip/forget about data up until the provided TSN. This is used to implement partial
    /// reliability, such as limiting the number of retransmissions or the an expiration duration.
    /// As a result of skipping data, this may result in the implementation being able to assemble
    /// messages in ordered streams.
    ///
    /// Returns the number of bytes removed from the queue as a result of this operation.
    fn handle_forward_tsn(
        &mut self,
        new_cumulative_ack: Tsn,
        skipped_streams: &[SkippedStream],
        on_reassembled: &mut dyn FnMut(Message),
    ) -> usize;

    /// Called for incoming (possibly deferred) RE_CONFIG chunks asking for either a few streams, or
    /// all streams (when the list is empty) to be reset - to have their next SSN or Message ID to
    /// be zero.
    fn reset_streams(&mut self, streams: &[StreamId]);

    fn get_handover_readiness(&self) -> HandoverReadiness;
    fn add_to_handover_state(&self, state: &mut SocketHandoverState);
    fn restore_from_state(&mut self, state: &SocketHandoverState);
}
