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

use crate::api::LifecycleId;
use crate::api::SocketTime;
use crate::api::StreamId;
use crate::math::round_up_to_4;
use crate::packet::SkippedStream;
use crate::packet::data::Data;
use crate::packet::forward_tsn_chunk::ForwardTsnChunk;
use crate::packet::iforward_tsn_chunk::IForwardTsnChunk;
use crate::packet::sack_chunk::GapAckBlock;
use crate::types::Mid;
use crate::types::OutgoingMessageId;
use crate::types::Ssn;
use crate::types::StreamKey;
use crate::types::Tsn;
use std::cmp::max;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::VecDeque;
use std::time::Duration;

#[derive(Debug, PartialEq)]
enum Lifecycle {
    Active,
    ToBeRetransmitted,
    Abandoned,
}

#[derive(Debug, PartialEq)]
enum AckState {
    Unacked,
    Acked,
    Nacked,
}

#[derive(Debug, PartialEq)]
enum NackAction {
    Nothing,
    Retransmit,
    Abandon,
}

/// Contains variables scoped to a processing of an incoming SACK.
#[derive(Debug)]
pub(crate) struct AckInfo {
    /// Bytes acked by increasing cumulative_tsn_ack and gap_ack_blocks.
    pub bytes_acked: usize,

    /// Indicates if this SACK indicates that packet loss has occurred. Just because a packet is
    /// missing in the SACK doesn't necessarily mean that there is packet loss as that packet might
    /// be in-flight and received out-of-order. But when it has been reported missing consecutive
    /// times, it will eventually be considered "lost" and this will be set.
    pub has_packet_loss: bool,

    /// Highest TSN Newly Acknowledged, an SCTP variable.
    pub highest_tsn_acked: Tsn,

    /// The set of lifecycle IDs that were acked using cumulative_tsn_ack.
    pub acked_lifecycle_ids: Vec<LifecycleId>,

    /// The set of lifecycle IDs that were acked, but had been abandoned.
    pub abandoned_lifecycle_ids: Vec<LifecycleId>,
}

/// State for DATA chunks (message fragments) in the queue - used in tests.
#[derive(Debug, PartialEq)]
pub(crate) enum ChunkState {
    /// The chunk has been sent but not received yet (from the sender's point of view, as no SACK
    /// has been received yet that reference this chunk).
    InFlight,

    /// A SACK has been received which explicitly marked this chunk as missing - it's now NACKED
    /// and may be retransmitted if NACKED enough times.
    Nacked,

    /// A chunk that will be retransmitted when possible.
    ToBeRetransmitted,

    /// A SACK has been received which explicitly marked this chunk as received.
    Acked,

    /// A chunk whose message has expired or has been retransmitted too many times (RFC 3758). It
    /// will not be retransmitted anymore.
    Abandoned,
}

/// The number of times a packet must be NACKed before it's retransmitted, see
/// <https://datatracker.ietf.org/doc/html/rfc9260#section-7.2.4-5.1.1>.
const NUMBER_OF_NACKS_FOR_RETRANSMISSION: u8 = 3;

#[derive(Debug)]
struct Item {
    message_id: OutgoingMessageId,
    time_sent: SocketTime,
    max_retransmissions: u16,
    lifecycle: Lifecycle,
    ack_state: AckState,
    nack_count: u8,
    num_retransmissions: u16,
    expires_at: SocketTime,
    lifecycle_id: Option<LifecycleId>,
    data: Data,
}

impl Item {
    pub fn is_outstanding(&self) -> bool {
        self.ack_state == AckState::Unacked
    }
    pub fn is_acked(&self) -> bool {
        self.ack_state == AckState::Acked
    }
    pub fn is_nacked(&self) -> bool {
        self.ack_state == AckState::Nacked
    }
    pub fn is_abandoned(&self) -> bool {
        self.lifecycle == Lifecycle::Abandoned
    }
    /// Indicates if this chunk should be retransmitted.
    pub fn should_be_retransmitted(&self) -> bool {
        self.lifecycle == Lifecycle::ToBeRetransmitted
    }
    /// Indicates if this chunk has ever been retransmitted.
    pub fn has_been_retransmitted(&self) -> bool {
        self.num_retransmissions > 0
    }
    /// Given the current time, and the current state of this DATA chunk, it will indicate if it has
    /// expired (SCTP Partial Reliability Extension).
    pub fn has_expired(&self, now: SocketTime) -> bool {
        self.expires_at <= now
    }

    pub fn ack(&mut self) {
        if self.lifecycle != Lifecycle::Abandoned {
            self.lifecycle = Lifecycle::Active;
        }
        self.ack_state = AckState::Acked;
    }

    pub fn nack(&mut self, retransmit_now: bool) -> NackAction {
        self.ack_state = AckState::Nacked;
        self.nack_count = self.nack_count.saturating_add(1);
        if !self.should_be_retransmitted()
            && !self.is_abandoned()
            && (retransmit_now || self.nack_count >= NUMBER_OF_NACKS_FOR_RETRANSMISSION)
        {
            // Nacked enough times - it's considered lost.
            if self.num_retransmissions < self.max_retransmissions {
                self.lifecycle = Lifecycle::ToBeRetransmitted;
                return NackAction::Retransmit;
            }
            self.abandon();
            return NackAction::Abandon;
        }
        NackAction::Nothing
    }

    pub fn mark_as_retransmitted(&mut self) {
        self.lifecycle = Lifecycle::Active;
        self.ack_state = AckState::Unacked;
        self.nack_count = 0;
        self.num_retransmissions = self.num_retransmissions.saturating_add(1);
    }

    pub fn abandon(&mut self) {
        self.lifecycle = Lifecycle::Abandoned;
    }
}

/// This class keeps track of outstanding data chunks (sent, not yet acked) and handles acking,
/// nacking, rescheduling and abandoning.
///
/// Items are added to this queue as they are sent and will be removed when the peer acks them using
/// the cumulative TSN ack.
#[derive(Debug)]
pub(crate) struct OutstandingData {
    data_chunk_header_size: usize,
    last_cumulative_tsn_ack: Tsn,
    outstanding_data: VecDeque<Item>,
    unacked_bytes: usize,
    unacked_items: usize,
    to_be_fast_retransmitted: BTreeSet<Tsn>,
    to_be_retransmitted: BTreeSet<Tsn>,
    stream_reset_breakpoint_tsns: BTreeSet<Tsn>,
    unsent_messages_to_discard: Vec<(StreamId, OutgoingMessageId)>,
}

impl OutstandingData {
    pub fn new(data_chunk_header_size: usize, last_cumulative_tsn_ack: Tsn) -> Self {
        OutstandingData {
            data_chunk_header_size,
            last_cumulative_tsn_ack,
            outstanding_data: VecDeque::new(),
            unacked_bytes: 0,
            unacked_items: 0,
            to_be_fast_retransmitted: BTreeSet::new(),
            to_be_retransmitted: BTreeSet::new(),
            stream_reset_breakpoint_tsns: BTreeSet::new(),
            unsent_messages_to_discard: Vec::new(),
        }
    }

    pub(crate) fn is_consistent(&self) -> bool {
        let mut actual_unacked_payload_bytes = 0;
        let mut actual_unacked_items = 0;
        let mut actual_combined_to_be_retransmitted = BTreeSet::new();

        let mut tsn = self.last_cumulative_tsn_ack;
        for item in &self.outstanding_data {
            tsn += 1;
            if item.is_outstanding() {
                actual_unacked_payload_bytes +=
                    round_up_to_4!(self.data_chunk_header_size + item.data.payload.len());
                actual_unacked_items += 1;
            }

            if item.should_be_retransmitted() {
                actual_combined_to_be_retransmitted.insert(tsn);
            }
        }

        let mut combined_to_be_retransmitted = BTreeSet::new();
        combined_to_be_retransmitted.extend(self.to_be_retransmitted.iter());
        combined_to_be_retransmitted.extend(self.to_be_fast_retransmitted.iter());

        actual_unacked_payload_bytes == self.unacked_bytes
            && actual_unacked_items == self.unacked_items
            && actual_combined_to_be_retransmitted == combined_to_be_retransmitted
    }

    // Note: This may discard unsent messages - call `get_unsent_messages_to_discard`.
    pub fn handle_sack(
        &mut self,
        cumulative_tsn_ack: Tsn,
        gap_ack_blocks: &[GapAckBlock],
        is_in_fast_recovery: bool,
    ) -> AckInfo {
        let mut ack_info = AckInfo {
            highest_tsn_acked: cumulative_tsn_ack,
            bytes_acked: 0,
            has_packet_loss: false,
            acked_lifecycle_ids: vec![],
            abandoned_lifecycle_ids: vec![],
        };

        // Erase all items up to cumulative_tsn_ack.
        self.remove_acked(cumulative_tsn_ack, &mut ack_info);

        // ACK packets reported in the gap ack blocks
        self.ack_gap_blocks(cumulative_tsn_ack, gap_ack_blocks, &mut ack_info);

        // NACK and possibly mark for retransmit chunks that weren't acked.
        self.nack_between_ack_blocks(
            cumulative_tsn_ack,
            gap_ack_blocks,
            is_in_fast_recovery,
            &mut ack_info,
        );
        debug_assert!(self.is_consistent());
        ack_info
    }

    fn remove_acked(&mut self, cumulative_tsn_ack: Tsn, ack_info: &mut AckInfo) {
        while !self.outstanding_data.is_empty() && self.last_cumulative_tsn_ack < cumulative_tsn_ack
        {
            let tsn = self.last_cumulative_tsn_ack + 1;
            self.ack_chunk(tsn, ack_info);

            let index = tsn.distance_to(self.last_cumulative_tsn_ack) - 1;
            let item = self.outstanding_data.get_mut(index as usize).unwrap();
            if let Some(lifecycle_id) = &item.lifecycle_id {
                debug_assert!(item.data.is_end);
                if item.is_abandoned() {
                    ack_info.abandoned_lifecycle_ids.push(lifecycle_id.clone());
                } else {
                    ack_info.acked_lifecycle_ids.push(lifecycle_id.clone());
                }
            }

            self.outstanding_data.pop_front();
            self.last_cumulative_tsn_ack += 1;
        }
        self.stream_reset_breakpoint_tsns.retain(|b| *b > cumulative_tsn_ack + 1);
    }

    fn ack_gap_blocks(
        &mut self,
        cumulative_tsn_ack: Tsn,
        gap_ack_blocks: &[GapAckBlock],
        ack_info: &mut AckInfo,
    ) {
        // Mark all non-gaps as ACKED (but they can't be removed), from
        // <https://datatracker.ietf.org/doc/html/rfc9260#section-7.1>:
        //
        //   SCTP considers the information carried in the Gap Ack Blocks in the SACK chunk as
        //   advisory.
        //
        // Note that when NR-SACK is supported, this can be handled differently.
        for block in gap_ack_blocks {
            let start = cumulative_tsn_ack.add_to(block.start as u32);
            let end = cumulative_tsn_ack.add_to(block.end as u32);
            let mut tsn = start;
            while tsn <= end {
                if tsn > self.last_cumulative_tsn_ack && tsn < self.next_tsn() {
                    self.ack_chunk(tsn, ack_info);
                }
                tsn += 1;
            }
        }
    }

    fn nack_between_ack_blocks(
        &mut self,
        cumulative_tsn_ack: Tsn,
        gap_ack_blocks: &[GapAckBlock],
        is_in_fast_recovery: bool,
        ack_info: &mut AckInfo,
    ) {
        // Mark everything between the blocks as NACKed or to be transmitted.
        //
        // From <https://datatracker.ietf.org/doc/html/rfc9260#section-7.2.4>:
        //
        //   For each incoming SACK chunk, miss indications are incremented only for missing TSNs
        //   prior to the HTNA in the SACK chunk. [...]
        //
        //   Mark the DATA chunk(s) with three miss indications for retransmission.
        //
        // What this means is that only when there is a increasing stream of data received and there
        // are new packets seen (since last time), packets that are in-flight and between gaps
        // should be nacked. This means that SCTP relies on the T3-RTX-timer to re-send packets
        // otherwise.
        let mut max_tsn_to_nack = ack_info.highest_tsn_acked;
        if is_in_fast_recovery && cumulative_tsn_ack > self.last_cumulative_tsn_ack {
            // From <https://datatracker.ietf.org/doc/html/rfc9260#section-7.2.4-3>:
            //
            //   If an endpoint is in Fast Recovery and a SACK chunks arrives that advances the
            //   Cumulative TSN Ack Point, the miss indications are incremented for all TSNs
            //   reported missing in the SACK chunk.
            max_tsn_to_nack =
                cumulative_tsn_ack.add_to(gap_ack_blocks.last().map(|b| b.end as u32).unwrap_or(0));
        }

        let mut prev_block_last_acked = cumulative_tsn_ack;
        for block in gap_ack_blocks {
            let cur_block_first_acked = cumulative_tsn_ack.add_to(block.start as u32);
            let mut tsn = prev_block_last_acked + 1;
            while tsn < cur_block_first_acked && tsn <= max_tsn_to_nack {
                ack_info.has_packet_loss |= self.nack_chunk(tsn, false, !is_in_fast_recovery);
                tsn += 1;
            }
            prev_block_last_acked = cumulative_tsn_ack.add_to(block.end as u32);
        }

        // Note that packets are not NACKED which are above the highest gap-ack-block (or above the
        // cumulative ack TSN if no gap-ack-blocks) as only packets up until the highest_tsn_acked
        // (see above) should be considered when NACKing.
    }

    fn nack_chunk(&mut self, tsn: Tsn, retransmit_now: bool, do_fast_retransmit: bool) -> bool {
        let index = tsn.distance_to(self.last_cumulative_tsn_ack) - 1;
        let item = self.outstanding_data.get_mut(index as usize).unwrap();

        if item.is_outstanding() {
            self.unacked_bytes -=
                round_up_to_4!(self.data_chunk_header_size + item.data.payload.len());
            self.unacked_items -= 1;
        }

        match item.nack(retransmit_now) {
            NackAction::Nothing => false,
            NackAction::Retransmit => {
                if do_fast_retransmit {
                    self.to_be_fast_retransmitted.insert(tsn);
                } else {
                    self.to_be_retransmitted.insert(tsn);
                }
                true
            }
            NackAction::Abandon => {
                self.abandon_all_for(tsn);
                true
            }
        }
    }

    fn ack_chunk(&mut self, tsn: Tsn, ack_info: &mut AckInfo) {
        let index = tsn.distance_to(self.last_cumulative_tsn_ack) - 1;
        let item = self.outstanding_data.get_mut(index as usize).unwrap();
        if !item.is_acked() {
            let serialized_size =
                round_up_to_4!(self.data_chunk_header_size + item.data.payload.len());
            ack_info.bytes_acked += serialized_size;
            if item.is_outstanding() {
                self.unacked_bytes -= serialized_size;
                self.unacked_items -= 1;
            }
            if item.should_be_retransmitted() {
                self.to_be_retransmitted.remove(&tsn);
            }
            item.ack();
            ack_info.highest_tsn_acked = max(ack_info.highest_tsn_acked, tsn);
        }
    }

    pub fn has_unsent_messages_to_discard(&self) -> bool {
        !self.unsent_messages_to_discard.is_empty()
    }

    pub fn get_unsent_messages_to_discard(&mut self) -> Vec<(StreamId, OutgoingMessageId)> {
        std::mem::take(&mut self.unsent_messages_to_discard)
    }

    fn extract_chunks_that_can_fit(
        &mut self,
        mut max_size: usize,
        tsns: &mut BTreeSet<Tsn>,
    ) -> Vec<(Tsn, Data)> {
        let mut result: Vec<(Tsn, Data)> = vec![];
        for tsn in tsns.iter() {
            let index = tsn.distance_to(self.last_cumulative_tsn_ack) - 1;
            let item = self.outstanding_data.get_mut(index as usize).unwrap();

            debug_assert!(item.should_be_retransmitted());
            debug_assert!(!item.is_outstanding());
            debug_assert!(!item.is_abandoned());
            debug_assert!(!item.is_acked());

            let size = round_up_to_4!(self.data_chunk_header_size + item.data.payload.len());
            if size <= max_size {
                item.mark_as_retransmitted();
                result.push((*tsn, item.data.clone()));
                max_size -= size;
                self.unacked_bytes += size;
                self.unacked_items += 1;
            }
            if max_size <= self.data_chunk_header_size {
                break;
            }
        }
        for (tsn, _) in &result {
            tsns.remove(tsn);
        }
        result
    }

    /// Returns as many of the chunks that are eligible for fast retransmissions and that would fit
    /// in a single packet of `max_size`. The eligible chunks that didn't fit will be marked for
    /// (normal) retransmission and will not be returned if this method is called again.
    pub fn get_chunks_to_be_fast_retransmitted(&mut self, max_size: usize) -> Vec<(Tsn, Data)> {
        let mut tsns = std::mem::take(&mut self.to_be_fast_retransmitted);
        let chunks = self.extract_chunks_that_can_fit(max_size, &mut tsns);

        // From <https://datatracker.ietf.org/doc/html/rfc9260#section-7.2.4-5.5.1>:
        //
        //   Those TSNs marked for retransmission due to the Fast-Retransmit algorithm that did not
        //   fit in the sent datagram carrying K other TSNs are also marked as ineligible for a
        //   subsequent Fast Retransmit. However, as they are marked for retransmission, they will
        //   be retransmitted later on as soon as cwnd allows."
        self.to_be_retransmitted.append(&mut tsns);
        debug_assert!(self.is_consistent());
        chunks
    }

    /// Given `max_size` of space left in a packet, which chunks can be added to it?
    ///
    /// Note: This may discard unsent messages - call `get_unsent_messages_to_discard`.
    pub fn get_chunks_to_be_retransmitted(&mut self, max_size: usize) -> Vec<(Tsn, Data)> {
        let mut tsns = std::mem::take(&mut self.to_be_retransmitted);
        let chunks = self.extract_chunks_that_can_fit(max_size, &mut tsns);
        std::mem::swap(&mut self.to_be_retransmitted, &mut tsns);
        chunks
    }

    pub fn unacked_bytes(&self) -> usize {
        self.unacked_bytes
    }

    /// Returns the number of DATA chunks that are in-flight (not acked or nacked).
    pub fn unacked_items(&self) -> usize {
        self.unacked_items
    }

    /// Given the current time `now`, expire and abandon outstanding (sent at least once) chunks
    /// that have a limited lifetime.
    pub fn expire_outstanding_chunks(&mut self, now: SocketTime) {
        let mut tsns_to_expire: Vec<Tsn> = Vec::new();
        let mut tsn = self.last_cumulative_tsn_ack;
        for item in &mut self.outstanding_data {
            tsn += 1;
            // Chunks that are nacked can be expired. Care should be taken not to expire unacked
            // (in-flight) chunks as they might have been received, but the SACK is either delayed
            // or in-flight and may be received later.
            if item.is_abandoned() {
                // Already abandoned.
            } else if item.is_nacked() && item.has_expired(now) {
                log::debug!(
                    "Marking nacked chunk {} and message {} as expired",
                    tsn,
                    item.data.mid
                );
                tsns_to_expire.push(tsn);
            } else {
                // A non-expired chunk. No need to iterate any further.
                break;
            }
        }
        for tsn in tsns_to_expire {
            self.abandon_all_for(tsn);
        }
        debug_assert!(self.is_consistent());
    }

    pub fn is_empty(&self) -> bool {
        self.outstanding_data.is_empty()
    }

    pub fn has_data_to_be_fast_retransmitted(&self) -> bool {
        !self.to_be_fast_retransmitted.is_empty()
    }

    pub fn has_data_to_be_retransmitted(&self) -> bool {
        !self.to_be_retransmitted.is_empty() || !self.to_be_fast_retransmitted.is_empty()
    }

    pub fn last_cumulative_acked_tsn(&self) -> Tsn {
        self.last_cumulative_tsn_ack
    }

    pub fn next_tsn(&self) -> Tsn {
        self.highest_outstanding_tsn() + 1
    }

    pub fn highest_outstanding_tsn(&self) -> Tsn {
        self.last_cumulative_tsn_ack.add_to(self.outstanding_data.len() as u32)
    }

    /// Schedules `data` to be sent, with the provided partial reliability parameters. Returns the
    /// TSN if the item was actually added and scheduled to be sent, and nothing if it shouldn't be
    /// sent.
    ///
    /// Note: This may discard unsent messages - call `get_unsent_messages_to_discard`.
    pub fn insert(
        &mut self,
        message_id: OutgoingMessageId,
        data: &Data,
        time_sent: SocketTime,
        max_retransmissions: u16,
        expires_at: SocketTime,
        lifecycle_id: Option<LifecycleId>,
    ) -> Option<Tsn> {
        // Verify that the client has called `get_unsent_messages_to_discard`, so that this message
        // isn't a fragment of an already discarded message.
        debug_assert!(self.unsent_messages_to_discard.is_empty());

        // All chunks are always padded to be even divisible by 4.
        let chunk_size = round_up_to_4!(self.data_chunk_header_size + data.payload.len());
        self.unacked_bytes += chunk_size;
        self.unacked_items += 1;
        let tsn = self.next_tsn();
        let item = Item {
            message_id,
            time_sent,
            max_retransmissions,
            lifecycle: Lifecycle::Active,
            ack_state: AckState::Unacked,
            nack_count: 0,
            num_retransmissions: 0,
            expires_at,
            lifecycle_id,
            data: data.clone(),
        };
        self.outstanding_data.push_back(item);
        let item = self.outstanding_data.back().unwrap();
        if item.expires_at <= time_sent {
            // No need to send it - it was expired when it was in the send queue.
            log::debug!(
                "Marking freshly produced chunk {} and message {} as expired",
                tsn,
                item.data.mid
            );
            self.abandon_all_for(tsn);
            debug_assert!(self.is_consistent());
            return None;
        }

        debug_assert!(self.is_consistent());
        Some(tsn)
    }

    /// Abandon all chunks in this message, and if no end is found, add a placeholder "end", that
    /// will also be abandoned.
    fn abandon_all_for(&mut self, tsn: Tsn) {
        let index = tsn.distance_to(self.last_cumulative_tsn_ack) - 1;
        let item = self.outstanding_data.get(index as usize).unwrap();
        let message_id = item.message_id;
        let stream_key = item.data.stream_key;
        let ssn = item.data.ssn;
        let mid = item.data.mid;

        let mut end_found = false;
        let mut tsn = self.last_cumulative_tsn_ack;
        for other in &mut self.outstanding_data {
            tsn += 1;
            if other.message_id == message_id {
                end_found |= other.data.is_end;
                if !other.is_abandoned() {
                    if other.should_be_retransmitted() {
                        self.to_be_fast_retransmitted.remove(&tsn);
                        self.to_be_retransmitted.remove(&tsn);
                    }
                    other.abandon();
                }
            }
        }
        if end_found {
            return;
        }

        // There were remaining chunks to be produced for this message. Since the receiver may have
        // already received all chunks (up till now) for this message, we can't just FORWARD-TSN to
        // the last fragment in this (abandoned) message and start sending a new message, as the
        // receiver will then see a new message before the end of the previous one was seen (or
        // skipped over). So create a new fragment, representing the end, that the received will
        // never see as it is abandoned immediately and used as TSN in the sent FORWARD-TSN.
        let data = Data { stream_key, ssn, mid, is_end: true, ..Default::default() };
        let item = Item {
            message_id,
            time_sent: SocketTime::zero(),
            max_retransmissions: 0,
            lifecycle: Lifecycle::Abandoned,
            ack_state: AckState::Acked,
            nack_count: 0,
            num_retransmissions: 0,
            expires_at: SocketTime::zero(),
            lifecycle_id: None,
            data,
        };
        self.outstanding_data.push_back(item);
        self.unsent_messages_to_discard.push((stream_key.id(), message_id));
    }

    /// Nacks all outstanding data.
    ///
    /// Note: This may discard unsent messages - call `get_unsent_messages_to_discard`.
    pub fn nack_all(&mut self) {
        // A two-pass algorithm is needed, as NackItem will invalidate iterators.
        let mut tsns_to_nack: Vec<Tsn> = Vec::new();
        let mut tsn = self.last_cumulative_tsn_ack;
        for item in &self.outstanding_data {
            tsn += 1;
            if !item.is_acked() {
                tsns_to_nack.push(tsn);
            }
        }

        for tsn in &tsns_to_nack {
            self.nack_chunk(*tsn, true, false);
        }
        debug_assert!(self.is_consistent());
    }

    /// Creates a FORWARD-TSN chunk.
    pub fn create_forward_tsn(&self) -> ForwardTsnChunk {
        let mut skipped_per_ordered_stream: BTreeMap<StreamId, Ssn> = BTreeMap::new();
        let mut new_cumulative_tsn = self.last_cumulative_tsn_ack;

        let mut tsn = self.last_cumulative_tsn_ack;
        for item in &self.outstanding_data {
            tsn += 1;
            if self.stream_reset_breakpoint_tsns.contains(&tsn)
                || tsn != new_cumulative_tsn + 1
                || !item.is_abandoned()
            {
                break;
            }
            new_cumulative_tsn = tsn;

            if item.data.stream_key.is_ordered() {
                let entry =
                    skipped_per_ordered_stream.entry(item.data.stream_key.id()).or_insert(Ssn(0));
                if item.data.ssn > *entry {
                    *entry = item.data.ssn;
                }
            }
        }

        let skipped_streams: Vec<SkippedStream> = skipped_per_ordered_stream
            .iter()
            .map(|(stream_id, ssn)| SkippedStream::ForwardTsn(*stream_id, *ssn))
            .collect();

        ForwardTsnChunk { new_cumulative_tsn, skipped_streams }
    }

    /// Creates an I-FORWARD-TSN chunk.
    pub fn create_iforward_tsn(&self) -> IForwardTsnChunk {
        let mut skipped_per_stream: BTreeMap<StreamKey, Mid> = BTreeMap::new();
        let mut new_cumulative_tsn = self.last_cumulative_tsn_ack;

        let mut tsn = self.last_cumulative_tsn_ack;
        for item in &self.outstanding_data {
            tsn += 1;
            if self.stream_reset_breakpoint_tsns.contains(&tsn)
                || tsn != new_cumulative_tsn + 1
                || !item.is_abandoned()
            {
                break;
            }
            new_cumulative_tsn = tsn;

            let entry = skipped_per_stream.entry(item.data.stream_key).or_insert(Mid(0));
            if item.data.mid > *entry {
                *entry = item.data.mid;
            }
        }

        let skipped_streams: Vec<SkippedStream> = skipped_per_stream
            .iter()
            .map(|(stream_key, mid)| SkippedStream::IForwardTsn(*stream_key, *mid))
            .collect();

        IForwardTsnChunk { new_cumulative_tsn, skipped_streams }
    }

    /// Given the current time and a TSN, it returns the measured RTT between when the chunk was
    /// sent and now. It takes into account Karn's algorithm, so if the chunk has ever been
    /// retransmitted, it will return `None`.
    pub fn measure_rtt(&mut self, now: SocketTime, tsn: Tsn) -> Option<Duration> {
        if tsn > self.last_cumulative_tsn_ack && tsn < self.next_tsn() {
            let index = tsn.distance_to(self.last_cumulative_tsn_ack) - 1;
            let item = self.outstanding_data.get_mut(index as usize).unwrap();
            if !item.has_been_retransmitted() {
                return Some(now - item.time_sent);
            }
        }
        None
    }

    /// Returns the internal state of all queued chunks. This is only used in unit-tests.
    pub fn get_chunk_states_for_testing(&self) -> Vec<(Tsn, ChunkState)> {
        let mut states: Vec<(Tsn, ChunkState)> = vec![];
        states.push((self.last_cumulative_tsn_ack, ChunkState::Acked));
        let mut tsn = self.last_cumulative_tsn_ack;
        for item in &self.outstanding_data {
            tsn += 1;
            let state = if item.is_abandoned() {
                ChunkState::Abandoned
            } else if item.should_be_retransmitted() {
                ChunkState::ToBeRetransmitted
            } else if item.is_acked() {
                ChunkState::Acked
            } else if item.is_outstanding() {
                ChunkState::InFlight
            } else {
                ChunkState::Nacked
            };
            states.push((tsn, state));
        }
        states
    }

    /// Returns true if the next chunk that is not acked by the peer has been abandoned, which means
    /// that a FORWARD-TSN should be sent.
    pub fn should_send_forward_tsn(&self) -> bool {
        self.outstanding_data.front().map(|c| c.is_abandoned()).unwrap_or(false)
    }

    /// Sets the next TSN to be used. This is used in handover.
    pub fn reset_sequence_numbers(&mut self, last_cumulative_tsn: Tsn) {
        self.last_cumulative_tsn_ack = last_cumulative_tsn;
    }

    /// Called when an outgoing stream reset is sent, marking the last assigned TSN as a breakpoint
    /// that a FORWARD-TSN shouldn't cross.
    pub fn begin_reset_streams(&mut self) {
        self.stream_reset_breakpoint_tsns.insert(self.next_tsn());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::data_sequencer::DataSequencer;
    use itertools::Itertools;
    use std::collections::HashMap;

    const MESSAGE_ID: OutgoingMessageId = OutgoingMessageId(17);
    const DATA_CHUNK_HEADER_SIZE: usize = 16;

    fn now() -> SocketTime {
        SocketTime::zero()
    }

    fn no_expiry() -> SocketTime {
        SocketTime::infinite_future()
    }

    fn insert(buf: &mut OutstandingData, data: Data) -> Tsn {
        insert_limited_rtx(buf, data, u16::MAX)
    }

    fn insert_limited_rtx(buf: &mut OutstandingData, data: Data, max_retransmissions: u16) -> Tsn {
        buf.insert(MESSAGE_ID, &data, now(), max_retransmissions, no_expiry(), None).unwrap()
    }

    struct ChunkGenerator {
        current_message_id: OutgoingMessageId,
        data_sequencers: HashMap<StreamId, DataSequencer>,
    }

    impl ChunkGenerator {
        pub fn new() -> Self {
            Self { current_message_id: OutgoingMessageId(17), data_sequencers: HashMap::new() }
        }
        pub fn add(
            &mut self,
            buf: &mut OutstandingData,
            sid: StreamId,
            payload: &str,
            flags: &str,
        ) -> Tsn {
            self.add_limited_rtx(buf, sid, payload, flags, u16::MAX)
        }
        pub fn add_limited_rtx(
            &mut self,
            buf: &mut OutstandingData,
            sid: StreamId,
            payload: &str,
            flags: &str,
            max_retransmissions: u16,
        ) -> Tsn {
            let seq = self.data_sequencers.entry(sid).or_insert_with(|| DataSequencer::new(sid));
            let data = seq.ordered(payload, flags);
            let tsn = buf.insert(
                self.current_message_id,
                &data,
                now(),
                max_retransmissions,
                no_expiry(),
                None,
            );

            if flags.contains("E") {
                self.current_message_id += 1;
            }
            tsn.unwrap()
        }
    }

    #[test]
    fn has_initial_state() {
        let buf = OutstandingData::new(DATA_CHUNK_HEADER_SIZE, Tsn(9));

        assert!(buf.is_empty());
        assert_eq!(buf.unacked_bytes(), 0);
        assert_eq!(buf.unacked_items(), 0);
        assert!(!buf.has_data_to_be_retransmitted());
        assert_eq!(buf.last_cumulative_acked_tsn(), Tsn(9));
        assert_eq!(buf.next_tsn(), Tsn(10));
        assert_eq!(buf.highest_outstanding_tsn(), Tsn(9));
        assert_eq!(buf.get_chunk_states_for_testing(), vec![(Tsn(9), ChunkState::Acked)]);
        assert!(!buf.should_send_forward_tsn());
    }

    #[test]
    fn insert_chunk() {
        let mut buf = OutstandingData::new(DATA_CHUNK_HEADER_SIZE, Tsn(9));
        let mut seq = DataSequencer::new(StreamId(1));
        let tsn = insert(&mut buf, seq.ordered("a", "BE"));
        assert_eq!(tsn, Tsn(10));
        assert_eq!(buf.unacked_bytes(), DATA_CHUNK_HEADER_SIZE + round_up_to_4!(1));
        assert_eq!(buf.unacked_items(), 1);
        assert!(!buf.has_data_to_be_retransmitted());
        assert_eq!(buf.last_cumulative_acked_tsn(), Tsn(9));
        assert_eq!(buf.highest_outstanding_tsn(), Tsn(10));
        assert_eq!(buf.next_tsn(), Tsn(11));
        assert_eq!(
            buf.get_chunk_states_for_testing(),
            vec![(Tsn(9), ChunkState::Acked), (Tsn(10), ChunkState::InFlight)]
        );
    }

    #[test]
    fn acks_single_chunk() {
        let mut buf = OutstandingData::new(DATA_CHUNK_HEADER_SIZE, Tsn(9));
        let mut seq = DataSequencer::new(StreamId(1));
        let tsn = insert(&mut buf, seq.ordered("a", "BE"));
        assert_eq!(tsn, Tsn(10));
        let ack = buf.handle_sack(Tsn(10), &[], false);

        assert_eq!(ack.bytes_acked, DATA_CHUNK_HEADER_SIZE + round_up_to_4!(1));
        assert_eq!(ack.highest_tsn_acked, Tsn(10));
        assert!(!ack.has_packet_loss);

        assert_eq!(buf.unacked_bytes(), 0);
        assert_eq!(buf.unacked_items(), 0);
        assert!(!buf.has_data_to_be_retransmitted());
        assert_eq!(buf.last_cumulative_acked_tsn(), Tsn(10));
        assert_eq!(buf.highest_outstanding_tsn(), Tsn(10));
        assert_eq!(buf.next_tsn(), Tsn(11));
        assert_eq!(buf.get_chunk_states_for_testing(), vec![(Tsn(10), ChunkState::Acked)]);
    }

    #[test]
    fn acks_previous_chunk_doesnt_update() {
        let mut buf = OutstandingData::new(DATA_CHUNK_HEADER_SIZE, Tsn(9));
        let mut seq = DataSequencer::new(StreamId(1));
        let tsn = insert(&mut buf, seq.ordered("a", "BE"));
        assert_eq!(tsn, Tsn(10));
        let ack = buf.handle_sack(Tsn(9), &[], false);

        assert_eq!(ack.bytes_acked, 0);
        assert_eq!(ack.highest_tsn_acked, Tsn(9));
        assert!(!ack.has_packet_loss);

        assert_eq!(buf.unacked_bytes(), DATA_CHUNK_HEADER_SIZE + round_up_to_4!(1));
        assert_eq!(buf.unacked_items(), 1);
        assert!(!buf.has_data_to_be_retransmitted());
        assert_eq!(buf.last_cumulative_acked_tsn(), Tsn(9));
        assert_eq!(buf.highest_outstanding_tsn(), Tsn(10));
        assert_eq!(buf.next_tsn(), Tsn(11));
        assert_eq!(
            buf.get_chunk_states_for_testing(),
            vec![(Tsn(9), ChunkState::Acked), (Tsn(10), ChunkState::InFlight)]
        );
    }

    #[test]
    fn acks_and_nacks_with_gap_ack_blocks() {
        let mut buf = OutstandingData::new(DATA_CHUNK_HEADER_SIZE, Tsn(9));
        let mut seq = DataSequencer::new(StreamId(1));
        insert(&mut buf, seq.ordered("a", "B"));
        insert(&mut buf, seq.ordered("b", "E"));

        let ack = buf.handle_sack(Tsn(9), &[GapAckBlock::new(2, 2)], false);

        assert_eq!(ack.bytes_acked, DATA_CHUNK_HEADER_SIZE + round_up_to_4!(1));
        assert_eq!(ack.highest_tsn_acked, Tsn(11));
        assert!(!ack.has_packet_loss);

        assert_eq!(buf.unacked_bytes(), 0);
        assert_eq!(buf.unacked_items(), 0);
        assert!(!buf.has_data_to_be_retransmitted());
        assert_eq!(buf.last_cumulative_acked_tsn(), Tsn(9));
        assert_eq!(buf.highest_outstanding_tsn(), Tsn(11));
        assert_eq!(buf.next_tsn(), Tsn(12));
        assert_eq!(
            buf.get_chunk_states_for_testing(),
            vec![
                (Tsn(9), ChunkState::Acked),
                (Tsn(10), ChunkState::Nacked),
                (Tsn(11), ChunkState::Acked)
            ]
        );
    }

    #[test]
    fn nacks_three_times_with_same_tsn_doesnt_retransmit() {
        let mut buf = OutstandingData::new(DATA_CHUNK_HEADER_SIZE, Tsn(9));
        let mut seq = DataSequencer::new(StreamId(1));
        insert(&mut buf, seq.ordered("a", "B"));
        insert(&mut buf, seq.ordered("b", "E"));

        assert!(!buf.handle_sack(Tsn(9), &[GapAckBlock::new(2, 2)], false).has_packet_loss);
        assert!(!buf.handle_sack(Tsn(9), &[GapAckBlock::new(2, 2)], false).has_packet_loss);
        assert!(!buf.handle_sack(Tsn(9), &[GapAckBlock::new(2, 2)], false).has_packet_loss);

        assert_eq!(
            buf.get_chunk_states_for_testing(),
            vec![
                (Tsn(9), ChunkState::Acked),
                (Tsn(10), ChunkState::Nacked),
                (Tsn(11), ChunkState::Acked)
            ]
        );
    }

    #[test]
    fn nacks_three_times_results_in_retransmission() {
        let mut buf = OutstandingData::new(DATA_CHUNK_HEADER_SIZE, Tsn(9));
        let mut seq = DataSequencer::new(StreamId(1));
        insert(&mut buf, seq.ordered("a", "B"));
        insert(&mut buf, seq.ordered("b", ""));
        insert(&mut buf, seq.ordered("c", ""));
        insert(&mut buf, seq.ordered("d", "E"));

        assert!(!buf.handle_sack(Tsn(9), &[GapAckBlock::new(2, 2)], false).has_packet_loss);
        assert!(!buf.has_data_to_be_retransmitted());
        assert!(!buf.handle_sack(Tsn(9), &[GapAckBlock::new(2, 3)], false).has_packet_loss);
        assert!(!buf.has_data_to_be_retransmitted());

        let ack = buf.handle_sack(Tsn(9), &[GapAckBlock::new(2, 4)], false);
        assert_eq!(ack.bytes_acked, DATA_CHUNK_HEADER_SIZE + round_up_to_4!(1));
        assert_eq!(ack.highest_tsn_acked, Tsn(13));
        assert!(ack.has_packet_loss);

        assert!(buf.has_data_to_be_retransmitted());
        assert_eq!(
            buf.get_chunk_states_for_testing(),
            vec![
                (Tsn(9), ChunkState::Acked),
                (Tsn(10), ChunkState::ToBeRetransmitted),
                (Tsn(11), ChunkState::Acked),
                (Tsn(12), ChunkState::Acked),
                (Tsn(13), ChunkState::Acked)
            ]
        );
    }

    #[test]
    fn nacks_three_times_results_in_abandoning() {
        let mut buf = OutstandingData::new(DATA_CHUNK_HEADER_SIZE, Tsn(9));
        let mut seq = DataSequencer::new(StreamId(1));
        insert_limited_rtx(&mut buf, seq.ordered("a", "B"), 0);
        insert_limited_rtx(&mut buf, seq.ordered("b", ""), 0);
        insert_limited_rtx(&mut buf, seq.ordered("c", ""), 0);
        insert_limited_rtx(&mut buf, seq.ordered("d", "E"), 0);

        assert!(!buf.handle_sack(Tsn(9), &[GapAckBlock::new(2, 2)], false).has_packet_loss);
        assert!(!buf.has_data_to_be_retransmitted());
        assert!(!buf.handle_sack(Tsn(9), &[GapAckBlock::new(2, 3)], false).has_packet_loss);
        assert!(!buf.has_data_to_be_retransmitted());

        let ack = buf.handle_sack(Tsn(9), &[GapAckBlock::new(2, 4)], false);
        assert_eq!(ack.bytes_acked, DATA_CHUNK_HEADER_SIZE + round_up_to_4!(1));
        assert_eq!(ack.highest_tsn_acked, Tsn(13));
        assert!(ack.has_packet_loss);

        assert!(!buf.has_data_to_be_retransmitted());
        assert_eq!(
            buf.get_chunk_states_for_testing(),
            vec![
                (Tsn(9), ChunkState::Acked),
                (Tsn(10), ChunkState::Abandoned),
                (Tsn(11), ChunkState::Abandoned),
                (Tsn(12), ChunkState::Abandoned),
                (Tsn(13), ChunkState::Abandoned)
            ]
        );
    }

    #[test]
    fn nacks_extremely_many_times_doesnt_overflow() {
        // This test verifies that the nack counter doesn't overflow. Found by fuzzing.
        let mut buf = OutstandingData::new(DATA_CHUNK_HEADER_SIZE, Tsn(9));
        let mut seq = DataSequencer::new(StreamId(1));
        insert_limited_rtx(&mut buf, seq.ordered("a", "B"), 0);

        const FRAGMENT_COUNT: u16 = 1000;
        for _ in 0..FRAGMENT_COUNT {
            insert_limited_rtx(&mut buf, seq.ordered("b", ""), 0);
        }

        for i in 0..FRAGMENT_COUNT {
            buf.handle_sack(Tsn(9), &[GapAckBlock::new(2, 2 + i)], false);
        }
    }

    #[test]
    fn nacks_three_times_results_in_abandoning_with_placeholder() {
        let mut buf = OutstandingData::new(DATA_CHUNK_HEADER_SIZE, Tsn(9));
        let mut seq = DataSequencer::new(StreamId(1));
        insert_limited_rtx(&mut buf, seq.ordered("a", "B"), 0);
        insert_limited_rtx(&mut buf, seq.ordered("b", ""), 0);
        insert_limited_rtx(&mut buf, seq.ordered("c", ""), 0);
        insert_limited_rtx(&mut buf, seq.ordered("d", ""), 0);

        assert!(!buf.handle_sack(Tsn(9), &[GapAckBlock::new(2, 2)], false).has_packet_loss);
        assert!(!buf.has_data_to_be_retransmitted());
        assert!(!buf.handle_sack(Tsn(9), &[GapAckBlock::new(2, 3)], false).has_packet_loss);
        assert!(!buf.has_data_to_be_retransmitted());
        assert!(!buf.has_unsent_messages_to_discard());
        let ack = buf.handle_sack(Tsn(9), &[GapAckBlock::new(2, 4)], false);
        assert_eq!(ack.bytes_acked, DATA_CHUNK_HEADER_SIZE + round_up_to_4!(1));
        assert_eq!(ack.highest_tsn_acked, Tsn(13));
        assert!(ack.has_packet_loss);

        assert!(!buf.has_data_to_be_retransmitted());
        assert_eq!(
            buf.get_chunk_states_for_testing(),
            vec![
                (Tsn(9), ChunkState::Acked),
                (Tsn(10), ChunkState::Abandoned),
                (Tsn(11), ChunkState::Abandoned),
                (Tsn(12), ChunkState::Abandoned),
                (Tsn(13), ChunkState::Abandoned),
                (Tsn(14), ChunkState::Abandoned)
            ]
        );
        assert_eq!(buf.get_unsent_messages_to_discard(), vec![(StreamId(1), MESSAGE_ID)]);
    }

    #[test]
    fn expires_chunk_before_it_is_inserted() {
        let now = now();
        let mut buf = OutstandingData::new(DATA_CHUNK_HEADER_SIZE, Tsn(9));
        let mut seq = DataSequencer::new(StreamId(1));

        let expires_at = now + Duration::from_millis(1);
        assert!(
            buf.insert(
                MESSAGE_ID,
                &seq.ordered("a", "B"),
                now + Duration::from_millis(0),
                u16::MAX,
                expires_at,
                None,
            )
            .is_some()
        );
        assert!(
            buf.insert(
                MESSAGE_ID,
                &seq.ordered("b", ""),
                now + Duration::from_millis(0),
                u16::MAX,
                expires_at,
                None,
            )
            .is_some()
        );

        // Time reaches "expires_at"
        assert!(
            buf.insert(
                MESSAGE_ID,
                &seq.ordered("c", "E"),
                now + Duration::from_millis(1),
                u16::MAX,
                expires_at,
                None,
            )
            .is_none()
        );
        assert!(!buf.has_data_to_be_retransmitted());
        assert_eq!(buf.last_cumulative_acked_tsn(), Tsn(9));
        assert_eq!(buf.highest_outstanding_tsn(), Tsn(12));
        assert_eq!(buf.next_tsn(), Tsn(13));
        assert_eq!(
            buf.get_chunk_states_for_testing(),
            vec![
                (Tsn(9), ChunkState::Acked),
                (Tsn(10), ChunkState::Abandoned),
                (Tsn(11), ChunkState::Abandoned),
                (Tsn(12), ChunkState::Abandoned),
            ]
        );
        assert!(!buf.has_unsent_messages_to_discard());
    }

    #[test]
    fn expires_chunk_before_it_is_inserted_adds_placeholder() {
        let now = now();
        let mut buf = OutstandingData::new(DATA_CHUNK_HEADER_SIZE, Tsn(9));
        let mut seq = DataSequencer::new(StreamId(1));

        let expires_at = now + Duration::from_millis(1);
        assert!(
            buf.insert(
                MESSAGE_ID,
                &seq.ordered("a", "B"),
                now + Duration::from_millis(0),
                u16::MAX,
                expires_at,
                None,
            )
            .is_some()
        );
        assert!(
            buf.insert(
                MESSAGE_ID,
                &seq.ordered("b", ""),
                now + Duration::from_millis(0),
                u16::MAX,
                expires_at,
                None,
            )
            .is_some()
        );
        assert!(!buf.has_unsent_messages_to_discard());

        // Time reaches "expires_at", but not an "end" chunk.
        assert!(
            buf.insert(
                MESSAGE_ID,
                &seq.ordered("c", ""),
                now + Duration::from_millis(1),
                u16::MAX,
                expires_at,
                None,
            )
            .is_none()
        );
        assert!(!buf.has_data_to_be_retransmitted());
        assert_eq!(buf.last_cumulative_acked_tsn(), Tsn(9));
        assert_eq!(buf.highest_outstanding_tsn(), Tsn(13));
        assert_eq!(buf.next_tsn(), Tsn(14));
        assert_eq!(
            buf.get_chunk_states_for_testing(),
            vec![
                (Tsn(9), ChunkState::Acked),
                (Tsn(10), ChunkState::Abandoned),
                (Tsn(11), ChunkState::Abandoned),
                (Tsn(12), ChunkState::Abandoned),
                (Tsn(13), ChunkState::Abandoned),
            ]
        );
        assert_eq!(buf.get_unsent_messages_to_discard(), vec![(StreamId(1), MESSAGE_ID)]);
    }

    #[test]
    fn can_generate_forward_tsn() {
        let mut buf = OutstandingData::new(DATA_CHUNK_HEADER_SIZE, Tsn(9));
        let mut seq = DataSequencer::new(StreamId(1));
        insert_limited_rtx(&mut buf, seq.ordered("a", "B"), 0);
        insert_limited_rtx(&mut buf, seq.ordered("b", ""), 0);
        insert_limited_rtx(&mut buf, seq.ordered("c", "E"), 0);

        buf.nack_all();

        assert_eq!(
            buf.get_chunk_states_for_testing(),
            vec![
                (Tsn(9), ChunkState::Acked),
                (Tsn(10), ChunkState::Abandoned),
                (Tsn(11), ChunkState::Abandoned),
                (Tsn(12), ChunkState::Abandoned),
            ]
        );

        assert!(buf.should_send_forward_tsn());
        let chunk = buf.create_forward_tsn();
        assert_eq!(chunk.new_cumulative_tsn, Tsn(12));
    }

    #[test]
    fn ack_with_gap_blocks_from_rfc9260_section334() {
        let mut buf = OutstandingData::new(DATA_CHUNK_HEADER_SIZE, Tsn(9));
        let mut seq = DataSequencer::new(StreamId(1));
        insert(&mut buf, seq.ordered("a", "B"));
        insert(&mut buf, seq.ordered("b", ""));
        insert(&mut buf, seq.ordered("c", ""));
        insert(&mut buf, seq.ordered("d", ""));
        insert(&mut buf, seq.ordered("e", ""));
        insert(&mut buf, seq.ordered("f", ""));
        insert(&mut buf, seq.ordered("g", ""));
        insert(&mut buf, seq.ordered("h", "E"));

        assert_eq!(
            buf.get_chunk_states_for_testing(),
            vec![
                (Tsn(9), ChunkState::Acked),
                (Tsn(10), ChunkState::InFlight),
                (Tsn(11), ChunkState::InFlight),
                (Tsn(12), ChunkState::InFlight),
                (Tsn(13), ChunkState::InFlight),
                (Tsn(14), ChunkState::InFlight),
                (Tsn(15), ChunkState::InFlight),
                (Tsn(16), ChunkState::InFlight),
                (Tsn(17), ChunkState::InFlight)
            ]
        );

        buf.handle_sack(Tsn(12), &[GapAckBlock::new(2, 3), GapAckBlock::new(5, 5)], false);

        assert_eq!(
            buf.get_chunk_states_for_testing(),
            vec![
                (Tsn(12), ChunkState::Acked),
                (Tsn(13), ChunkState::Nacked),
                (Tsn(14), ChunkState::Acked),
                (Tsn(15), ChunkState::Acked),
                (Tsn(16), ChunkState::Nacked),
                (Tsn(17), ChunkState::Acked)
            ]
        );
    }

    #[test]
    fn measure_rtt() {
        let mut buf = OutstandingData::new(DATA_CHUNK_HEADER_SIZE, Tsn(9));
        let mut seq = DataSequencer::new(StreamId(1));
        let now = now();

        buf.insert(OutgoingMessageId(1), &seq.ordered("a", "BE"), now, u16::MAX, no_expiry(), None);
        let tsn = buf
            .insert(
                OutgoingMessageId(2),
                &seq.ordered("b", "BE"),
                now + Duration::from_millis(1),
                u16::MAX,
                no_expiry(),
                None,
            )
            .unwrap();
        buf.insert(
            OutgoingMessageId(3),
            &seq.ordered("c", "BE"),
            now + Duration::from_millis(2),
            u16::MAX,
            no_expiry(),
            None,
        );

        let duration = buf.measure_rtt(now + Duration::from_millis(123), tsn).unwrap();
        assert_eq!(duration, Duration::from_millis(122));
    }

    #[test]
    fn must_retransmit_before_getting_nacked_again() {
        let mut buf = OutstandingData::new(DATA_CHUNK_HEADER_SIZE, Tsn(9));
        let mut seq = DataSequencer::new(StreamId(1));
        for i in 10..=20 {
            let flags = match i {
                10 => "B",
                20 => "E",
                _ => "",
            };
            insert_limited_rtx(&mut buf, seq.ordered("a", flags), /* max_retransmissions */ 1);
        }

        buf.handle_sack(Tsn(9), &[GapAckBlock::new(2, 2)], false);
        assert!(!buf.has_data_to_be_retransmitted());

        buf.handle_sack(Tsn(9), &[GapAckBlock::new(2, 3)], false);
        assert!(!buf.has_data_to_be_retransmitted());

        let ack = buf.handle_sack(Tsn(9), &[GapAckBlock::new(2, 4)], false);
        assert!(ack.has_packet_loss);
        assert!(buf.has_data_to_be_retransmitted());

        // Don't call get_chunks_to_be_retransmitted yet - simulate that the congestion window
        // doesn't allow it to be retransmitted yet. It does however get more SACKs indicating
        // packet loss.

        buf.handle_sack(Tsn(9), &[GapAckBlock::new(2, 5)], false);
        assert!(buf.has_data_to_be_retransmitted());
        buf.handle_sack(Tsn(9), &[GapAckBlock::new(2, 6)], false);
        assert!(buf.has_data_to_be_retransmitted());
        let ack = buf.handle_sack(Tsn(9), &[GapAckBlock::new(2, 7)], false);
        assert!(!ack.has_packet_loss);
        assert!(buf.has_data_to_be_retransmitted());

        // Now it's retransmitted.
        let chunks = buf.get_chunks_to_be_fast_retransmitted(1000);
        assert_eq!(chunks.iter().map(|c| c.0).collect_vec(), &[Tsn(10)]);
        assert!(buf.get_chunks_to_be_retransmitted(1000).is_empty());

        // And obviously lost, as it will get NACKed and abandoned.
        buf.handle_sack(Tsn(9), &[GapAckBlock::new(2, 8)], false);
        assert!(!buf.has_data_to_be_retransmitted());
        buf.handle_sack(Tsn(9), &[GapAckBlock::new(2, 9)], false);
        assert!(!buf.has_data_to_be_retransmitted());
        let ack = buf.handle_sack(Tsn(9), &[GapAckBlock::new(2, 10)], false);
        assert!(ack.has_packet_loss);
        assert!(!buf.has_data_to_be_retransmitted());
    }

    #[test]
    fn lifecyle_returns_acked_items_in_ack_info() {
        let mut buf = OutstandingData::new(DATA_CHUNK_HEADER_SIZE, Tsn(9));
        let mut seq = DataSequencer::new(StreamId(1));

        buf.insert(
            OutgoingMessageId(1),
            &seq.ordered("a", "BE"),
            now(),
            u16::MAX,
            no_expiry(),
            LifecycleId::new(42),
        );
        buf.insert(
            OutgoingMessageId(2),
            &seq.ordered("b", "BE"),
            now(),
            u16::MAX,
            no_expiry(),
            LifecycleId::new(43),
        );
        buf.insert(
            OutgoingMessageId(3),
            &seq.ordered("c", "BE"),
            now(),
            u16::MAX,
            no_expiry(),
            LifecycleId::new(44),
        );

        let ack = buf.handle_sack(Tsn(11), &[], false);
        assert_eq!(ack.acked_lifecycle_ids, &[LifecycleId::from(42), LifecycleId::from(43)]);

        let ack = buf.handle_sack(Tsn(12), &[], false);
        assert_eq!(ack.acked_lifecycle_ids, &[LifecycleId::from(44)]);
    }

    #[test]
    fn lifecycle_returns_abandoned_nacked_three_times() {
        let mut buf = OutstandingData::new(DATA_CHUNK_HEADER_SIZE, Tsn(9));
        let mut seq = DataSequencer::new(StreamId(1));

        buf.insert(
            OutgoingMessageId(1),
            &seq.ordered("a", "B"),
            now(),
            /* max_retransmissions */ 0,
            no_expiry(),
            None,
        );
        buf.insert(
            OutgoingMessageId(1),
            &seq.ordered("b", ""),
            now(),
            /* max_retransmissions */ 0,
            no_expiry(),
            None,
        );
        buf.insert(
            OutgoingMessageId(1),
            &seq.ordered("c", ""),
            now(),
            /* max_retransmissions */ 0,
            no_expiry(),
            None,
        );
        buf.insert(
            OutgoingMessageId(1),
            &seq.ordered("d", "E"),
            now(),
            /* max_retransmissions */ 0,
            no_expiry(),
            LifecycleId::new(42),
        );

        buf.handle_sack(Tsn(9), &[GapAckBlock::new(2, 2)], false);
        assert!(!buf.has_data_to_be_retransmitted());

        buf.handle_sack(Tsn(9), &[GapAckBlock::new(2, 3)], false);
        assert!(!buf.has_data_to_be_retransmitted());

        let ack = buf.handle_sack(Tsn(9), &[GapAckBlock::new(2, 4)], false);
        assert!(ack.has_packet_loss);
        assert!(ack.abandoned_lifecycle_ids.is_empty());

        assert!(buf.should_send_forward_tsn());
        let fwd = buf.create_forward_tsn();
        assert_eq!(fwd.new_cumulative_tsn, Tsn(13));

        let ack = buf.handle_sack(Tsn(13), &[], false);
        assert!(!ack.has_packet_loss);
        assert_eq!(ack.abandoned_lifecycle_ids, &[LifecycleId::from(42)]);
    }

    #[test]
    fn lifecycle_returns_abandoned_after_t3rtx_expired() {
        let mut buf = OutstandingData::new(DATA_CHUNK_HEADER_SIZE, Tsn(9));
        let mut seq = DataSequencer::new(StreamId(1));

        buf.insert(
            OutgoingMessageId(1),
            &seq.ordered("a", "B"),
            now(),
            /* max_retransmissions */ 0,
            no_expiry(),
            None,
        );
        buf.insert(
            OutgoingMessageId(1),
            &seq.ordered("b", ""),
            now(),
            /* max_retransmissions */ 0,
            no_expiry(),
            None,
        );
        buf.insert(
            OutgoingMessageId(1),
            &seq.ordered("c", ""),
            now(),
            /* max_retransmissions */ 0,
            no_expiry(),
            None,
        );
        buf.insert(
            OutgoingMessageId(1),
            &seq.ordered("d", "E"),
            now(),
            /* max_retransmissions */ 0,
            no_expiry(),
            LifecycleId::new(42),
        );

        assert_eq!(
            buf.get_chunk_states_for_testing(),
            vec![
                (Tsn(9), ChunkState::Acked),
                (Tsn(10), ChunkState::InFlight),
                (Tsn(11), ChunkState::InFlight),
                (Tsn(12), ChunkState::InFlight),
                (Tsn(13), ChunkState::InFlight),
            ]
        );

        buf.handle_sack(Tsn(9), &[GapAckBlock::new(2, 4)], false);
        assert!(!buf.has_data_to_be_retransmitted());

        assert_eq!(
            buf.get_chunk_states_for_testing(),
            vec![
                (Tsn(9), ChunkState::Acked),
                (Tsn(10), ChunkState::Nacked),
                (Tsn(11), ChunkState::Acked),
                (Tsn(12), ChunkState::Acked),
                (Tsn(13), ChunkState::Acked),
            ]
        );

        // T3-rtx triggered.
        buf.nack_all();

        assert_eq!(
            buf.get_chunk_states_for_testing(),
            vec![
                (Tsn(9), ChunkState::Acked),
                (Tsn(10), ChunkState::Abandoned),
                (Tsn(11), ChunkState::Abandoned),
                (Tsn(12), ChunkState::Abandoned),
                (Tsn(13), ChunkState::Abandoned),
            ]
        );

        // This will generate a FORWARD-TSN, which is acked
        assert!(buf.should_send_forward_tsn());
        let fwd = buf.create_forward_tsn();
        assert_eq!(fwd.new_cumulative_tsn, Tsn(13));

        let ack = buf.handle_sack(Tsn(13), &[], false);
        assert!(!ack.has_packet_loss);
        assert_eq!(ack.abandoned_lifecycle_ids, &[LifecycleId::from(42)]);
    }

    #[test]
    fn generates_forward_tsn_until_next_stream_reset_tsn() {
        // This test generates:
        // * Stream 1: TSN 10, 11, 12 <RESET>
        // * Stream 2: TSN 13, 14 <RESET>
        // * Stream 3: TSN 15, 16
        //
        // Then it expires chunk 12-15, and ensures that the generated FORWARD-TSN only includes up
        // till TSN 12 until the cum ack TSN has reached 12, and then 13 and 14 are included, and
        // then after the cum ack TSN has reached 14, then 15 is included.
        //
        // What it shouldn't do, is to generate a FORWARD-TSN directly at the start with new TSN=15,
        // and setting [(sid=1, ssn=44), (sid=2, ssn=46), (sid=3, ssn=47)], because that will
        // confuse the receiver at TSN=17, receiving SID=1, SSN=0 (it's reset!), expecting SSN to be
        // 45.
        let mut buf = OutstandingData::new(DATA_CHUNK_HEADER_SIZE, Tsn(9));
        let mut seq = ChunkGenerator::new();

        // TSN 10-12
        seq.add_limited_rtx(&mut buf, StreamId(1), "a", "BE", 0);
        seq.add_limited_rtx(&mut buf, StreamId(1), "b", "BE", 0);
        seq.add_limited_rtx(&mut buf, StreamId(1), "c", "BE", 0);
        buf.begin_reset_streams();

        // TSN 13, 14
        seq.add_limited_rtx(&mut buf, StreamId(2), "d", "BE", 0);
        seq.add_limited_rtx(&mut buf, StreamId(2), "e", "BE", 0);
        buf.begin_reset_streams();

        // TSN 15, 16
        seq.add_limited_rtx(&mut buf, StreamId(3), "f", "BE", 0);
        assert_eq!(seq.add(&mut buf, StreamId(3), "g", "BE"), Tsn(16));

        assert!(!buf.should_send_forward_tsn());
        buf.handle_sack(Tsn(11), &[], false);
        buf.nack_all();

        assert_eq!(
            buf.get_chunk_states_for_testing(),
            vec![
                (Tsn(11), ChunkState::Acked),
                (Tsn(12), ChunkState::Abandoned),
                (Tsn(13), ChunkState::Abandoned),
                (Tsn(14), ChunkState::Abandoned),
                (Tsn(15), ChunkState::Abandoned),
                (Tsn(16), ChunkState::ToBeRetransmitted),
            ]
        );

        assert!(buf.should_send_forward_tsn());
        let fwd = buf.create_forward_tsn();
        assert_eq!(fwd.new_cumulative_tsn, Tsn(12));
        assert_eq!(fwd.skipped_streams, vec!(SkippedStream::ForwardTsn(StreamId(1), Ssn(2))));

        // Ack 12, allowing a FORWARD-TSN that spans to TSN=14 to be created.
        buf.handle_sack(Tsn(12), &[], false);
        assert!(buf.should_send_forward_tsn());
        let fwd = buf.create_forward_tsn();
        assert_eq!(fwd.new_cumulative_tsn, Tsn(14));
        assert_eq!(fwd.skipped_streams, vec!(SkippedStream::ForwardTsn(StreamId(2), Ssn(1))));

        // Ack 13, allowing a FORWARD-TSN that spans to TSN=14 to be created.
        buf.handle_sack(Tsn(13), &[], false);
        assert!(buf.should_send_forward_tsn());
        let fwd = buf.create_forward_tsn();
        assert_eq!(fwd.new_cumulative_tsn, Tsn(14));
        assert_eq!(fwd.skipped_streams, vec!(SkippedStream::ForwardTsn(StreamId(2), Ssn(1))));

        // Ack 14, allowing a FORWARD-TSN that spans to TSN=15 to be created.
        buf.handle_sack(Tsn(14), &[], false);
        assert!(buf.should_send_forward_tsn());
        let fwd = buf.create_forward_tsn();
        assert_eq!(fwd.new_cumulative_tsn, Tsn(15));
        assert_eq!(fwd.skipped_streams, vec!(SkippedStream::ForwardTsn(StreamId(3), Ssn(0))));

        // Ack 15, nothing more will be skipped.
        buf.handle_sack(Tsn(15), &[], false);
        assert!(!buf.should_send_forward_tsn());
    }
}
