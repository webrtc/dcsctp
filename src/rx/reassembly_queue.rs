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

use crate::api::Message;
use crate::api::StreamId;
use crate::api::handover::HandoverReadiness;
use crate::api::handover::SocketHandoverState;
use crate::packet::SkippedStream;
use crate::packet::data::Data;
use crate::rx::interleaved_reassembly_streams::InterleavedReassemblyStreams;
use crate::rx::reassembly_streams::ReassemblyStreams;
use crate::rx::traditional_reassembly_streams::TraditionalReassemblyStreams;
use crate::types::Tsn;
use std::collections::HashSet;
use std::collections::VecDeque;

pub const HIGH_WATERMARK_LIMIT: f32 = 0.9;

enum DeferredOperation {
    Data(Tsn, Data),
    ForwardTsn(Tsn, Vec<SkippedStream>),
}

struct DeferredResetStreams {
    sender_last_assigned_tsn: Tsn,
    streams: HashSet<StreamId>,
    deferred_operations: Vec<DeferredOperation>,
}

pub struct ReassemblyQueue {
    max_size_bytes: usize,
    watermark_bytes: usize,
    queued_bytes: usize,
    streams: Box<dyn ReassemblyStreams>,
    deferred_reset_streams: Option<DeferredResetStreams>,
    rx_messages_count: usize,
    reassembled_messages: VecDeque<Message>,
}

impl ReassemblyQueue {
    pub fn new(max_size_bytes: usize, use_message_interleaving: bool) -> Self {
        let streams: Box<dyn ReassemblyStreams> = if use_message_interleaving {
            Box::new(InterleavedReassemblyStreams::new())
        } else {
            Box::new(TraditionalReassemblyStreams::new())
        };

        Self {
            max_size_bytes,
            watermark_bytes: (max_size_bytes as f32 * HIGH_WATERMARK_LIMIT) as usize,
            queued_bytes: 0,
            streams,
            deferred_reset_streams: None,
            rx_messages_count: 0,
            reassembled_messages: VecDeque::new(),
        }
    }

    pub fn messages_ready_count(&self) -> usize {
        self.reassembled_messages.len()
    }

    pub fn get_next_message(&mut self) -> Option<Message> {
        let message = self.reassembled_messages.pop_front()?;
        self.queued_bytes -= message.payload.len();
        Some(message)
    }

    pub fn rx_messages_count(&self) -> usize {
        self.rx_messages_count
    }

    pub fn add(&mut self, tsn: Tsn, data: Data) {
        if let Some(deferred_stream) = &mut self.deferred_reset_streams {
            if tsn > deferred_stream.sender_last_assigned_tsn
                && deferred_stream.streams.contains(&data.stream_key.id())
            {
                self.queued_bytes += data.payload.len();
                deferred_stream.deferred_operations.push(DeferredOperation::Data(tsn, data));
                return;
            }
        }

        let bytes_added_to_queue = self.streams.add(tsn, data, &mut |message| {
            self.rx_messages_count += 1;
            self.queued_bytes += message.payload.len();
            self.reassembled_messages.push_back(message);
        });

        self.queued_bytes = self.queued_bytes.wrapping_add_signed(bytes_added_to_queue);
    }

    pub fn queued_bytes(&self) -> usize {
        self.queued_bytes
    }

    pub fn is_above_watermark(&self) -> bool {
        self.queued_bytes >= self.watermark_bytes
    }

    pub fn is_full(&self) -> bool {
        self.queued_bytes >= self.max_size_bytes
    }

    pub fn handle_forward_tsn(
        &mut self,
        new_cumulative_ack: Tsn,
        skipped_streams: Vec<SkippedStream>,
    ) {
        if let Some(deferred_stream) = &mut self.deferred_reset_streams {
            if new_cumulative_ack > deferred_stream.sender_last_assigned_tsn {
                deferred_stream
                    .deferred_operations
                    .push(DeferredOperation::ForwardTsn(new_cumulative_ack, skipped_streams));
                return;
            }
        }

        let bytes_removed_from_queue =
            self.streams.handle_forward_tsn(new_cumulative_ack, &skipped_streams, &mut |message| {
                self.rx_messages_count += 1;
                self.queued_bytes += message.payload.len();
                self.reassembled_messages.push_back(message);
            });
        self.queued_bytes -= bytes_removed_from_queue;
    }

    /// The remaining bytes until the queue has reached the watermark limit.
    pub fn remaining_bytes(&self) -> usize {
        self.watermark_bytes - self.queued_bytes
    }

    pub(crate) fn enter_deferred_reset(
        &mut self,
        sender_last_assigned_tsn: Tsn,
        streams: &[StreamId],
    ) {
        self.deferred_reset_streams.get_or_insert_with(|| DeferredResetStreams {
            sender_last_assigned_tsn,
            streams: streams.iter().copied().collect(),
            deferred_operations: Vec::new(),
        });
    }

    pub(crate) fn reset_streams_and_leave_deferred_reset(&mut self, streams: &[StreamId]) {
        self.streams.reset_streams(streams);
        if let Some(deferred) = self.deferred_reset_streams.take() {
            deferred.deferred_operations.into_iter().for_each(|op| match op {
                DeferredOperation::Data(tsn, data) => self.add(tsn, data),
                DeferredOperation::ForwardTsn(tsn, skipped) => {
                    self.handle_forward_tsn(tsn, skipped);
                }
            });
        }
    }

    pub(crate) fn get_handover_readiness(&self) -> HandoverReadiness {
        HandoverReadiness::STREAM_RESET_DEFERRED & self.deferred_reset_streams.is_some()
            | self.streams.get_handover_readiness()
    }

    pub(crate) fn add_to_handover_state(&self, state: &mut SocketHandoverState) {
        self.streams.add_to_handover_state(state);
    }

    pub(crate) fn restore_from_state(&mut self, state: &SocketHandoverState) {
        self.streams.restore_from_state(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::PpId;
    use crate::testing::data_sequencer::DataSequencer;
    use crate::types::Fsn;
    use crate::types::Mid;
    use crate::types::Ssn;
    use crate::types::StreamKey;
    use itertools::Itertools;

    const MAX_SIZE: usize = 1000;

    fn make_traditional_queue() -> ReassemblyQueue {
        ReassemblyQueue::new(MAX_SIZE, false)
    }

    fn make_interleaved_queue() -> ReassemblyQueue {
        ReassemblyQueue::new(MAX_SIZE, true)
    }

    fn assert_no_partial_message_in_queue(q: &mut ReassemblyQueue) {
        // Drain the reassembled messages, and validate that there is nothing partial remaining.
        while q.messages_ready_count() > 0 {
            q.get_next_message();
        }
        assert_eq!(q.messages_ready_count(), 0);
        assert_eq!(q.queued_bytes(), 0);
    }

    #[test]
    fn empty_queue() {
        let q = make_traditional_queue();
        assert_eq!(q.queued_bytes(), 0);
    }

    #[test]
    fn single_unordered_chunk_message() {
        let mut q = make_traditional_queue();
        let mut seq = DataSequencer::new(StreamId(1));
        q.add(Tsn(10), seq.unordered("abcde", "BE"));
        let message = q.get_next_message().unwrap();
        assert_eq!(message.stream_id, StreamId(1));
        assert_eq!(message.ppid, PpId(53));
        assert_eq!(message.payload, "abcde".as_bytes().to_vec());
        assert_eq!(q.queued_bytes(), 0);
        assert_eq!(q.messages_ready_count(), 0);
    }

    #[test]
    fn can_receive_large_unordered_chunk_all_permutations() {
        let tsns: Vec<u32> = vec![10, 11, 12, 13];
        let payload: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

        for perm in tsns.iter().permutations(tsns.len()) {
            let mut q = make_traditional_queue();
            for (i, tsn) in perm.iter().enumerate() {
                let offset = ((*tsn - 10) * 4) as usize;
                let perm_payload = payload[offset..offset + 4].to_vec();
                let is_beginning = **tsn == 10;
                let is_end = **tsn == 13;
                q.add(
                    Tsn(**tsn),
                    Data {
                        stream_key: StreamKey::Unordered(StreamId(1)),
                        ssn: Ssn(0),
                        ppid: PpId(53),
                        payload: perm_payload,
                        is_beginning,
                        is_end,
                        ..Default::default()
                    },
                );
                if i < 3 {
                    assert_eq!(q.messages_ready_count(), 0);
                    assert!(q.queued_bytes() > 0);
                } else {
                    assert_eq!(q.messages_ready_count(), 1);
                    assert_no_partial_message_in_queue(&mut q);
                }
            }
        }
    }

    #[test]
    fn single_ordered_chunk_message() {
        let mut q = make_traditional_queue();
        let mut seq = DataSequencer::new(StreamId(1));
        q.add(Tsn(10), seq.ordered("abcde", "BE"));
        let message = q.get_next_message().unwrap();
        assert_eq!(message.stream_id, StreamId(1));
        assert_eq!(message.ppid, PpId(53));
        assert_eq!(message.payload, "abcde".as_bytes().to_vec());
        assert_eq!(q.queued_bytes(), 0);
        assert_eq!(q.messages_ready_count(), 0);
    }

    #[test]
    fn can_receive_many_small_ordered_chunks_all_permutations() {
        let tsns: Vec<u32> = vec![10, 11, 12, 13];
        let payload: Vec<u8> = "abcdefghijklmnop".as_bytes().to_vec();

        for perm in tsns.iter().permutations(tsns.len()) {
            let mut q = make_traditional_queue();
            for tsn in perm {
                let offset = ((*tsn - 10) * 4) as usize;
                let perm_payload = payload[offset..offset + 4].to_vec();
                q.add(
                    Tsn(*tsn),
                    Data {
                        stream_key: StreamKey::Ordered(StreamId(1)),
                        ssn: Ssn((*tsn - 10) as u16),
                        ppid: PpId(53),
                        payload: perm_payload,
                        is_beginning: true,
                        is_end: true,
                        ..Default::default()
                    },
                );
            }
            assert_eq!(q.messages_ready_count(), 4);
            assert_eq!(q.queued_bytes(), 4 * 4);
            assert_no_partial_message_in_queue(&mut q);
        }
    }

    #[test]
    fn retransmission_in_large_ordered() {
        let mut q = make_traditional_queue();
        let mut seq = DataSequencer::new(StreamId(1));
        q.add(Tsn(10), seq.ordered("a", "B"));
        q.add(Tsn(12), seq.ordered("c", ""));
        q.add(Tsn(13), seq.ordered("d", ""));
        q.add(Tsn(14), seq.ordered("e", ""));
        q.add(Tsn(15), seq.ordered("f", ""));
        q.add(Tsn(16), seq.ordered("g", ""));
        q.add(Tsn(17), seq.ordered("h", ""));
        assert_eq!(q.queued_bytes(), 7);

        // lost and retransmitted
        q.add(Tsn(11), seq.ordered("b", ""));
        q.add(Tsn(18), seq.ordered("i", ""));
        q.add(Tsn(19), seq.ordered("j", ""));
        assert_eq!(q.queued_bytes(), 10);
        assert_eq!(q.messages_ready_count(), 0);

        q.add(Tsn(20), seq.ordered("klmnop", "E"));
        assert_eq!(q.queued_bytes(), 16);
        assert_eq!(q.messages_ready_count(), 1);
        assert_no_partial_message_in_queue(&mut q);
    }

    #[test]
    fn forward_tsn_remove_unordered() {
        let mut q = make_traditional_queue();
        let mut seq = DataSequencer::new(StreamId(1));
        q.add(Tsn(10), seq.unordered("a", "B"));
        q.add(Tsn(12), seq.unordered("c", ""));
        q.add(Tsn(13), seq.unordered("d", "E"));

        q.add(Tsn(14), seq.unordered("e", "B"));
        q.add(Tsn(15), seq.unordered("f", ""));
        q.add(Tsn(17), seq.unordered("h", "E"));
        assert_eq!(q.queued_bytes(), 6);
        assert_eq!(q.messages_ready_count(), 0);

        q.handle_forward_tsn(Tsn(13), vec![]);
        assert_eq!(q.queued_bytes(), 3);

        q.add(Tsn(16), seq.unordered("g", ""));
        assert_eq!(q.queued_bytes(), 4);
        assert_eq!(q.messages_ready_count(), 1);
        assert_no_partial_message_in_queue(&mut q);
    }

    #[test]
    fn forward_tsn_remove_ordered() {
        let mut q = make_traditional_queue();
        let mut seq = DataSequencer::new(StreamId(1));
        q.add(Tsn(10), seq.ordered("a", "B"));
        q.add(Tsn(12), seq.ordered("c", ""));
        q.add(Tsn(13), seq.ordered("d", "E"));

        q.add(Tsn(14), seq.ordered("e", "B"));
        q.add(Tsn(15), seq.ordered("f", ""));
        q.add(Tsn(16), seq.ordered("g", ""));
        q.add(Tsn(17), seq.ordered("h", "E"));
        assert_eq!(q.queued_bytes(), 7);
        assert_eq!(q.messages_ready_count(), 0);

        q.handle_forward_tsn(Tsn(13), vec![SkippedStream::ForwardTsn(StreamId(1), Ssn(0))]);
        assert_eq!(q.queued_bytes(), 4);
        assert_eq!(q.messages_ready_count(), 1);
        assert_no_partial_message_in_queue(&mut q);
    }

    #[test]
    fn not_ready_for_handover_when_reset_stream_is_deferred() {
        let mut q = make_traditional_queue();
        let mut seq = DataSequencer::new(StreamId(1));
        q.add(Tsn(10), seq.ordered("abcd", "BE"));
        q.add(Tsn(11), seq.ordered("efgh", "BE"));

        assert!(q.get_handover_readiness().is_ready());

        q.enter_deferred_reset(Tsn(12), &[StreamId(1)]);
        assert_eq!(q.get_handover_readiness(), HandoverReadiness::STREAM_RESET_DEFERRED);

        q.add(Tsn(12), seq.ordered("ijkl", "BE"));

        q.reset_streams_and_leave_deferred_reset(&[StreamId(1)]);
        assert!(q.get_handover_readiness().is_ready());
    }

    #[test]
    fn handover_in_initial_state() {
        let q = make_traditional_queue();
        let mut seq = DataSequencer::new(StreamId(1));

        let mut state = SocketHandoverState::default();
        q.add_to_handover_state(&mut state);

        let mut q = make_traditional_queue();
        q.restore_from_state(&state);

        q.add(Tsn(10), seq.ordered("abcd", "BE"));
        assert_eq!(q.messages_ready_count(), 1);
    }

    #[test]
    fn handover_after_having_assembed_one_message() {
        let mut q = make_traditional_queue();
        let mut seq = DataSequencer::new(StreamId(1));

        q.add(Tsn(10), seq.ordered("abcd", "BE"));
        assert_eq!(q.messages_ready_count(), 1);

        let mut state = SocketHandoverState::default();
        q.add_to_handover_state(&mut state);

        let mut q = make_traditional_queue();
        q.restore_from_state(&state);

        q.add(Tsn(11), seq.ordered("efgh", "BE"));
        assert_eq!(q.messages_ready_count(), 1);
    }

    #[test]
    fn single_unordered_chunk_message_in_rfc8260() {
        let mut q = make_interleaved_queue();
        let mut seq = DataSequencer::new(StreamId(1));
        q.add(Tsn(10), seq.ordered("abcd", "BE"));
        let message = q.get_next_message().unwrap();
        assert_eq!(message.stream_id, StreamId(1));
        assert_eq!(message.payload, "abcd".as_bytes().to_vec());
        assert_eq!(q.queued_bytes(), 0);
        assert_eq!(q.messages_ready_count(), 0);
    }

    #[test]
    fn two_interleaved_chunks() {
        let mut q = make_interleaved_queue();
        let mut s1 = DataSequencer::new(StreamId(1));
        let mut s2 = DataSequencer::new(StreamId(2));
        q.add(Tsn(10), s1.ordered("abcd", "B"));
        q.add(Tsn(11), s2.ordered("ijkl", "B"));
        assert_eq!(q.queued_bytes(), 8);
        q.add(Tsn(12), s1.ordered("efgh", "E"));

        let message = q.get_next_message().unwrap();
        assert_eq!(message.stream_id, StreamId(1));
        assert_eq!(message.payload, "abcdefgh".as_bytes().to_vec());
        assert_eq!(q.queued_bytes(), 4);

        q.add(Tsn(13), s2.ordered("mnop", "E"));

        let message = q.get_next_message().unwrap();
        assert_eq!(message.stream_id, StreamId(2));
        assert_eq!(message.payload, "ijklmnop".as_bytes().to_vec());
        assert_eq!(q.queued_bytes(), 0);
        assert_eq!(q.messages_ready_count(), 0);
    }

    #[test]
    fn unordered_interleaved_messages_all_permutations() {
        struct ChunkState {
            stream_id: StreamId,
            tsn: Tsn,
            fsn: Fsn,
            payload: &'static str,
        }

        let chunks = [
            ChunkState { stream_id: StreamId(1), tsn: Tsn(10), fsn: Fsn(0), payload: "ab" },
            ChunkState { stream_id: StreamId(2), tsn: Tsn(11), fsn: Fsn(0), payload: "ab" },
            ChunkState { stream_id: StreamId(1), tsn: Tsn(12), fsn: Fsn(1), payload: "cd" },
            ChunkState { stream_id: StreamId(1), tsn: Tsn(13), fsn: Fsn(2), payload: "ef" },
            ChunkState { stream_id: StreamId(2), tsn: Tsn(14), fsn: Fsn(1), payload: "cd" },
            ChunkState { stream_id: StreamId(2), tsn: Tsn(15), fsn: Fsn(2), payload: "ef" },
        ];

        for perm in chunks.iter().permutations(chunks.len()) {
            let mut q = make_interleaved_queue();
            for chunk in perm {
                q.add(
                    chunk.tsn,
                    Data {
                        stream_key: StreamKey::Unordered(chunk.stream_id),
                        fsn: chunk.fsn,
                        payload: chunk.payload.as_bytes().to_vec(),
                        is_beginning: chunk.fsn == Fsn(0),
                        is_end: chunk.fsn == Fsn(2),
                        ..Default::default()
                    },
                );
            }
            assert_eq!(q.messages_ready_count(), 2);
        }
    }

    #[test]
    fn i_forward_tsn_remove_a_lot_ordered() {
        let mut q = make_interleaved_queue();
        let mut s1 = DataSequencer::new(StreamId(1));

        q.add(Tsn(10), s1.ordered("a", "B"));
        let lost = s1.ordered("b", ""); // Lost;
        q.add(Tsn(12), s1.ordered("c", ""));
        q.add(Tsn(13), s1.ordered("d", "E"));
        // TSN=14 is another stream.
        q.add(Tsn(15), s1.ordered("e", "B"));
        q.add(Tsn(16), s1.ordered("f", ""));
        q.add(Tsn(17), s1.ordered("g", ""));
        q.add(Tsn(18), s1.ordered("h", "E"));

        assert_eq!(q.queued_bytes(), 7);
        q.handle_forward_tsn(
            Tsn(13),
            vec![SkippedStream::IForwardTsn(StreamKey::Ordered(StreamId(1)), Mid(0))],
        );

        let message = q.get_next_message().unwrap();
        assert_eq!(message.stream_id, StreamId(1));
        assert_eq!(message.payload, "efgh".as_bytes().to_vec());

        assert_eq!(q.messages_ready_count(), 0);
        assert_no_partial_message_in_queue(&mut q);

        // The lost chunk comes, but too late. This is actually not a realistic scenario, as the
        // data tracker ensures that this chunk is never fed into the reassembly queue, but let's
        // just validate that it hasn't kept the discarded message and now tries to assemble it.
        q.add(Tsn(11), lost);
        assert_eq!(q.messages_ready_count(), 0);
    }
}
