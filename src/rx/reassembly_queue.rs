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
use crate::api::SocketEvent;
use crate::api::StreamId;
use crate::packet::data::Data;
use crate::packet::forward_tsn_chunk::SkippedStream;
use crate::rx::interleaved_reassembly_streams::InterleavedReassemblyStreams;
use crate::rx::reassembly_streams::ReassemblyStreams;
use crate::rx::traditional_reassembly_streams::TraditionalReassemblyStreams;
use crate::types::Tsn;
use crate::EventSink;
use std::cell::RefCell;
use std::collections::HashSet;
use std::rc::Rc;

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
    events: Rc<RefCell<dyn EventSink>>,
    rx_messages_count: usize,
}

impl ReassemblyQueue {
    pub fn new(
        max_size_bytes: usize,
        use_message_interleaving: bool,
        events: Rc<RefCell<dyn EventSink>>,
    ) -> Self {
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
            events,
            rx_messages_count: 0,
        }
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

        self.queued_bytes =
            self.queued_bytes.wrapping_add_signed(self.streams.add(tsn, data, &mut |message| {
                self.rx_messages_count += 1;
                self.events.borrow_mut().add(SocketEvent::OnMessage(message))
            }));
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

        self.queued_bytes -=
            self.streams.handle_forward_tsn(new_cumulative_ack, &skipped_streams, &mut |message| {
                self.rx_messages_count += 1;
                self.events.borrow_mut().add(SocketEvent::OnMessage(message))
            });
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
                    self.handle_forward_tsn(tsn, skipped)
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
    use crate::events::Events;
    use crate::testing::data_generator::DataGenerator;
    use crate::testing::event_helpers::expect_no_event;
    use crate::testing::event_helpers::expect_on_message;
    use crate::types::Fsn;
    use crate::types::Mid;
    use crate::types::Ssn;
    use crate::types::StreamKey;
    use itertools::Itertools;

    const MAX_SIZE: usize = 1000;

    fn make_events() -> Rc<RefCell<Events>> {
        Rc::new(RefCell::new(Events::new()))
    }

    fn next_event(events: &Rc<RefCell<Events>>) -> Option<SocketEvent> {
        events.borrow_mut().next_event()
    }

    fn make_traditional_queue(events: &Rc<RefCell<Events>>) -> ReassemblyQueue {
        ReassemblyQueue::new(MAX_SIZE, false, Rc::clone(events) as Rc<RefCell<dyn EventSink>>)
    }

    fn make_interleaved_queue(events: &Rc<RefCell<Events>>) -> ReassemblyQueue {
        ReassemblyQueue::new(MAX_SIZE, true, Rc::clone(events) as Rc<RefCell<dyn EventSink>>)
    }

    #[test]
    fn empty_queue() {
        let q = make_traditional_queue(&make_events());
        assert_eq!(q.queued_bytes(), 0);
    }

    #[test]
    fn single_unordered_chunk_message() {
        let events = make_events();
        let mut q = make_traditional_queue(&events);
        let mut gen = DataGenerator::new(StreamId(1));
        q.add(Tsn(10), gen.unordered("abcde", "BE"));
        let message = expect_on_message!(next_event(&events));
        assert_eq!(message.stream_id, StreamId(1));
        assert_eq!(message.ppid, PpId(53));
        assert_eq!(message.payload, "abcde".as_bytes().to_vec());
        assert_eq!(q.queued_bytes(), 0);
        expect_no_event!(next_event(&events));
    }

    #[test]
    fn can_receive_large_unordered_chunk_all_permutations() {
        let tsns: Vec<u32> = vec![10, 11, 12, 13];
        let payload: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

        for perm in tsns.iter().permutations(tsns.len()) {
            let events = make_events();
            let mut q = make_traditional_queue(&events);
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
                    expect_no_event!(next_event(&events));
                    assert!(q.queued_bytes() > 0);
                } else {
                    expect_on_message!(next_event(&events));
                    assert_eq!(q.queued_bytes(), 0);
                }
            }
        }
    }

    #[test]
    fn single_ordered_chunk_message() {
        let events = make_events();
        let mut q = make_traditional_queue(&events);
        let mut gen = DataGenerator::new(StreamId(1));
        q.add(Tsn(10), gen.ordered("abcde", "BE"));
        let message = expect_on_message!(next_event(&events));
        assert_eq!(message.stream_id, StreamId(1));
        assert_eq!(message.ppid, PpId(53));
        assert_eq!(message.payload, "abcde".as_bytes().to_vec());
        assert_eq!(q.queued_bytes(), 0);
        expect_no_event!(next_event(&events));
    }

    #[test]
    fn can_receive_many_small_ordered_chunks_all_permutations() {
        let tsns: Vec<u32> = vec![10, 11, 12, 13];
        let payload: Vec<u8> = "abcdefghijklmnop".as_bytes().to_vec();

        for perm in tsns.iter().permutations(tsns.len()) {
            let events = make_events();
            let mut q = make_traditional_queue(&events);
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
            expect_on_message!(next_event(&events));
            expect_on_message!(next_event(&events));
            expect_on_message!(next_event(&events));
            expect_on_message!(next_event(&events));
            expect_no_event!(next_event(&events));
            assert_eq!(q.queued_bytes(), 0);
        }
    }

    #[test]
    fn retransmission_in_large_ordered() {
        let events = make_events();
        let mut q = make_traditional_queue(&events);
        let mut gen = DataGenerator::new(StreamId(1));
        q.add(Tsn(10), gen.ordered("a", "B"));
        q.add(Tsn(12), gen.ordered("c", ""));
        q.add(Tsn(13), gen.ordered("d", ""));
        q.add(Tsn(14), gen.ordered("e", ""));
        q.add(Tsn(15), gen.ordered("f", ""));
        q.add(Tsn(16), gen.ordered("g", ""));
        q.add(Tsn(17), gen.ordered("h", ""));
        assert_eq!(q.queued_bytes(), 7);

        // lost and retransmitted
        q.add(Tsn(11), gen.ordered("b", ""));
        q.add(Tsn(18), gen.ordered("i", ""));
        q.add(Tsn(19), gen.ordered("j", ""));
        assert_eq!(q.queued_bytes(), 10);
        expect_no_event!(next_event(&events));

        q.add(Tsn(20), gen.ordered("klmnop", "E"));
        expect_on_message!(next_event(&events));
        assert_eq!(q.queued_bytes(), 0);
        expect_no_event!(next_event(&events));
    }

    #[test]
    fn forward_tsn_remove_unordered() {
        let events = make_events();
        let mut q = make_traditional_queue(&events);
        let mut gen = DataGenerator::new(StreamId(1));
        q.add(Tsn(10), gen.unordered("a", "B"));
        q.add(Tsn(12), gen.unordered("c", ""));
        q.add(Tsn(13), gen.unordered("d", "E"));

        q.add(Tsn(14), gen.unordered("e", "B"));
        q.add(Tsn(15), gen.unordered("f", ""));
        q.add(Tsn(17), gen.unordered("h", "E"));
        assert_eq!(q.queued_bytes(), 6);
        expect_no_event!(next_event(&events));

        q.handle_forward_tsn(Tsn(13), vec![]);
        assert_eq!(q.queued_bytes(), 3);

        q.add(Tsn(16), gen.unordered("g", ""));
        expect_on_message!(next_event(&events));
        assert_eq!(q.queued_bytes(), 0);
        expect_no_event!(next_event(&events));
    }

    #[test]
    fn forward_tsn_remove_ordered() {
        let events = make_events();
        let mut q = make_traditional_queue(&events);
        let mut gen = DataGenerator::new(StreamId(1));
        q.add(Tsn(10), gen.ordered("a", "B"));
        q.add(Tsn(12), gen.ordered("c", ""));
        q.add(Tsn(13), gen.ordered("d", "E"));

        q.add(Tsn(14), gen.ordered("e", "B"));
        q.add(Tsn(15), gen.ordered("f", ""));
        q.add(Tsn(16), gen.ordered("g", ""));
        q.add(Tsn(17), gen.ordered("h", "E"));
        assert_eq!(q.queued_bytes(), 7);
        expect_no_event!(next_event(&events));

        q.handle_forward_tsn(Tsn(13), vec![SkippedStream::ForwardTsn(StreamId(1), Ssn(0))]);
        assert_eq!(q.queued_bytes(), 0);
        expect_on_message!(next_event(&events));
    }

    #[test]
    fn not_ready_for_handover_when_reset_stream_is_deferred() {
        let events = make_events();
        let mut q = make_traditional_queue(&events);
        let mut gen = DataGenerator::new(StreamId(1));
        q.add(Tsn(10), gen.ordered("abcd", "BE"));
        q.add(Tsn(11), gen.ordered("efgh", "BE"));

        assert!(q.get_handover_readiness().is_ready());

        q.enter_deferred_reset(Tsn(12), &[StreamId(1)]);
        assert_eq!(q.get_handover_readiness(), HandoverReadiness::STREAM_RESET_DEFERRED);

        q.add(Tsn(12), gen.ordered("ijkl", "BE"));

        q.reset_streams_and_leave_deferred_reset(&[StreamId(1)]);
        assert!(q.get_handover_readiness().is_ready());
    }

    #[test]
    fn handover_in_initial_state() {
        let events = make_events();
        let q = make_traditional_queue(&events);
        let mut gen = DataGenerator::new(StreamId(1));

        let mut state = SocketHandoverState::default();
        q.add_to_handover_state(&mut state);

        let mut q = make_traditional_queue(&events);
        q.restore_from_state(&state);

        q.add(Tsn(10), gen.ordered("abcd", "BE"));
        expect_on_message!(next_event(&events));
    }

    #[test]
    fn handover_after_having_assembed_one_message() {
        let events = make_events();
        let mut q = make_traditional_queue(&events);
        let mut gen = DataGenerator::new(StreamId(1));

        q.add(Tsn(10), gen.ordered("abcd", "BE"));
        expect_on_message!(next_event(&events));

        let mut state = SocketHandoverState::default();
        q.add_to_handover_state(&mut state);

        let mut q = make_traditional_queue(&events);
        q.restore_from_state(&state);

        q.add(Tsn(11), gen.ordered("efgh", "BE"));
        expect_on_message!(next_event(&events));
    }

    #[test]
    fn single_unordered_chunk_message_in_rfc8260() {
        let events = make_events();
        let mut q = make_interleaved_queue(&events);
        let mut gen = DataGenerator::new(StreamId(1));
        q.add(Tsn(10), gen.ordered("abcd", "BE"));
        let message = expect_on_message!(next_event(&events));
        assert_eq!(message.stream_id, StreamId(1));
        assert_eq!(message.payload, "abcd".as_bytes().to_vec());
        assert_eq!(q.queued_bytes(), 0);
        expect_no_event!(next_event(&events));
    }

    #[test]
    fn two_interleaved_chunks() {
        let events = make_events();
        let mut q = make_interleaved_queue(&events);
        let mut s1 = DataGenerator::new(StreamId(1));
        let mut s2 = DataGenerator::new(StreamId(2));
        q.add(Tsn(10), s1.ordered("abcd", "B"));
        q.add(Tsn(11), s2.ordered("ijkl", "B"));
        assert_eq!(q.queued_bytes(), 8);
        q.add(Tsn(12), s1.ordered("efgh", "E"));
        assert_eq!(q.queued_bytes(), 4);
        q.add(Tsn(13), s2.ordered("mnop", "E"));
        assert_eq!(q.queued_bytes(), 0);

        let message = expect_on_message!(next_event(&events));
        assert_eq!(message.stream_id, StreamId(1));
        assert_eq!(message.payload, "abcdefgh".as_bytes().to_vec());

        let message = expect_on_message!(next_event(&events));
        assert_eq!(message.stream_id, StreamId(2));
        assert_eq!(message.payload, "ijklmnop".as_bytes().to_vec());

        expect_no_event!(next_event(&events));
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
            let events = make_events();
            let mut q = make_interleaved_queue(&events);
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
            expect_on_message!(next_event(&events));
            expect_on_message!(next_event(&events));
            expect_no_event!(next_event(&events));
        }
    }

    #[test]
    fn i_forward_tsn_remove_a_lot_ordered() {
        let events = make_events();
        let mut q = make_interleaved_queue(&events);
        let mut s1 = DataGenerator::new(StreamId(1));

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
        assert_eq!(q.queued_bytes(), 0);

        let message = expect_on_message!(next_event(&events));
        assert_eq!(message.stream_id, StreamId(1));
        assert_eq!(message.payload, "efgh".as_bytes().to_vec());

        expect_no_event!(next_event(&events));

        // The lost chunk comes, but too late. This is actually not a realistic scenario, as the
        // data tracker ensures that this chunk is never fed into the reassembly queue, but let's
        // just validate that it hasn't kept the discarded message and now tries to assemble it.
        q.add(Tsn(11), lost);
        expect_no_event!(next_event(&events));
    }
}
