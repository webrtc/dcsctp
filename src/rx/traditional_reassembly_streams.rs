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
use crate::api::handover::HandoverOrderedStream;
use crate::api::handover::HandoverReadiness;
use crate::api::handover::HandoverUnorderedStream;
use crate::api::handover::SocketHandoverState;
use crate::packet::SkippedStream;
use crate::packet::data::Data;
use crate::rx::IntervalList;
use crate::rx::ReassemblyKey;
use crate::rx::reassembly_streams::ReassemblyStreams;
use crate::types::Ssn;
use crate::types::StreamKey;
use crate::types::Tsn;
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct TraditionalKey {
    pub ssn: Ssn, // Primary sort key, NOTE: Is always 0 for unordered chunks.
    pub tsn: Tsn, // Secondary sort key.
}

impl ReassemblyKey for TraditionalKey {
    fn next(&self) -> Self {
        TraditionalKey { ssn: self.ssn, tsn: self.tsn + 1 }
    }
}

pub struct TraditionalReassemblyStreams {
    ordered: HashMap<StreamId, OrderedStream>,
    unordered: HashMap<StreamId, UnorderedStream>,
}

impl TraditionalReassemblyStreams {
    pub fn new() -> Self {
        Self { ordered: HashMap::new(), unordered: HashMap::new() }
    }
}

impl ReassemblyStreams for TraditionalReassemblyStreams {
    fn add(&mut self, tsn: Tsn, data: Data, on_reassembled: &mut dyn FnMut(Message)) -> isize {
        match data.stream_key {
            StreamKey::Ordered(id) => self
                .ordered
                .entry(id)
                .or_insert_with(|| OrderedStream::new(id))
                .add(tsn, data, on_reassembled),
            StreamKey::Unordered(id) => self
                .unordered
                .entry(id)
                .or_insert_with(|| UnorderedStream::new(id))
                .add(tsn, data, on_reassembled),
        }
    }

    fn handle_forward_tsn(
        &mut self,
        new_cumulative_ack: Tsn,
        skipped_streams: &[SkippedStream],
        on_reassembled: &mut dyn FnMut(Message),
    ) -> usize {
        let mut ret = 0;

        for stream in self.unordered.values_mut() {
            ret += stream.erase_to(new_cumulative_ack, None::<&SkippedStream>, on_reassembled);
        }

        for skipped_stream in skipped_streams {
            if let SkippedStream::ForwardTsn(stream_id, _) = skipped_stream {
                ret += self
                    .ordered
                    .entry(*stream_id)
                    .or_insert_with(|| OrderedStream::new(*stream_id))
                    .erase_to(new_cumulative_ack, Some(skipped_stream), on_reassembled);
            }
        }
        ret
    }

    fn reset_streams(&mut self, streams: &[StreamId]) {
        self.ordered
            .iter_mut()
            .filter(|(id, _)| streams.is_empty() || streams.contains(id))
            .for_each(|(_, stream)| stream.reset());
    }

    fn get_handover_readiness(&self) -> HandoverReadiness {
        let ordered_has_unassembled = self.ordered.values().any(|s| s.has_unassembled_chunks());
        let unordered_has_unassembled = self.unordered.values().any(|s| s.has_unassembled_chunks());

        HandoverReadiness::STREAM_HAS_UNASSEMBLED_CHUNKS
            & (ordered_has_unassembled || unordered_has_unassembled)
    }

    fn add_to_handover_state(&self, state: &mut SocketHandoverState) {
        self.ordered
            .iter()
            .for_each(|(id, s)| s.add_to_handover_state(StreamKey::Ordered(*id), state));
        self.unordered
            .iter()
            .for_each(|(id, s)| s.add_to_handover_state(StreamKey::Unordered(*id), state));
    }

    fn restore_from_state(&mut self, state: &SocketHandoverState) {
        state.rx.ordered_streams.iter().for_each(|s| {
            self.ordered.insert(StreamId(s.id), OrderedStream::from_state(s));
        });
    }
}

pub struct UnorderedStream {
    stream_id: StreamId,
    intervals: IntervalList<TraditionalKey>,
}

impl UnorderedStream {
    pub fn new(stream_id: StreamId) -> Self {
        Self { stream_id, intervals: IntervalList::default() }
    }

    fn add(&mut self, tsn: Tsn, data: Data, on_reassembled: &mut dyn FnMut(Message)) -> isize {
        if data.is_beginning && data.is_end {
            // Fastpath for already assembled chunks.
            on_reassembled(Message::new(data.stream_key.id(), data.ppid, data.payload));
            return 0;
        }
        let key = TraditionalKey { ssn: Ssn(0), tsn };
        let queued_bytes = data.payload.len() as isize;
        let idx = self.intervals.add(key, data);

        if let Some(interval) = self.intervals.pop_if_complete(idx) {
            let stream_id = self.stream_id;
            let ppid = interval.ppid;
            let payload = interval.collect_payload();
            let total_payload_len = payload.len();

            on_reassembled(Message::new(stream_id, ppid, payload));
            queued_bytes - (total_payload_len as isize)
        } else {
            queued_bytes
        }
    }

    fn erase_to(
        &mut self,
        new_cumulative_ack: Tsn,
        _: Option<&SkippedStream>,
        _: &mut dyn FnMut(Message),
    ) -> usize {
        self.intervals.retain(|interval| interval.start.tsn > new_cumulative_ack)
    }

    fn reset(&mut self) {
        unreachable!()
    }

    fn has_unassembled_chunks(&self) -> bool {
        !self.intervals.is_empty()
    }

    fn add_to_handover_state(&self, stream_id: StreamKey, state: &mut SocketHandoverState) {
        state.rx.unordered_streams.push(HandoverUnorderedStream { id: stream_id.id().0 });
    }
}

pub struct OrderedStream {
    stream_id: StreamId,
    intervals: IntervalList<TraditionalKey>,
    next_ssn: Ssn,
}

impl OrderedStream {
    pub fn new(stream_id: StreamId) -> Self {
        Self { stream_id, intervals: IntervalList::default(), next_ssn: Ssn(0) }
    }

    fn from_state(s: &HandoverOrderedStream) -> Self {
        Self {
            stream_id: StreamId(s.id),
            next_ssn: Ssn(s.next_ssn as u16),
            intervals: IntervalList::default(),
        }
    }

    fn try_to_assemble_messages(&mut self, on_reassembled: &mut dyn FnMut(Message)) -> usize {
        let mut assembled_bytes = 0;

        while let Some(interval) =
            self.intervals.pop_front_if_complete_and(|i| i.start.ssn == self.next_ssn)
        {
            let stream_id = self.stream_id;
            let ppid = interval.ppid;
            let payload = interval.collect_payload();

            assembled_bytes += payload.len();
            on_reassembled(Message::new(stream_id, ppid, payload));
            self.next_ssn += 1;
        }

        assembled_bytes
    }
}

impl OrderedStream {
    fn add(&mut self, tsn: Tsn, data: Data, on_reassembled: &mut dyn FnMut(Message)) -> isize {
        if data.ssn < self.next_ssn {
            // Already delivered or skipped.
            return 0;
        }

        if data.ssn == self.next_ssn && data.is_beginning && data.is_end {
            // Fastpath for already assembled chunks.
            on_reassembled(Message::new(self.stream_id, data.ppid, data.payload));
            self.next_ssn += 1;
            let assembled = self.try_to_assemble_messages(on_reassembled);
            return -(assembled as isize);
        }

        let key = TraditionalKey { ssn: data.ssn, tsn };
        let queued_bytes = data.payload.len() as isize;
        self.intervals.add(key, data);
        let assembled = self.try_to_assemble_messages(on_reassembled);
        queued_bytes - (assembled as isize)
    }

    fn erase_to(
        &mut self,
        _: Tsn,
        skipped_stream: Option<&SkippedStream>,
        on_reassembled: &mut dyn FnMut(Message),
    ) -> usize {
        match skipped_stream {
            Some(SkippedStream::ForwardTsn(_, ssn)) => {
                let mut removed_bytes = self.intervals.retain(|interval| interval.start.ssn > *ssn);

                if *ssn >= self.next_ssn {
                    self.next_ssn = *ssn + 1;
                }
                removed_bytes += self.try_to_assemble_messages(on_reassembled);
                removed_bytes
            }
            _ => 0,
        }
    }

    fn reset(&mut self) {
        self.next_ssn = Ssn(0);
        self.intervals = IntervalList::default();
    }

    fn has_unassembled_chunks(&self) -> bool {
        !self.intervals.is_empty()
    }

    fn add_to_handover_state(&self, stream_id: StreamKey, state: &mut SocketHandoverState) {
        state
            .rx
            .ordered_streams
            .push(HandoverOrderedStream { id: stream_id.id().0, next_ssn: self.next_ssn.0 as u32 });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::data_sequencer::DataSequencer;

    #[test]
    fn add_unordered_message_returns_correct_size() {
        let mut s = TraditionalReassemblyStreams::new();
        let mut seq = DataSequencer::new(StreamId(1));

        assert_eq!(s.add(Tsn(1), seq.unordered("a", "B"), &mut |_| {}), 1);
        assert_eq!(s.add(Tsn(2), seq.unordered("bcd", ""), &mut |_| {}), 3);
        assert_eq!(s.add(Tsn(3), seq.unordered("ef", ""), &mut |_| {}), 2);
        // Adding the end fragment should make it empty again.
        assert_eq!(s.add(Tsn(4), seq.unordered("g", "E"), &mut |_| {}), -6);
    }

    #[test]
    fn add_unordered_message_out_of_order_returns_correct_size() {
        let mut s = TraditionalReassemblyStreams::new();
        let mut seq = DataSequencer::new(StreamId(1));
        let mut messages = Vec::new();

        assert_eq!(s.add(Tsn(1), seq.unordered("a", "B"), &mut |m| messages.push(m)), 1);
        assert_eq!(s.add(Tsn(2), seq.unordered("bcd", ""), &mut |m| messages.push(m)), 3);
        assert_eq!(s.add(Tsn(4), seq.unordered("g", "E"), &mut |m| messages.push(m)), 1);
        assert!(messages.is_empty());
        assert_eq!(s.add(Tsn(3), seq.unordered("ef", ""), &mut |m| messages.push(m)), -5);
        assert_eq!(messages.len(), 1);
    }

    #[test]
    fn add_simple_ordered_message_returns_correct_size() {
        let mut s = TraditionalReassemblyStreams::new();
        let mut seq = DataSequencer::new(StreamId(1));
        let mut messages = Vec::new();

        assert_eq!(s.add(Tsn(1), seq.ordered("a", "B"), &mut |m| messages.push(m)), 1);
        assert_eq!(s.add(Tsn(2), seq.ordered("bcd", ""), &mut |m| messages.push(m)), 3);
        assert_eq!(s.add(Tsn(3), seq.ordered("ef", ""), &mut |m| messages.push(m)), 2);
        assert_eq!(s.add(Tsn(4), seq.ordered("g", "E"), &mut |m| messages.push(m)), -6);
        assert_eq!(messages.len(), 1);
    }

    #[test]
    fn add_more_complex_ordered_message_returns_correct_size() {
        let mut s = TraditionalReassemblyStreams::new();
        let mut seq = DataSequencer::new(StreamId(1));
        let mut messages = Vec::new();

        assert_eq!(s.add(Tsn(1), seq.ordered("a", "B"), &mut |m| messages.push(m)), 1);
        let late = seq.ordered("bcd", "");
        assert_eq!(s.add(Tsn(3), seq.ordered("ef", ""), &mut |m| messages.push(m)), 2);
        assert_eq!(s.add(Tsn(4), seq.ordered("g", "E"), &mut |m| messages.push(m)), 1);

        assert_eq!(s.add(Tsn(5), seq.ordered("h", "BE"), &mut |m| messages.push(m)), 1);
        assert_eq!(s.add(Tsn(6), seq.ordered("ij", "B"), &mut |m| messages.push(m)), 2);
        assert_eq!(s.add(Tsn(7), seq.ordered("k", "E"), &mut |m| messages.push(m)), 1);
        assert!(messages.is_empty());
        assert_eq!(s.add(Tsn(2), late, &mut |m| messages.push(m)), -8);

        assert_eq!(messages.len(), 3);
    }

    #[test]
    fn delete_unordered_message_returns_correct_size() {
        let mut s = TraditionalReassemblyStreams::new();
        let mut seq = DataSequencer::new(StreamId(1));
        let mut messages = Vec::new();

        assert_eq!(s.add(Tsn(1), seq.unordered("a", "B"), &mut |m| messages.push(m)), 1);
        assert_eq!(s.add(Tsn(2), seq.unordered("bcd", ""), &mut |m| messages.push(m)), 3);
        assert_eq!(s.add(Tsn(3), seq.unordered("ef", ""), &mut |m| messages.push(m)), 2);
        // Adding the end fragment should make it empty again.
        assert_eq!(s.handle_forward_tsn(Tsn(3), &[], &mut |m| messages.push(m)), 6);
    }

    #[test]
    fn delete_simple_ordered_message_returns_correct_size() {
        let mut s = TraditionalReassemblyStreams::new();
        let mut seq = DataSequencer::new(StreamId(1));
        let mut messages = Vec::new();

        assert_eq!(s.add(Tsn(1), seq.ordered("a", "B"), &mut |m| messages.push(m)), 1);
        assert_eq!(s.add(Tsn(2), seq.ordered("bcd", ""), &mut |m| messages.push(m)), 3);
        assert_eq!(s.add(Tsn(3), seq.ordered("ef", ""), &mut |m| messages.push(m)), 2);
        // Adding the end fragment should make it empty again.
        assert_eq!(
            s.handle_forward_tsn(
                Tsn(3),
                &[SkippedStream::ForwardTsn(StreamId(1), Ssn(0))],
                &mut |m| messages.push(m)
            ),
            6
        );
    }

    #[test]
    fn delete_many_ordered_messages_returns_correct_size() {
        let mut s = TraditionalReassemblyStreams::new();
        let mut seq = DataSequencer::new(StreamId(1));
        let mut messages = Vec::new();

        assert_eq!(s.add(Tsn(1), seq.ordered("a", "B"), &mut |m| messages.push(m)), 1);
        seq.ordered("bcd", ""); // TSN=2 Not received.
        assert_eq!(s.add(Tsn(3), seq.ordered("ef", ""), &mut |m| messages.push(m)), 2);
        assert_eq!(s.add(Tsn(4), seq.ordered("g", "E"), &mut |m| messages.push(m)), 1);

        assert_eq!(s.add(Tsn(5), seq.ordered("h", "BE"), &mut |m| messages.push(m)), 1);
        assert_eq!(s.add(Tsn(6), seq.ordered("ij", "B"), &mut |m| messages.push(m)), 2);
        assert_eq!(s.add(Tsn(7), seq.ordered("k", "E"), &mut |m| messages.push(m)), 1);

        assert_eq!(
            s.handle_forward_tsn(
                Tsn(8),
                &[SkippedStream::ForwardTsn(StreamId(1), Ssn(2))],
                &mut |m| messages.push(m)
            ),
            8
        );
    }

    #[test]
    fn delete_ordered_message_delives_two_returns_correct_size() {
        let mut s = TraditionalReassemblyStreams::new();
        let mut seq = DataSequencer::new(StreamId(1));
        let mut messages = Vec::new();

        assert_eq!(s.add(Tsn(1), seq.ordered("a", "B"), &mut |m| messages.push(m)), 1);
        seq.ordered("bcd", ""); // TSN=2 Not received.
        assert_eq!(s.add(Tsn(3), seq.ordered("ef", ""), &mut |m| messages.push(m)), 2);
        assert_eq!(s.add(Tsn(4), seq.ordered("g", "E"), &mut |m| messages.push(m)), 1);

        assert_eq!(s.add(Tsn(5), seq.ordered("h", "BE"), &mut |m| messages.push(m)), 1);
        assert_eq!(s.add(Tsn(6), seq.ordered("ij", "B"), &mut |m| messages.push(m)), 2);
        assert_eq!(s.add(Tsn(7), seq.ordered("k", "E"), &mut |m| messages.push(m)), 1);

        assert_eq!(
            s.handle_forward_tsn(
                Tsn(8),
                &[SkippedStream::ForwardTsn(StreamId(1), Ssn(0))],
                &mut |m| messages.push(m)
            ),
            8
        );
        assert_eq!(messages.len(), 2);
    }

    #[test]
    fn no_streams_can_be_handed_over() {
        let s = TraditionalReassemblyStreams::new();
        let mut g1 = DataSequencer::new(StreamId(1));
        let mut g2 = DataSequencer::new(StreamId(2));
        let mut ms = Vec::<Message>::new();

        assert!(s.get_handover_readiness().is_ready());

        let mut state = SocketHandoverState::default();
        s.add_to_handover_state(&mut state);

        let mut s = TraditionalReassemblyStreams::new();
        s.restore_from_state(&state);

        assert_eq!(s.add(Tsn(1), g1.ordered("a", "B"), &mut |m| ms.push(m)), 1);
        assert_eq!(s.add(Tsn(2), g1.ordered("bcd", ""), &mut |m| ms.push(m)), 3);
        assert_eq!(s.add(Tsn(3), g2.ordered("e", "B"), &mut |m| ms.push(m)), 1);
        assert_eq!(s.add(Tsn(4), g2.ordered("fgh", ""), &mut |m| ms.push(m)), 3);
    }

    #[test]
    fn ordered_streams_can_be_handed_over_when_no_unassembled_chunks_exist() {
        let mut s = TraditionalReassemblyStreams::new();
        let mut g1 = DataSequencer::new(StreamId(1));
        let mut ms = Vec::<Message>::new();

        assert_eq!(s.add(Tsn(1), g1.ordered("a", "B"), &mut |m| ms.push(m)), 1);
        assert_eq!(s.get_handover_readiness(), HandoverReadiness::STREAM_HAS_UNASSEMBLED_CHUNKS);
        assert_eq!(s.add(Tsn(2), g1.ordered("bcd", ""), &mut |m| ms.push(m)), 3);
        assert_eq!(s.get_handover_readiness(), HandoverReadiness::STREAM_HAS_UNASSEMBLED_CHUNKS);

        g1.ordered("efg", "E"); // TSN=3 Not received.
        assert_eq!(
            s.handle_forward_tsn(
                Tsn(3),
                &[SkippedStream::ForwardTsn(StreamId(1), Ssn(0))],
                &mut |m| ms.push(m)
            ),
            4
        );
        assert!(s.get_handover_readiness().is_ready());

        let mut state = SocketHandoverState::default();
        s.add_to_handover_state(&mut state);

        let mut s = TraditionalReassemblyStreams::new();
        s.restore_from_state(&state);

        assert_eq!(s.add(Tsn(4), g1.ordered("h", "B"), &mut |m| ms.push(m)), 1);
    }

    #[test]
    fn can_delete_first_ordered_message() {
        let mut s = TraditionalReassemblyStreams::new();
        let mut seq = DataSequencer::new(StreamId(1));
        let mut messages = Vec::new();

        seq.ordered("abc", "BE"); // TSN=1 Not received.
        assert_eq!(
            s.handle_forward_tsn(
                Tsn(1),
                &[SkippedStream::ForwardTsn(StreamId(1), Ssn(0))],
                &mut |m| messages.push(m)
            ),
            0
        );

        assert_eq!(s.add(Tsn(2), seq.ordered("def", "BE"), &mut |m| messages.push(m)), 0);
        assert_eq!(messages.len(), 1);
    }

    #[test]
    fn can_reassemble_fast_path_unordered() {
        let mut s = TraditionalReassemblyStreams::new();
        let mut seq = DataSequencer::new(StreamId(1));
        let mut messages = Vec::new();

        let data1 = seq.unordered("a", "BE");
        let data2 = seq.unordered("b", "BE");
        let data3 = seq.unordered("c", "BE");
        let data4 = seq.unordered("d", "BE");

        assert_eq!(s.add(Tsn(1), data1, &mut |m| messages.push(m)), 0);
        assert_eq!(messages.len(), 1);

        assert_eq!(s.add(Tsn(3), data3, &mut |m| messages.push(m)), 0);
        assert_eq!(messages.len(), 2);

        assert_eq!(s.add(Tsn(2), data2, &mut |m| messages.push(m)), 0);
        assert_eq!(messages.len(), 3);

        assert_eq!(s.add(Tsn(4), data4, &mut |m| messages.push(m)), 0);
        assert_eq!(messages.len(), 4);
    }

    #[test]
    fn can_reassemble_fast_path_ordered() {
        let mut s = TraditionalReassemblyStreams::new();
        let mut seq = DataSequencer::new(StreamId(1));
        let mut messages = Vec::new();

        let data1 = seq.ordered("a", "BE");
        let data2 = seq.ordered("b", "BE");
        let data3 = seq.ordered("c", "BE");
        let data4 = seq.ordered("d", "BE");

        assert_eq!(s.add(Tsn(1), data1, &mut |m| messages.push(m)), 0);
        assert_eq!(messages.len(), 1);

        assert_eq!(s.add(Tsn(3), data3, &mut |m| messages.push(m)), 1);
        assert_eq!(messages.len(), 1);

        assert_eq!(s.add(Tsn(2), data2, &mut |m| messages.push(m)), -1);
        assert_eq!(messages.len(), 3);

        assert_eq!(s.add(Tsn(4), data4, &mut |m| messages.push(m)), 0);
        assert_eq!(messages.len(), 4);
    }
}
