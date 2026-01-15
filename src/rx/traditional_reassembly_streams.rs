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
use crate::rx::reassembly_streams::ReassemblyStreams;
use crate::types::Ssn;
use crate::types::StreamKey;
use crate::types::Tsn;
use std::collections::BTreeMap;
use std::collections::HashMap;

/// Given a chunk map and a tsn that points inside a fragmented message, returns the tsn which has
/// the `is_beginning` bit set. Will return None if the chunk was not found or if a gap was found
/// between `tsn` and the expected beginning.
fn find_beginning(chunks: &BTreeMap<Tsn, Data>, tsn: Tsn) -> Option<Tsn> {
    let mut expected_next = tsn + 1;
    for (tsn, data) in chunks.range(..=tsn).rev() {
        if *tsn + 1 != expected_next {
            return None;
        }
        if data.is_beginning {
            return Some(*tsn);
        }
        expected_next = *tsn;
    }
    None
}

/// Given a chunk map and a tsn that points inside a fragmented message, returns the tsn which has
/// the `is_end` bit set. Will return None if the chunk was not found or if a gap was found between
/// `tsn` and the expected end.
fn find_end(chunks: &BTreeMap<Tsn, Data>, tsn: Tsn) -> Option<Tsn> {
    let mut prev = tsn - 1;
    for (tsn, data) in chunks.range(tsn..) {
        if prev + 1 != *tsn {
            return None;
        }
        prev = *tsn;
        if data.is_end {
            return Some(*tsn);
        }
    }
    None
}

trait ReassemblyStream {
    fn add(&mut self, tsn: Tsn, data: Data, on_reassembled: &mut dyn FnMut(Message)) -> isize;
    fn erase_to(
        &mut self,
        new_cumulative_ack: Tsn,
        skipped: Option<&SkippedStream>,
        on_reassembled: &mut dyn FnMut(Message),
    ) -> usize;
    fn reset(&mut self);
    fn has_unassembled_chunks(&self) -> bool;
    fn add_to_handover_state(&self, stream_id: StreamKey, state: &mut SocketHandoverState);
}

pub struct TraditionalReassemblyStreams {
    streams: HashMap<StreamKey, Box<dyn ReassemblyStream>>,
}

impl TraditionalReassemblyStreams {
    pub fn new() -> Self {
        Self { streams: HashMap::new() }
    }

    fn get_or_create(&mut self, stream_key: StreamKey) -> &mut dyn ReassemblyStream {
        self.streams
            .entry(stream_key)
            .or_insert_with(|| match stream_key {
                StreamKey::Ordered(_) => Box::new(OrderedStream::new()),
                StreamKey::Unordered(_) => Box::new(UnorderedStream::new()),
            })
            .as_mut()
    }
}

impl ReassemblyStreams for TraditionalReassemblyStreams {
    fn add(&mut self, tsn: Tsn, data: Data, on_reassembled: &mut dyn FnMut(Message)) -> isize {
        self.get_or_create(data.stream_key).add(tsn, data, on_reassembled)
    }

    fn handle_forward_tsn(
        &mut self,
        new_cumulative_ack: Tsn,
        skipped_streams: &[SkippedStream],
        on_reassembled: &mut dyn FnMut(Message),
    ) -> usize {
        let mut ret = 0;
        // The `skipped_streams` only cover ordered messages - need to iterate all unordered streams
        // manually to remove those chunks.
        for (stream_key, stream) in &mut self.streams {
            if stream_key.is_unordered() {
                ret += stream.erase_to(new_cumulative_ack, None::<&SkippedStream>, on_reassembled);
            }
        }

        for skipped_stream in skipped_streams {
            if let SkippedStream::ForwardTsn(stream_id, _) = skipped_stream {
                ret += self.get_or_create(StreamKey::Ordered(*stream_id)).erase_to(
                    new_cumulative_ack,
                    Some(skipped_stream),
                    on_reassembled,
                );
            }
        }
        ret
    }

    fn reset_streams(&mut self, streams: &[StreamId]) {
        self.streams
            .iter_mut()
            .filter(|(stream_key, _)| stream_key.is_ordered())
            .filter(|(stream_key, _)| streams.is_empty() || streams.contains(&stream_key.id()))
            .for_each(|(_, stream)| stream.reset());
    }

    fn get_handover_readiness(&self) -> HandoverReadiness {
        let has_unassembled_chunks = self.streams.iter().any(|(_, s)| s.has_unassembled_chunks());

        HandoverReadiness::STREAM_HAS_UNASSEMBLED_CHUNKS & has_unassembled_chunks
    }

    fn add_to_handover_state(&self, state: &mut SocketHandoverState) {
        self.streams.iter().for_each(|(stream_id, s)| s.add_to_handover_state(*stream_id, state));
    }

    fn restore_from_state(&mut self, state: &SocketHandoverState) {
        state.rx.ordered_streams.iter().for_each(|s| {
            let stream_id = StreamKey::Ordered(StreamId(s.id));
            self.streams.insert(stream_id, Box::new(OrderedStream::from_state(s)));
        });
    }
}

pub struct UnorderedStream {
    chunks: BTreeMap<Tsn, Data>,
}

impl UnorderedStream {
    pub fn new() -> Self {
        Self { chunks: BTreeMap::<Tsn, Data>::new() }
    }

    fn try_assemble(&mut self, tsn: Tsn, on_reassembled: &mut dyn FnMut(Message)) -> usize {
        let (Some(start_tsn), Some(end_tsn)) =
            (find_beginning(&self.chunks, tsn), find_end(&self.chunks, tsn))
        else {
            return 0;
        };

        // This is only called when needing to assemble more than one unordered chunk since the fast
        // path handles all messages consisting of a single chunk.
        debug_assert!(start_tsn != end_tsn);
        let first_chunk = self.chunks.remove(&start_tsn).unwrap();
        let stream_id = first_chunk.stream_key.id();
        let ppid = first_chunk.ppid;
        let mut payload: Vec<u8> = first_chunk.payload;

        let mut tsn = start_tsn + 1;
        while tsn <= end_tsn {
            let mut c = self.chunks.remove(&tsn).unwrap();
            payload.append(&mut c.payload);
            tsn += 1;
        }

        let total_size = payload.len();
        on_reassembled(Message::new(stream_id, ppid, payload));
        total_size
    }
}

impl ReassemblyStream for UnorderedStream {
    fn add(&mut self, tsn: Tsn, data: Data, on_reassembled: &mut dyn FnMut(Message)) -> isize {
        if data.is_beginning && data.is_end {
            // Fastpath for already assembled chunks.
            on_reassembled(Message::new(data.stream_key.id(), data.ppid, data.payload));
            return 0;
        }
        let queued_bytes = data.payload.len() as isize;
        self.chunks.insert(tsn, data);

        queued_bytes - (self.try_assemble(tsn, on_reassembled) as isize)
    }

    fn erase_to(
        &mut self,
        new_cumulative_ack: Tsn,
        _: Option<&SkippedStream>,
        _: &mut dyn FnMut(Message),
    ) -> usize {
        let removed_bytes = self
            .chunks
            .range(..new_cumulative_ack + 1)
            .fold(0, |acc, (_, data)| acc + data.payload.len());

        self.chunks.retain(|tsn, _| *tsn > new_cumulative_ack);
        removed_bytes
    }

    fn reset(&mut self) {
        unreachable!()
    }

    fn has_unassembled_chunks(&self) -> bool {
        !self.chunks.is_empty()
    }

    fn add_to_handover_state(&self, stream_id: StreamKey, state: &mut SocketHandoverState) {
        state.rx.unordered_streams.push(HandoverUnorderedStream { id: stream_id.id().0 });
    }
}

pub struct OrderedStream {
    chunks_by_ssn: BTreeMap<Ssn, BTreeMap<Tsn, Data>>,
    next_ssn: Ssn,
}

impl OrderedStream {
    pub fn new() -> Self {
        Self { chunks_by_ssn: BTreeMap::<Ssn, BTreeMap<Tsn, Data>>::new(), next_ssn: Ssn(0) }
    }

    fn from_state(s: &HandoverOrderedStream) -> Self {
        Self { next_ssn: Ssn(s.next_ssn as u16), ..OrderedStream::new() }
    }

    fn try_to_assemble_messages(&mut self, on_reassembled: &mut dyn FnMut(Message)) -> usize {
        let mut assembled_bytes = 0;

        while let Some(chunks) = self.chunks_by_ssn.get_mut(&self.next_ssn) {
            let (first_tsn, first_data) = chunks.first_key_value().unwrap();
            let (last_tsn, last_data) = chunks.last_key_value().unwrap();
            if !first_data.is_beginning
                || !last_data.is_end
                || first_tsn.distance_to(*last_tsn) != (chunks.len() as u32 - 1)
            {
                break;
            }
            let stream_id = first_data.stream_key.id();
            let ppid = first_data.ppid;
            let mut payload: Vec<u8> = vec![];
            for data in chunks.values_mut() {
                payload.append(&mut data.payload);
            }
            assembled_bytes += payload.len();
            on_reassembled(Message::new(stream_id, ppid, payload));
            self.chunks_by_ssn.remove(&self.next_ssn);
            self.next_ssn += 1;
        }

        assembled_bytes
    }
}

impl ReassemblyStream for OrderedStream {
    fn add(&mut self, tsn: Tsn, data: Data, on_reassembled: &mut dyn FnMut(Message)) -> isize {
        let can_assemble = data.ssn == self.next_ssn;

        let mut queued_bytes = 0;
        if can_assemble && data.is_beginning && data.is_end {
            // Fastpath
            on_reassembled(Message::new(data.stream_key.id(), data.ppid, data.payload));
            self.next_ssn += 1;
        } else {
            queued_bytes += data.payload.len() as isize;
            self.chunks_by_ssn.entry(data.ssn).or_default().insert(tsn, data);
        }

        if can_assemble {
            queued_bytes -= self.try_to_assemble_messages(on_reassembled) as isize;
        }

        queued_bytes
    }

    fn erase_to(
        &mut self,
        _: Tsn,
        skipped_stream: Option<&SkippedStream>,
        on_reassembled: &mut dyn FnMut(Message),
    ) -> usize {
        match skipped_stream {
            Some(SkippedStream::ForwardTsn(_, ssn)) => {
                let mut removed_bytes: usize = 0;
                self.chunks_by_ssn.retain(|cur_ssn, chunks| {
                    if cur_ssn <= ssn {
                        removed_bytes +=
                            chunks.iter().fold(0, |acc, (_, data)| acc + data.payload.len());
                        false
                    } else {
                        true
                    }
                });
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
    }

    fn has_unassembled_chunks(&self) -> bool {
        !self.chunks_by_ssn.is_empty()
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
