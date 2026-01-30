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
use crate::api::PpId;
use crate::api::StreamId;
use crate::api::handover::HandoverOrderedStream;
use crate::api::handover::HandoverReadiness;
use crate::api::handover::HandoverUnorderedStream;
use crate::api::handover::SocketHandoverState;
use crate::packet::SkippedStream;
use crate::packet::data::Data;
use crate::rx::reassembly_streams::ReassemblyStreams;
use crate::types::Fsn;
use crate::types::Mid;
use crate::types::StreamKey;
use crate::types::Tsn;
use std::collections::BTreeMap;
use std::collections::HashMap;

pub struct OrderedStream {
    chunks_by_mid: BTreeMap<Mid, BTreeMap<Fsn, Data>>,
    next_mid: Mid,
}

impl OrderedStream {
    fn new(next_mid: Mid) -> Self {
        Self { chunks_by_mid: BTreeMap::new(), next_mid }
    }

    fn try_assemble_next(&mut self, on_reassembled: &mut dyn FnMut(Message)) -> usize {
        let mut assembled_bytes = 0;
        while let Some(chunks) = self.chunks_by_mid.get(&self.next_mid) {
            if !is_complete_message(chunks) {
                break;
            }

            let chunks = self.chunks_by_mid.remove(&self.next_mid).unwrap();
            let (stream_id, ppid, payload) = extract_payload(chunks);
            assembled_bytes += payload.len();
            on_reassembled(Message::new(stream_id, ppid, payload));
            self.next_mid += 1;
        }
        assembled_bytes
    }

    fn add(&mut self, data: Data, on_reassembled: &mut dyn FnMut(Message)) -> isize {
        let mut queued_bytes = 0;
        let mid = data.mid;

        if mid == self.next_mid && data.is_beginning && data.is_end {
            // Fast path - reassemble directly.
            on_reassembled(Message::new(data.stream_key.id(), data.ppid, data.payload));
            self.next_mid += 1;

            // Check if this unblocked subsequent messages
            queued_bytes -= self.try_assemble_next(on_reassembled) as isize;
            return queued_bytes;
        }

        queued_bytes += data.payload.len() as isize;
        self.chunks_by_mid.entry(mid).or_default().insert(data.fsn, data);

        if mid == self.next_mid {
            queued_bytes -= self.try_assemble_next(on_reassembled) as isize;
        }
        queued_bytes
    }
}

pub struct UnorderedStream {
    chunks_by_mid: BTreeMap<Mid, BTreeMap<Fsn, Data>>,
}

impl UnorderedStream {
    fn new() -> Self {
        Self { chunks_by_mid: BTreeMap::new() }
    }

    fn add(&mut self, data: Data, on_reassembled: &mut dyn FnMut(Message)) -> isize {
        if data.is_beginning && data.is_end {
            // Fast path - reassemble directly.
            on_reassembled(Message::new(data.stream_key.id(), data.ppid, data.payload));
            return 0;
        }

        let mid = data.mid;
        let mut queued_bytes = data.payload.len() as isize;
        let chunks = self.chunks_by_mid.entry(mid).or_default();
        chunks.insert(data.fsn, data);

        if is_complete_message(chunks) {
            let chunks = self.chunks_by_mid.remove(&mid).unwrap();
            let (stream_id, ppid, payload) = extract_payload(chunks);
            queued_bytes -= payload.len() as isize;
            on_reassembled(Message::new(stream_id, ppid, payload));
        }

        queued_bytes
    }
}

fn is_complete_message(chunks: &BTreeMap<Fsn, Data>) -> bool {
    if let (Some((first_fsn, first_data)), Some((last_fsn, last_data))) =
        (chunks.first_key_value(), chunks.last_key_value())
    {
        first_data.is_beginning
            && last_data.is_end
            && first_fsn.distance_to(*last_fsn) == (chunks.len() as u32 - 1)
    } else {
        false
    }
}

fn extract_payload(chunks: BTreeMap<Fsn, Data>) -> (StreamId, PpId, Vec<u8>) {
    let first_data = chunks.values().next().expect("Chunks should not be empty");
    let stream_id = first_data.stream_key.id();
    let ppid = first_data.ppid;

    // Calculate total size to pre-allocate
    let total_len: usize = chunks.values().map(|d| d.payload.len()).sum();
    let mut payload = Vec::with_capacity(total_len);

    for (_, mut data) in chunks {
        payload.append(&mut data.payload);
    }

    (stream_id, ppid, payload)
}

pub struct InterleavedReassemblyStreams {
    ordered: HashMap<StreamId, OrderedStream>,
    unordered: HashMap<StreamId, UnorderedStream>,
}

impl InterleavedReassemblyStreams {
    pub fn new() -> Self {
        Self { ordered: HashMap::new(), unordered: HashMap::new() }
    }
}

impl ReassemblyStreams for InterleavedReassemblyStreams {
    fn add(&mut self, _tsn: Tsn, data: Data, on_reassembled: &mut dyn FnMut(Message)) -> isize {
        match data.stream_key {
            StreamKey::Ordered(stream_id) => self
                .ordered
                .entry(stream_id)
                .or_insert_with(|| OrderedStream::new(Mid(0)))
                .add(data, on_reassembled),
            StreamKey::Unordered(stream_id) => self
                .unordered
                .entry(stream_id)
                .or_insert_with(UnorderedStream::new)
                .add(data, on_reassembled),
        }
    }

    fn handle_forward_tsn(
        &mut self,
        _new_cumulative_ack: Tsn,
        skipped_streams: &[SkippedStream],
        on_reassembled: &mut dyn FnMut(Message),
    ) -> usize {
        let mut released_bytes = 0;
        for skipped_stream in skipped_streams {
            if let SkippedStream::IForwardTsn(stream_key, mid) = skipped_stream {
                match stream_key {
                    StreamKey::Ordered(stream_id) => {
                        let stream = self
                            .ordered
                            .entry(*stream_id)
                            .or_insert_with(|| OrderedStream::new(Mid(0)));

                        stream.chunks_by_mid.retain(|cur_mid, chunks| {
                            if cur_mid <= mid {
                                released_bytes += chunks
                                    .iter()
                                    .fold(0, |acc, (_, data)| acc + data.payload.len());
                                false
                            } else {
                                true
                            }
                        });

                        if stream.next_mid <= *mid {
                            stream.next_mid = *mid + 1;
                        }

                        // Try to assemble messages after the jump
                        released_bytes += stream.try_assemble_next(on_reassembled);
                    }
                    StreamKey::Unordered(stream_id) => {
                        let stream =
                            self.unordered.entry(*stream_id).or_insert_with(UnorderedStream::new);

                        stream.chunks_by_mid.retain(|cur_mid, chunks| {
                            if cur_mid <= mid {
                                released_bytes += chunks
                                    .iter()
                                    .fold(0, |acc, (_, data)| acc + data.payload.len());
                                false
                            } else {
                                true
                            }
                        });
                    }
                }
            }
        }
        released_bytes
    }

    fn reset_streams(&mut self, streams: &[StreamId]) {
        if streams.is_empty() {
            for stream in self.ordered.values_mut() {
                stream.next_mid = Mid(0);
            }
        } else {
            for stream_id in streams {
                if let Some(stream) = self.ordered.get_mut(stream_id) {
                    stream.next_mid = Mid(0);
                }
            }
        }
        // Unordered streams don't need reset as they don't block on MID.
    }

    fn get_handover_readiness(&self) -> HandoverReadiness {
        let has_ordered_chunks = self.ordered.values().any(|s| !s.chunks_by_mid.is_empty());
        let has_unordered_chunks = self.unordered.values().any(|s| !s.chunks_by_mid.is_empty());

        HandoverReadiness::STREAM_HAS_UNASSEMBLED_CHUNKS
            & (has_ordered_chunks | has_unordered_chunks)
    }

    fn add_to_handover_state(&self, state: &mut SocketHandoverState) {
        for (stream_id, stream) in &self.ordered {
            state
                .rx
                .ordered_streams
                .push(HandoverOrderedStream { id: stream_id.0, next_ssn: stream.next_mid.0 });
        }

        for stream_id in self.unordered.keys() {
            // We only track existence if needed, but handover struct currently only has ID for
            // unordered
            state.rx.unordered_streams.push(HandoverUnorderedStream { id: stream_id.0 });
        }
    }

    fn restore_from_state(&mut self, state: &SocketHandoverState) {
        for stream in &state.rx.ordered_streams {
            self.ordered.insert(StreamId(stream.id), OrderedStream::new(Mid(stream.next_ssn)));
        }
        for stream in &state.rx.unordered_streams {
            self.unordered.insert(StreamId(stream.id), UnorderedStream::new());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::data_sequencer::DataSequencer;

    #[test]
    fn add_unordered_message_returns_correct_size() {
        let mut s = InterleavedReassemblyStreams::new();
        let mut seq = DataSequencer::new(StreamId(1));

        assert_eq!(s.add(Tsn(1), seq.unordered("a", "B"), &mut |_| {}), 1);
        assert_eq!(s.add(Tsn(2), seq.unordered("bcd", ""), &mut |_| {}), 3);
        assert_eq!(s.add(Tsn(3), seq.unordered("ef", ""), &mut |_| {}), 2);
        // Adding the end fragment should make it empty again.
        assert_eq!(s.add(Tsn(4), seq.unordered("g", "E"), &mut |_| {}), -6);
    }

    #[test]
    fn add_unordered_message_out_of_order_returns_correct_size() {
        let mut s = InterleavedReassemblyStreams::new();
        let mut seq = DataSequencer::new(StreamId(1));
        let mut messages = Vec::new();

        let c1 = seq.unordered("a", "B");
        let c2 = seq.unordered("bcd", "");
        let c3 = seq.unordered("ef", "");
        let c4 = seq.unordered("g", "E");

        assert_eq!(s.add(Tsn(1), c1, &mut |m| messages.push(m)), 1);
        assert_eq!(s.add(Tsn(2), c2, &mut |m| messages.push(m)), 3);
        assert_eq!(s.add(Tsn(4), c4, &mut |m| messages.push(m)), 1);
        assert!(messages.is_empty());
        assert_eq!(s.add(Tsn(3), c3, &mut |m| messages.push(m)), -5);
        assert_eq!(messages.len(), 1);
    }

    #[test]
    fn add_simple_ordered_message_returns_correct_size() {
        let mut s = InterleavedReassemblyStreams::new();
        let mut seq = DataSequencer::new(StreamId(1));
        let mut messages = Vec::new();

        let c1 = seq.ordered("a", "B");
        let c2 = seq.ordered("bcd", "");
        let c3 = seq.ordered("ef", "");
        let c4 = seq.ordered("g", "E");

        assert_eq!(s.add(Tsn(1), c1, &mut |m| messages.push(m)), 1);
        assert_eq!(s.add(Tsn(2), c2, &mut |m| messages.push(m)), 3);
        assert_eq!(s.add(Tsn(3), c3, &mut |m| messages.push(m)), 2);
        assert_eq!(s.add(Tsn(4), c4, &mut |m| messages.push(m)), -6);
        assert_eq!(messages.len(), 1);
    }

    #[test]
    fn add_more_complex_ordered_message_returns_correct_size() {
        let mut s = InterleavedReassemblyStreams::new();
        let mut seq = DataSequencer::new(StreamId(1));
        let mut messages = Vec::new();

        let c11 = seq.ordered("a", "B");
        let c12 = seq.ordered("bcd", "");
        let c13 = seq.ordered("ef", "");
        let c14 = seq.ordered("g", "E");
        let c21 = seq.ordered("h", "BE");
        let c31 = seq.ordered("ij", "B");
        let c32 = seq.ordered("k", "E");

        assert_eq!(s.add(Tsn(1), c11, &mut |m| messages.push(m)), 1);
        assert_eq!(s.add(Tsn(3), c13, &mut |m| messages.push(m)), 2);
        assert_eq!(s.add(Tsn(4), c14, &mut |m| messages.push(m)), 1);
        assert_eq!(s.add(Tsn(5), c21, &mut |m| messages.push(m)), 1);
        assert_eq!(s.add(Tsn(6), c31, &mut |m| messages.push(m)), 2);
        assert_eq!(s.add(Tsn(7), c32, &mut |m| messages.push(m)), 1);
        assert!(messages.is_empty());
        assert_eq!(s.add(Tsn(2), c12, &mut |m| messages.push(m)), -8);

        assert_eq!(messages.len(), 3);
    }

    #[test]
    fn delete_unordered_message_returns_correct_size() {
        let mut s = InterleavedReassemblyStreams::new();
        let mut seq = DataSequencer::new(StreamId(1));
        let mut messages = Vec::new();

        let c1 = seq.unordered("a", "B");
        let c2 = seq.unordered("bcd", "");
        let c3 = seq.unordered("ef", "");

        assert_eq!(s.add(Tsn(1), c1, &mut |m| messages.push(m)), 1);
        assert_eq!(s.add(Tsn(2), c2, &mut |m| messages.push(m)), 3);
        assert_eq!(s.add(Tsn(3), c3, &mut |m| messages.push(m)), 2);
        // Adding the end fragment should make it empty again.
        assert_eq!(
            s.handle_forward_tsn(
                Tsn(3),
                &[SkippedStream::IForwardTsn(StreamKey::Unordered(StreamId(1)), Mid(0))],
                &mut |m| messages.push(m)
            ),
            6
        );
    }

    #[test]
    fn delete_simple_ordered_message_returns_correct_size() {
        let mut s = InterleavedReassemblyStreams::new();
        let mut seq = DataSequencer::new(StreamId(1));
        let mut messages = Vec::new();

        let c1 = seq.ordered("a", "B");
        let c2 = seq.ordered("bcd", "");
        let c3 = seq.ordered("ef", "");
        assert_eq!(s.add(Tsn(1), c1, &mut |m| messages.push(m)), 1);
        assert_eq!(s.add(Tsn(2), c2, &mut |m| messages.push(m)), 3);
        assert_eq!(s.add(Tsn(3), c3, &mut |m| messages.push(m)), 2);
        // Adding the end fragment should make it empty again.
        assert_eq!(
            s.handle_forward_tsn(
                Tsn(3),
                &[SkippedStream::IForwardTsn(StreamKey::Ordered(StreamId(1)), Mid(0))],
                &mut |m| messages.push(m)
            ),
            6
        );
    }

    #[test]
    fn delete_many_ordered_messages_returns_correct_size() {
        let mut s = InterleavedReassemblyStreams::new();
        let mut seq = DataSequencer::new(StreamId(1));
        let mut messages = Vec::new();

        let c1 = seq.ordered("a", "B");
        seq.ordered("bcd", ""); // TSN=2 Not received.
        let c3 = seq.ordered("ef", "");
        let c4 = seq.ordered("g", "E");
        let c5 = seq.ordered("h", "BE");
        let c6 = seq.ordered("ij", "B");
        let c7 = seq.ordered("k", "E");

        assert_eq!(s.add(Tsn(1), c1, &mut |m| messages.push(m)), 1);
        assert_eq!(s.add(Tsn(3), c3, &mut |m| messages.push(m)), 2);
        assert_eq!(s.add(Tsn(4), c4, &mut |m| messages.push(m)), 1);
        assert_eq!(s.add(Tsn(5), c5, &mut |m| messages.push(m)), 1);
        assert_eq!(s.add(Tsn(6), c6, &mut |m| messages.push(m)), 2);
        assert_eq!(s.add(Tsn(7), c7, &mut |m| messages.push(m)), 1);

        assert_eq!(
            s.handle_forward_tsn(
                Tsn(8),
                &[SkippedStream::IForwardTsn(StreamKey::Ordered(StreamId(1)), Mid(2))],
                &mut |m| messages.push(m)
            ),
            8
        );
    }

    #[test]
    fn delete_ordered_message_delives_two_returns_correct_size() {
        let mut s = InterleavedReassemblyStreams::new();
        let mut seq = DataSequencer::new(StreamId(1));
        let mut messages = Vec::new();

        let c1 = seq.ordered("a", "B");
        seq.ordered("bcd", ""); // TSN=2 Not received.
        let c3 = seq.ordered("ef", "");
        let c4 = seq.ordered("g", "E");
        let c5 = seq.ordered("h", "BE");
        let c6 = seq.ordered("ij", "B");
        let c7 = seq.ordered("k", "E");

        assert_eq!(s.add(Tsn(1), c1, &mut |m| messages.push(m)), 1);

        assert_eq!(s.add(Tsn(3), c3, &mut |m| messages.push(m)), 2);
        assert_eq!(s.add(Tsn(4), c4, &mut |m| messages.push(m)), 1);

        assert_eq!(s.add(Tsn(5), c5, &mut |m| messages.push(m)), 1);
        assert_eq!(s.add(Tsn(6), c6, &mut |m| messages.push(m)), 2);
        assert_eq!(s.add(Tsn(7), c7, &mut |m| messages.push(m)), 1);

        assert_eq!(
            s.handle_forward_tsn(
                Tsn(8),
                &[SkippedStream::IForwardTsn(StreamKey::Ordered(StreamId(1)), Mid(0))],
                &mut |m| messages.push(m)
            ),
            8
        );
        assert_eq!(messages.len(), 2);
    }

    #[test]
    fn can_delete_first_ordered_message() {
        let mut s = InterleavedReassemblyStreams::new();
        let mut seq = DataSequencer::new(StreamId(1));
        let mut messages = Vec::new();

        seq.ordered("abc", "BE"); // TSN=1 Not received.
        let c2 = seq.ordered("def", "BE");
        assert_eq!(
            s.handle_forward_tsn(
                Tsn(1),
                &[SkippedStream::IForwardTsn(StreamKey::Ordered(StreamId(1)), Mid(0))],
                &mut |m| messages.push(m)
            ),
            0
        );

        assert_eq!(s.add(Tsn(2), c2, &mut |m| messages.push(m)), 0);
        assert_eq!(messages.len(), 1);
    }

    #[test]
    fn can_reassemble_fast_path_unordered() {
        let mut s = InterleavedReassemblyStreams::new();
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
        let mut s = InterleavedReassemblyStreams::new();
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

    #[test]
    fn can_handover_ordered_streams() {
        let mut streams1 = InterleavedReassemblyStreams::new();
        let mut seq = DataSequencer::new(StreamId(1));

        // Check readiness: Should only be ready when there are no unassembled chunks.
        assert_eq!(streams1.add(Tsn(1), seq.ordered("a", "B"), &mut |_| {}), 1);
        assert!(
            streams1
                .get_handover_readiness()
                .contains(HandoverReadiness::STREAM_HAS_UNASSEMBLED_CHUNKS)
        );
        assert_eq!(streams1.add(Tsn(2), seq.ordered("bcd", "E"), &mut |_| {}), -1);
        assert!(streams1.get_handover_readiness().is_ready());

        // Save and restore state
        let mut state = SocketHandoverState::default();
        streams1.add_to_handover_state(&mut state);

        let mut streams2 = InterleavedReassemblyStreams::new();
        let mut messages = Vec::new();
        streams2.restore_from_state(&state);

        // Verify restored state handles new message correctly (preserves next expected MID)
        let data = seq.ordered("efgh", "BE");
        assert_eq!(data.mid, Mid(1));

        assert_eq!(streams2.add(Tsn(3), data, &mut |m| messages.push(m)), 0);
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].payload, b"efgh");
    }

    #[test]
    fn can_handover_unordered_streams() {
        let mut streams1 = InterleavedReassemblyStreams::new();
        let mut seq = DataSequencer::new(StreamId(1));

        // Check readiness: Should only be ready when there are no unassembled chunks.
        assert_eq!(streams1.add(Tsn(1), seq.unordered("a", "B"), &mut |_| {}), 1);
        assert!(
            streams1
                .get_handover_readiness()
                .contains(HandoverReadiness::STREAM_HAS_UNASSEMBLED_CHUNKS)
        );
        assert_eq!(streams1.add(Tsn(2), seq.unordered("bcd", "E"), &mut |_| {}), -1);
        assert!(streams1.get_handover_readiness().is_ready());

        // Save and restore state
        let mut state = SocketHandoverState::default();
        streams1.add_to_handover_state(&mut state);

        let mut streams2 = InterleavedReassemblyStreams::new();
        let mut messages = Vec::new();
        streams2.restore_from_state(&state);

        // Verify restored state
        let data = seq.unordered("efgh", "BE");
        assert_eq!(streams2.add(Tsn(3), data, &mut |m| messages.push(m)), 0);
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].payload, b"efgh");
    }
}
