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
use crate::rx::reassembly_streams::ReassemblyStreams;
use crate::types::Fsn;
use crate::types::Mid;
use crate::types::StreamKey;
use crate::types::Tsn;
use std::collections::BTreeMap;
use std::collections::HashMap;

pub struct Stream {
    stream_key: StreamKey,
    chunks_by_mid: BTreeMap<Mid, BTreeMap<Fsn, Data>>,
    next_mid: Mid,
}

impl Stream {
    pub fn new(stream_key: StreamKey) -> Self {
        Self {
            stream_key,
            chunks_by_mid: BTreeMap::<Mid, BTreeMap<Fsn, Data>>::new(),
            next_mid: Mid(0),
        }
    }

    fn try_to_assemble_messages(
        &mut self,
        start_mid: Mid,
        on_reassembled: &mut dyn FnMut(Message),
    ) -> usize {
        let mut assembled_bytes = 0;
        let mut mid = start_mid;
        while let Some(chunks) = self.chunks_by_mid.get_mut(&mid) {
            let (first_fsn, first_data) = chunks.first_key_value().unwrap();
            let (last_fsn, last_data) = chunks.last_key_value().unwrap();
            if !first_data.is_beginning
                || !last_data.is_end
                || first_fsn.distance_to(*last_fsn) != (chunks.len() as u32 - 1)
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
            self.chunks_by_mid.remove(&mid);
            self.next_mid += 1;
            mid = self.next_mid;
        }
        assembled_bytes
    }
}

pub struct InterleavedReassemblyStreams {
    streams: HashMap<StreamKey, Stream>,
}

impl InterleavedReassemblyStreams {
    pub fn new() -> Self {
        Self { streams: HashMap::new() }
    }

    fn get_or_create(&mut self, stream_key: StreamKey) -> &mut Stream {
        self.streams.entry(stream_key).or_insert_with(|| Stream::new(stream_key))
    }
}

impl ReassemblyStreams for InterleavedReassemblyStreams {
    fn add(&mut self, _tsn: Tsn, data: Data, on_reassembled: &mut dyn FnMut(Message)) -> isize {
        let stream = self.get_or_create(data.stream_key);
        let mid = data.mid;
        let can_assemble = data.stream_key.is_unordered() || mid == stream.next_mid;

        let mut queued_bytes = 0;
        if can_assemble && data.is_beginning && data.is_end {
            // Fast path - reassemble directly if possible, without adding to buffer.
            on_reassembled(Message::new(data.stream_key.id(), data.ppid, data.payload));
            stream.next_mid += 1;
        } else {
            queued_bytes += data.payload.len() as isize;
            stream.chunks_by_mid.entry(mid).or_default().insert(data.fsn, data);
        }

        if can_assemble {
            queued_bytes -=
                stream.try_to_assemble_messages(stream.next_mid, on_reassembled) as isize;
        }
        queued_bytes
    }

    fn handle_forward_tsn(
        &mut self,
        _new_cumulative_ack: Tsn,
        skipped_streams: &[SkippedStream],
        on_reassembled: &mut dyn FnMut(Message),
    ) -> usize {
        let mut released_bytes = 0;
        for skipped_stream in skipped_streams.iter() {
            if let SkippedStream::IForwardTsn(stream_key, mid) = skipped_stream {
                let stream = self.get_or_create(*stream_key);

                stream.chunks_by_mid.retain(|cur_mid, chunks| {
                    if cur_mid <= mid {
                        released_bytes +=
                            chunks.iter().fold(0, |acc, (_, data)| acc + data.payload.len());
                        false
                    } else {
                        true
                    }
                });
                stream.next_mid = stream.next_mid.max(*mid + 1);
                released_bytes += stream.try_to_assemble_messages(stream.next_mid, on_reassembled);
            }
        }
        released_bytes
    }

    fn reset_streams(&mut self, streams: &[StreamId]) {
        self.streams
            .iter_mut()
            .filter(|(stream_key, _)| streams.is_empty() || streams.contains(&stream_key.id()))
            .for_each(|(_, stream)| stream.next_mid = Mid(0));
    }

    fn get_handover_readiness(&self) -> HandoverReadiness {
        let has_unassembled_chunks = self.streams.iter().any(|(_, s)| !s.chunks_by_mid.is_empty());

        HandoverReadiness::STREAM_HAS_UNASSEMBLED_CHUNKS & has_unassembled_chunks
    }

    fn add_to_handover_state(&self, _state: &mut SocketHandoverState) {
        todo!()
    }

    fn restore_from_state(&mut self, _state: &SocketHandoverState) {
        todo!()
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
}
