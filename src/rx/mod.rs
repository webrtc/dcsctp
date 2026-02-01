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
use crate::packet::data::Data;
use std::collections::VecDeque;

pub mod data_tracker;
pub mod interleaved_reassembly_streams;
pub mod reassembly_queue;
pub mod reassembly_streams;
pub mod traditional_reassembly_streams;

/// A trait defining the ordering and adjacency of fragments.
pub trait ReassemblyKey: Copy + Ord {
    /// Returns the key that would represent the successor (next following) fragment within this
    /// message.
    fn next(&self) -> Self;
}

/// A contiguous sequence of assembled chunks.
///
/// An interval represents a range of reassembled data, from `start` to `end`.
/// It may or may not be a complete message (indicated by `has_beginning` and `has_end`).
#[derive(Debug, PartialEq)]
pub struct Interval<K: ReassemblyKey> {
    /// The key of the first chunk in this interval.
    pub start: K,
    /// The key of the last chunk in this interval.
    pub end: K,
    /// Whether this interval contains the beginning of a message (B-bit set).
    pub has_beginning: bool,
    /// Whether this interval contains the end of a message (E-bit set).
    pub has_end: bool,
    /// The Payload Protocol Identifier (PPID) of the message.
    /// Only valid if `has_beginning` is true (as per RFC 8260).
    pub ppid: PpId,
    /// The payload data chunks that make up this interval.
    pub payload: VecDeque<Vec<u8>>,
}

impl<K: ReassemblyKey> Interval<K> {
    /// Consumes the interval and returns the assembled payload.
    pub fn collect_payload(self) -> Vec<u8> {
        let mut parts = self.payload;
        if parts.len() == 1 {
            parts.pop_front().unwrap()
        } else {
            let total_payload_len = parts.iter().map(|p| p.len()).sum();
            let mut payload = Vec::with_capacity(total_payload_len);
            for p in parts {
                payload.extend(p);
            }
            payload
        }
    }
}

/// A list of non-overlapping, non-adjacent sorted intervals of received chunks.
#[derive(Debug)]
pub struct IntervalList<K: ReassemblyKey> {
    intervals: Vec<Interval<K>>,
}

impl<K: ReassemblyKey> Default for IntervalList<K> {
    fn default() -> Self {
        Self { intervals: Vec::new() }
    }
}

impl<K: ReassemblyKey> IntervalList<K> {
    pub fn is_empty(&self) -> bool {
        self.intervals.is_empty()
    }

    /// Adds a new chunk to the list, merging it with existing intervals if possible.
    ///
    /// This method expects that the data is deduplicated and sanity checked by the caller, e.g. by
    /// the DataTracker.
    ///
    /// Returns the index of the interval containing the added chunk.
    pub fn add(&mut self, key: K, data: Data) -> usize {
        // Find the insertion point or the interval that starts after this chunk.
        let idx = self.intervals.partition_point(|i| i.start < key);

        // Check if we can extend the interval immediately to the left (predecessor).
        let extend_left = if idx > 0 {
            let left = &self.intervals[idx - 1];
            left.end.next() == key && !left.has_end && !data.is_beginning
        } else {
            false
        };

        // Check if we can extend the interval immediately to the right (successor).
        let extend_right = if idx < self.intervals.len() {
            let right = &self.intervals[idx];
            key.next() == right.start && !right.has_beginning && !data.is_end
        } else {
            false
        };

        if extend_left && extend_right {
            // "Bridge the gap" - merge left, new chunk, and right into a single interval.
            let mut right = self.intervals.remove(idx);
            let left = &mut self.intervals[idx - 1];

            left.end = right.end;
            left.has_end = right.has_end;
            left.payload.push_back(data.payload);
            left.payload.append(&mut right.payload);
            idx - 1
        } else if extend_left {
            let left = &mut self.intervals[idx - 1];
            left.end = key;
            left.has_end = data.is_end;
            left.payload.push_back(data.payload);
            idx - 1
        } else if extend_right {
            let right = &mut self.intervals[idx];
            right.start = key;
            right.has_beginning = data.is_beginning;

            // Only update PPID if this chunk is the beginning, as it's only valid then in RFC8260.
            if data.is_beginning {
                right.ppid = data.ppid;
            }
            right.payload.push_front(data.payload);
            idx
        } else {
            // No merge possible, insert new isolated interval.
            self.intervals.insert(
                idx,
                Interval {
                    start: key,
                    end: key,
                    has_beginning: data.is_beginning,
                    has_end: data.is_end,
                    ppid: data.ppid,
                    payload: VecDeque::from([data.payload]),
                },
            );
            idx
        }
    }

    /// Checks if the interval at `idx` is a fully assembled message, which removes and returns it.
    pub fn pop_if_complete(&mut self, idx: usize) -> Option<Interval<K>> {
        if idx < self.intervals.len()
            && self.intervals[idx].has_beginning
            && self.intervals[idx].has_end
        {
            Some(self.intervals.remove(idx))
        } else {
            None
        }
    }

    /// Peeks at the first interval. If it is fully assembled AND satisfies the `predicate`, removes
    /// and returns it.
    pub fn pop_front_if_complete_and<F>(&mut self, predicate: F) -> Option<Interval<K>>
    where
        F: FnOnce(&Interval<K>) -> bool,
    {
        let interval = self.intervals.first()?;

        if interval.has_beginning && interval.has_end && predicate(interval) {
            Some(self.intervals.remove(0))
        } else {
            None
        }
    }

    /// Retains only the intervals specified by the predicate.
    ///
    /// Returns the total number of bytes (payload size) that were removed.
    pub fn retain<F>(&mut self, mut f: F) -> usize
    where
        F: FnMut(&Interval<K>) -> bool,
    {
        let mut bytes_removed = 0;
        self.intervals.retain(|interval| {
            if !f(interval) {
                bytes_removed += interval.payload.iter().map(|p| p.len()).sum::<usize>();
                false
            } else {
                true
            }
        });
        bytes_removed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::StreamId;
    use crate::testing::data_sequencer::DataSequencer;
    use crate::types::Tsn;

    // A simple key that wraps around a TSN, which wraps around at u32::MAX.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    struct TestKey(Tsn);

    impl ReassemblyKey for TestKey {
        fn next(&self) -> Self {
            TestKey(self.0 + 1)
        }
    }

    #[test]
    fn add_independent_intervals() {
        let mut list = IntervalList::default();
        let mut seq = DataSequencer::new(StreamId(0));

        // Add [3]
        let idx = list.add(TestKey(Tsn(3)), seq.ordered("p0", "BE"));
        assert_eq!(idx, 0);
        assert_eq!(list.intervals.len(), 1);

        // Add [5] -> should be index 1
        let idx = list.add(TestKey(Tsn(5)), seq.ordered("p1", "BE"));
        assert_eq!(idx, 1);
        assert_eq!(list.intervals.len(), 2);

        // Add [1] -> should be index 0
        let idx = list.add(TestKey(Tsn(1)), seq.ordered("p2", "BE"));
        assert_eq!(idx, 0);
        assert_eq!(list.intervals.len(), 3);

        // Verify content
        assert_eq!(list.intervals[0].start, TestKey(Tsn(1)));
        assert_eq!(list.intervals[1].start, TestKey(Tsn(3)));
        assert_eq!(list.intervals[2].start, TestKey(Tsn(5)));
    }

    #[test]
    fn add_merge_left() {
        let mut list = IntervalList::default();
        let mut seq = DataSequencer::new(StreamId(0));

        // [10] (Begin)
        list.add(TestKey(Tsn(10)), seq.ordered("p0", "B"));

        // Add [11] (Middle) -> merges with [10]
        let idx = list.add(TestKey(Tsn(11)), seq.ordered("p1", ""));

        // Should still be index 0, one interval
        assert_eq!(idx, 0);
        assert_eq!(list.intervals.len(), 1);
        assert_eq!(list.intervals[0].start, TestKey(Tsn(10)));
        assert_eq!(list.intervals[0].end, TestKey(Tsn(11)));
        assert_eq!(list.intervals[0].payload.len(), 2);
    }

    #[test]
    fn add_merge_right() {
        let mut list = IntervalList::default();
        let mut seq = DataSequencer::new(StreamId(0));

        // [11] (End)
        list.add(TestKey(Tsn(11)), seq.ordered("p1", "E"));

        // Add [10] (Begin) -> merges with [11]
        let idx = list.add(TestKey(Tsn(10)), seq.ordered("p0", "B"));

        assert_eq!(idx, 0);
        assert_eq!(list.intervals.len(), 1);
        assert_eq!(list.intervals[0].start, TestKey(Tsn(10)));
        assert_eq!(list.intervals[0].end, TestKey(Tsn(11)));
        // Verify payload order
        assert_eq!(list.intervals[0].payload, &[b"p0", b"p1"]);
        // Verify PPID inherited from Begin chunk
        assert_eq!(list.intervals[0].ppid, PpId(53));
    }

    #[test]
    fn add_doesnt_merge_right_on_begin_end_border() {
        let mut list = IntervalList::default();
        let mut seq = DataSequencer::new(StreamId(0));

        // [11] (End)
        let idx = list.add(TestKey(Tsn(11)), seq.unordered("p1", "E"));
        assert_eq!(idx, 0);

        // Add [12] (Begin) -> will not merge with [11], as they are from different messages.
        let idx = list.add(TestKey(Tsn(12)), seq.unordered("p2", "B"));
        assert_eq!(idx, 1);

        assert_eq!(list.intervals.len(), 2);
        assert_eq!(list.intervals[0].start, TestKey(Tsn(11)));
        assert_eq!(list.intervals[0].end, TestKey(Tsn(11)));
        assert_eq!(list.intervals[0].payload, &[b"p1"]);
        assert!(!list.intervals[0].has_beginning);
        assert!(list.intervals[0].has_end);

        assert_eq!(list.intervals[1].start, TestKey(Tsn(12)));
        assert_eq!(list.intervals[1].end, TestKey(Tsn(12)));
        assert_eq!(list.intervals[1].payload, &[b"p2"]);
        assert!(list.intervals[1].has_beginning);
        assert!(!list.intervals[1].has_end);
    }

    #[test]
    fn add_merge_both_filling_gap() {
        let mut list = IntervalList::default();
        let mut seq = DataSequencer::new(StreamId(0));

        // [10] (Begin)
        list.add(TestKey(Tsn(10)), seq.ordered("p0", "B"));
        // [12] (End)
        list.add(TestKey(Tsn(12)), seq.ordered("p2", "E"));
        assert_eq!(list.intervals.len(), 2);

        // Add [11] (Middle) -> merges both [10] and [12]
        let idx = list.add(TestKey(Tsn(11)), seq.ordered("p1", ""));

        assert_eq!(idx, 0);
        assert_eq!(list.intervals.len(), 1);
        let interval = &list.intervals[0];
        assert_eq!(interval.start, TestKey(Tsn(10)));
        assert_eq!(interval.end, TestKey(Tsn(12)));
        assert!(interval.has_beginning);
        assert!(interval.has_end);
        assert_eq!(interval.payload, &[b"p0", b"p1", b"p2"]);
    }

    #[test]
    fn add_wrapping_interval() {
        let mut list = IntervalList::default();
        let mut seq = DataSequencer::new(StreamId(0));

        // [u32::MAX] (Begin)
        list.add(TestKey(Tsn(u32::MAX)), seq.ordered("p0", "B"));

        // Add [0] (End) -> should merge because u32::MAX + 1 == 0 (wrapped)
        let idx = list.add(TestKey(Tsn(0)), seq.ordered("p1", "E"));

        assert_eq!(idx, 0);
        assert_eq!(list.intervals.len(), 1);
        let interval = &list.intervals[0];
        assert_eq!(interval.start, TestKey(Tsn(u32::MAX)));
        assert_eq!(interval.end, TestKey(Tsn(0)));
        assert!(interval.has_end);
        assert!(interval.has_beginning);
        assert_eq!(interval.payload.len(), 2);
        assert_eq!(interval.payload, &[b"p0", b"p1"]);
    }

    #[test]
    fn pop_if_complete_extracts_assembled() {
        let mut list = IntervalList::default();
        let mut seq = DataSequencer::new(StreamId(0));

        // [10] Complete
        list.add(TestKey(Tsn(10)), seq.ordered("p0", "BE"));
        // [12] Incomplete
        list.add(TestKey(Tsn(12)), seq.ordered("p1", "B"));

        assert_eq!(list.intervals.len(), 2);

        // Try pop incomplete
        assert!(list.pop_if_complete(1).is_none());
        assert_eq!(list.intervals.len(), 2);

        // Pop complete
        let popped = list.pop_if_complete(0).expect("Should pop");
        assert_eq!(popped.start, TestKey(Tsn(10)));
        assert_eq!(list.intervals.len(), 1);
        assert_eq!(list.intervals[0].start, TestKey(Tsn(12)));
    }

    #[test]
    fn retain_removes_matching_intervals() {
        let mut list = IntervalList::default();
        let mut seq = DataSequencer::new(StreamId(0));

        list.add(TestKey(Tsn(10)), seq.ordered("p0", "BE"));
        list.add(TestKey(Tsn(20)), seq.ordered("p1", "BE"));
        list.add(TestKey(Tsn(30)), seq.ordered("p2", "BE"));

        // Remove intervals > 15
        let removed_bytes = list.retain(|i| i.start <= TestKey(Tsn(15)));

        assert_eq!(list.intervals.len(), 1);
        assert_eq!(list.intervals[0].start, TestKey(Tsn(10)));
        assert_eq!(removed_bytes, 4);
    }
}
