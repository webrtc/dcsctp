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

use crate::api::StreamId;
use std::cmp::min;
use std::cmp::Ordering;
use std::collections::HashMap;

#[derive(Debug, PartialEq)]
enum SchedulingParameters {
    RoundRobin,
    WeightedFairQueuing(f64 /* inverse weight */),
}

#[derive(Debug, PartialEq)]
struct ActiveStreamInfo {
    stream_id: StreamId,
    parameters: SchedulingParameters,
    start_vt: f64,
    next_vt: f64,
    bytes_remaining: usize,
}

impl Default for ActiveStreamInfo {
    fn default() -> Self {
        Self {
            stream_id: StreamId(0),
            parameters: SchedulingParameters::RoundRobin,
            start_vt: 0.0,
            next_vt: 0.0,
            bytes_remaining: 0,
        }
    }
}

impl Ord for ActiveStreamInfo {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.next_vt == other.next_vt {
            self.stream_id.cmp(&other.stream_id)
        } else {
            self.next_vt.partial_cmp(&other.next_vt).unwrap()
        }
    }
}

impl PartialOrd for ActiveStreamInfo {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Eq for ActiveStreamInfo {}

pub struct StreamScheduler {
    max_payload_bytes: usize,
    current_stream: Option<StreamId>,
    current_vt: f64,
    active_streams: HashMap<StreamId, ActiveStreamInfo>,
}

/// Returns the new virtual time for the provided stream, given how many bytes of data that was
/// produced from it.
fn calculate_vt(active_stream: &ActiveStreamInfo, bytes: usize) -> f64 {
    active_stream.start_vt
        + match active_stream.parameters {
            SchedulingParameters::WeightedFairQueuing(iw) => bytes as f64 * iw,
            SchedulingParameters::RoundRobin => 1.0,
        }
}

/// Keeps track of all active streams and decides which stream that the next data chunk can be sent
/// from, based on the scheduler and stream priorities (if any).
impl StreamScheduler {
    pub fn new(max_payload_bytes: usize) -> Self {
        Self {
            max_payload_bytes,
            current_stream: None,
            current_vt: 0.0,
            active_streams: HashMap::new(),
        }
    }

    /// Updates the remaining number of bytes in the next following message in a stream. Priority is
    /// set if message interleaving (RFC 8260) and WFQ is to be used, otherwise it should be set to
    /// None for round-robin scheduling on message boundaries.
    pub fn set_bytes_remaining(
        &mut self,
        stream_id: StreamId,
        bytes_remaining: usize,
        priority: Option<u16>,
    ) {
        if bytes_remaining == 0 {
            self.active_streams.remove(&stream_id);
            if self.current_stream == Some(stream_id) {
                self.current_stream = None;
            }
            return;
        }

        let active_stream = self.active_streams.entry(stream_id).or_insert_with(|| {
            ActiveStreamInfo { stream_id, start_vt: self.current_vt, ..Default::default() }
        });
        active_stream.parameters = match priority {
            Some(v) => SchedulingParameters::WeightedFairQueuing(1.0 / v as f64),
            None => SchedulingParameters::RoundRobin,
        };
        active_stream.bytes_remaining = bytes_remaining;
        active_stream.next_vt =
            calculate_vt(active_stream, min(active_stream.bytes_remaining, self.max_payload_bytes));
    }

    /// Given space for `max_size` bytes, returns which stream that data should be produced from,
    /// and how many bytes to produce from that stream.
    ///
    /// After having called this, [`Self::set_bytes_remaining`] can be set to reject the proposal,
    /// or [`Self::accept`] should be called with the returned stream and size to accept it.
    pub fn peek(&self, max_size: usize) -> Option<(StreamId, usize)> {
        let active_stream = self
            .current_stream
            .and_then(|stream_id| self.active_streams.get(&stream_id))
            .or_else(|| self.active_streams.values().min())?;

        Some((active_stream.stream_id, min(active_stream.bytes_remaining, max_size)))
    }

    /// After having called [`Self::peek`], accept to produce from the returned stream.
    ///
    /// This must be called after having called [`Self::peek`], which guarantees that `stream_id`
    /// and `bytes` are valid.
    pub fn accept(&mut self, stream_id: StreamId, bytes: usize) {
        debug_assert!(self.active_streams.contains_key(&stream_id));
        self.current_stream = Some(stream_id);
        let active_stream = self.active_streams.get_mut(&stream_id).unwrap();
        self.current_vt = calculate_vt(active_stream, bytes);

        debug_assert!(active_stream.bytes_remaining >= bytes);
        active_stream.bytes_remaining -= bytes;

        if active_stream.bytes_remaining == 0 {
            // Consumed entire message - reschedule.
            self.current_stream = None;
            self.active_streams.remove(&stream_id);
        } else {
            active_stream.start_vt = self.current_vt;
            active_stream.next_vt = calculate_vt(
                active_stream,
                min(active_stream.bytes_remaining, self.max_payload_bytes),
            );

            if let SchedulingParameters::WeightedFairQueuing(_) = active_stream.parameters {
                // For non-interleaved streams, avoid rescheduling while still sending a message as
                // it needs to be sent in full. For interleaved messaging, reschedule for every
                // I-DATA chunk sent.
                self.current_stream = None
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MTU: usize = 1280;

    struct TestStreamConfig {
        priority: Option<u16>,
        packet_size: usize,
    }
    impl TestStreamConfig {
        fn new(priority: Option<u16>, packet_size: usize) -> Self {
            Self { priority, packet_size }
        }
    }

    fn send_packets(
        q: &mut StreamScheduler,
        stream_configs: &[TestStreamConfig],
        packet_count: usize,
    ) -> Vec<usize> {
        let mut packet_counts: Vec<usize> = vec![0; stream_configs.len()];

        for (idx, config) in stream_configs.iter().enumerate() {
            q.set_bytes_remaining(StreamId(idx as u16), config.packet_size, config.priority);
        }
        for _ in 0..packet_count {
            let c = produce(q, MTU).unwrap();
            let idx = c.0 .0 as usize;
            packet_counts[idx] += 1;
            let config = &stream_configs[idx];
            q.set_bytes_remaining(c.0, config.packet_size, config.priority);
        }

        packet_counts
    }

    fn produce(s: &mut StreamScheduler, max_size: usize) -> Option<(StreamId, usize)> {
        s.peek(max_size).map(|(stream_id, bytes)| {
            s.accept(stream_id, bytes);
            (stream_id, bytes)
        })
    }

    #[test]
    fn has_no_active_streams() {
        let mut s = StreamScheduler::new(MTU);
        assert!(produce(&mut s, MTU).is_none());
    }

    #[test]
    fn can_produce_from_single_stream() {
        let mut s = StreamScheduler::new(MTU);
        s.set_bytes_remaining(StreamId(1), 10, None);
        assert_eq!(produce(&mut s, MTU), Some((StreamId(1), 10)));
    }

    #[test]
    fn will_round_robin_between_streams() {
        let mut s = StreamScheduler::new(MTU);
        s.set_bytes_remaining(StreamId(1), 10, None);
        s.set_bytes_remaining(StreamId(2), 10, None);
        s.set_bytes_remaining(StreamId(3), 10, None);
        assert_eq!(produce(&mut s, MTU), Some((StreamId(1), 10)));
        s.set_bytes_remaining(StreamId(1), 10, None);
        assert_eq!(produce(&mut s, MTU), Some((StreamId(2), 10)));
        s.set_bytes_remaining(StreamId(2), 10, None);
        assert_eq!(produce(&mut s, MTU), Some((StreamId(3), 10)));
        s.set_bytes_remaining(StreamId(3), 10, None);

        assert_eq!(produce(&mut s, MTU), Some((StreamId(1), 10)));
        s.set_bytes_remaining(StreamId(1), 10, None);
        assert_eq!(produce(&mut s, MTU), Some((StreamId(2), 10)));
        s.set_bytes_remaining(StreamId(2), 10, None);
        assert_eq!(produce(&mut s, MTU), Some((StreamId(3), 10)));
        s.set_bytes_remaining(StreamId(3), 10, None);

        assert_eq!(produce(&mut s, MTU), Some((StreamId(1), 10)));
        assert_eq!(produce(&mut s, MTU), Some((StreamId(2), 10)));
        assert_eq!(produce(&mut s, MTU), Some((StreamId(3), 10)));

        assert!(produce(&mut s, MTU).is_none());
    }

    #[test]
    fn will_round_robin_only_when_finished_producing_chunk() {
        // Switches between two streams after every packet, but keeps producing from the same stream
        // when a packet contains of multiple fragments.
        let mut s = StreamScheduler::new(MTU);
        s.set_bytes_remaining(StreamId(1), MTU, None);
        s.set_bytes_remaining(StreamId(2), MTU, None);
        assert_eq!(produce(&mut s, MTU), Some((StreamId(1), MTU)));
        s.set_bytes_remaining(StreamId(1), 3 * MTU, None);
        assert_eq!(produce(&mut s, MTU), Some((StreamId(2), MTU)));
        s.set_bytes_remaining(StreamId(2), MTU, None);
        assert_eq!(produce(&mut s, MTU), Some((StreamId(1), MTU)));
        assert_eq!(produce(&mut s, MTU), Some((StreamId(1), MTU)));
        assert_eq!(produce(&mut s, MTU), Some((StreamId(1), MTU)));
        s.set_bytes_remaining(StreamId(1), MTU, None);
        assert_eq!(produce(&mut s, MTU), Some((StreamId(2), MTU)));
        assert_eq!(produce(&mut s, MTU), Some((StreamId(1), MTU)));
        assert!(produce(&mut s, MTU).is_none());
    }

    #[test]
    fn streams_can_be_made_inactive() {
        // Deactivates a stream before it has finished producing all packets.
        let mut s = StreamScheduler::new(MTU);
        s.set_bytes_remaining(StreamId(1), MTU, None);
        assert_eq!(produce(&mut s, MTU), Some((StreamId(1), MTU)));
        s.set_bytes_remaining(StreamId(1), MTU, None);
        s.set_bytes_remaining(StreamId(1), 0, None);
        assert!(produce(&mut s, MTU).is_none());
    }

    #[test]
    fn single_stream_can_be_resumed() {
        // Deactivates a stream before it has finished producing all packets.
        let mut s = StreamScheduler::new(MTU);
        s.set_bytes_remaining(StreamId(1), MTU, None);
        assert_eq!(produce(&mut s, MTU), Some((StreamId(1), MTU)));
        s.set_bytes_remaining(StreamId(1), MTU, None);
        s.set_bytes_remaining(StreamId(1), 0, None);
        assert!(produce(&mut s, MTU).is_none());

        s.set_bytes_remaining(StreamId(1), MTU, None);
        assert_eq!(produce(&mut s, MTU), Some((StreamId(1), MTU)));
        assert!(produce(&mut s, MTU).is_none());
    }

    #[test]
    fn will_round_robin_with_paused_stream() {
        // Iterates between streams, where one is suddenly paused and later resumed.
        let mut s = StreamScheduler::new(MTU);
        s.set_bytes_remaining(StreamId(1), MTU, None);
        s.set_bytes_remaining(StreamId(2), MTU, None);

        assert_eq!(produce(&mut s, MTU), Some((StreamId(1), MTU)));
        s.set_bytes_remaining(StreamId(1), MTU, None);

        assert_eq!(produce(&mut s, MTU), Some((StreamId(2), MTU)));
        s.set_bytes_remaining(StreamId(2), MTU, None);

        // Stream 1 becomes paused suddenly.
        s.set_bytes_remaining(StreamId(1), 0, None);

        assert_eq!(produce(&mut s, MTU), Some((StreamId(2), MTU)));
        s.set_bytes_remaining(StreamId(2), MTU, None);

        // Stream 1 is resumed.
        s.set_bytes_remaining(StreamId(1), MTU, None);

        assert_eq!(produce(&mut s, MTU), Some((StreamId(1), MTU)));
        s.set_bytes_remaining(StreamId(1), MTU, None);

        assert_eq!(produce(&mut s, MTU), Some((StreamId(2), MTU)));
    }

    #[test]
    fn will_distribute_round_robin_packets_evenly_two_streams() {
        // Verifies that packet counts are evenly distributed in round robin scheduling.
        let mut s = StreamScheduler::new(MTU);

        let counts = send_packets(
            &mut s,
            &[TestStreamConfig::new(Some(1), 10), TestStreamConfig::new(Some(1), 10)],
            10,
        );
        assert_eq!(counts, &[5, 5])
    }

    #[test]
    fn will_do_fair_queuing_with_same_size_same_priority() {
        let mut s = StreamScheduler::new(MTU);
        s.set_bytes_remaining(StreamId(1), 30, Some(2));
        s.set_bytes_remaining(StreamId(2), 30, Some(2));

        // t=30
        assert_eq!(produce(&mut s, MTU), Some((StreamId(1), 30)));
        s.set_bytes_remaining(StreamId(1), 30, Some(2));
        assert_eq!(produce(&mut s, MTU), Some((StreamId(2), 30)));
        s.set_bytes_remaining(StreamId(2), 30, Some(2));
        // t=60
        assert_eq!(produce(&mut s, MTU), Some((StreamId(1), 30)));
        s.set_bytes_remaining(StreamId(1), 30, Some(2));
        assert_eq!(produce(&mut s, MTU), Some((StreamId(2), 30)));
        s.set_bytes_remaining(StreamId(2), 30, Some(2));
        // t=90 (end of both streams).
        assert_eq!(produce(&mut s, MTU), Some((StreamId(1), 30)));
        assert_eq!(produce(&mut s, MTU), Some((StreamId(2), 30)));

        assert_eq!(produce(&mut s, MTU), None);
    }

    #[test]
    fn will_do_fair_queuing_with_less_produced_than_available() {
        let mut s = StreamScheduler::new(60);
        // S1, S2 adds a 120 byte message each; MTU=60, vt=[60, 60]
        s.set_bytes_remaining(StreamId(1), 60, Some(2));
        s.set_bytes_remaining(StreamId(2), 60, Some(2));

        // t=30 - produce S1 0..30 of 120, new vt=[90, 60]
        assert_eq!(produce(&mut s, 30), Some((StreamId(1), 30)));
        s.set_bytes_remaining(StreamId(1), 60, Some(2));

        // t=60 - produces S2 0..30 of 120, new vt=[90, 120]
        assert_eq!(produce(&mut s, 30), Some((StreamId(2), 30)));
        s.set_bytes_remaining(StreamId(2), 60, Some(2));

        // t=90 - produces S1 30..60 of 120, new vt=[120, 120]
        assert_eq!(produce(&mut s, 30), Some((StreamId(1), 30)));
        s.set_bytes_remaining(StreamId(1), 30, Some(2));

        // t=120 - produces S1 60..90 of 120, new vt=[150, 120]
        assert_eq!(produce(&mut s, 30), Some((StreamId(1), 30)));
        s.set_bytes_remaining(StreamId(1), 30, Some(2));

        // t=120 - produces S2 30..60 of 120, new vt=[150, 180]
        assert_eq!(produce(&mut s, 30), Some((StreamId(2), 30)));
        s.set_bytes_remaining(StreamId(2), 60, Some(2));

        // t=150 - produces S1 90..120 of 120, new vt=[x, 180]
        assert_eq!(produce(&mut s, 30), Some((StreamId(1), 30)));

        // t=180 - produces S2 60..90 of 120, new vt=[x, 210]
        assert_eq!(produce(&mut s, 30), Some((StreamId(2), 30)));
        s.set_bytes_remaining(StreamId(2), 30, Some(2));

        // t=210 - produces S2 60..90 of 120, new vt=[x, x]
        assert_eq!(produce(&mut s, 30), Some((StreamId(2), 30)));

        assert_eq!(produce(&mut s, 30), None);
    }

    #[test]
    fn will_do_fair_queuing_with_same_priority() {
        // Degrades to fair queuing with streams having identical priority.
        let mut s = StreamScheduler::new(MTU);
        s.set_bytes_remaining(StreamId(1), 30, Some(2));
        s.set_bytes_remaining(StreamId(2), 70, Some(2));

        // t=30
        assert_eq!(produce(&mut s, MTU), Some((StreamId(1), 30)));
        s.set_bytes_remaining(StreamId(1), 30, Some(2));
        // t=60
        assert_eq!(produce(&mut s, MTU), Some((StreamId(1), 30)));
        s.set_bytes_remaining(StreamId(1), 30, Some(2));
        // t=70
        assert_eq!(produce(&mut s, MTU), Some((StreamId(2), 70)));
        s.set_bytes_remaining(StreamId(2), 70, Some(2));
        // t=90
        assert_eq!(produce(&mut s, MTU), Some((StreamId(1), 30)));
        // No more data on SID=1
        // t=140
        assert_eq!(produce(&mut s, MTU), Some((StreamId(2), 70)));
        s.set_bytes_remaining(StreamId(2), 70, Some(2));
        // t=210
        assert_eq!(produce(&mut s, MTU), Some((StreamId(2), 70)));
        // No more data on SID=2

        assert_eq!(produce(&mut s, MTU), None);
    }

    #[test]
    fn will_do_weighted_fair_queuing_same_size_different_priority() {
        // Degrades to fair queuing with streams having identical priority. Sends 3 equally sized
        // messages each on SID=1,2,3.
        let mut s = StreamScheduler::new(MTU);
        const SIZE: usize = 4;
        // Priority 125 -> allowed to produce every 1000/125 ~= 80 time units.
        const PRIORITY_1: Option<u16> = Some(125);
        // Priority 200 -> allowed to produce every 1000/200 ~= 50 time units.
        const PRIORITY_2: Option<u16> = Some(200);
        // Priority 500 -> allowed to produce every 1000/500 ~= 20 time units.
        const PRIORITY_3: Option<u16> = Some(500);

        s.set_bytes_remaining(StreamId(1), SIZE, PRIORITY_1);
        s.set_bytes_remaining(StreamId(2), SIZE, PRIORITY_2);
        s.set_bytes_remaining(StreamId(3), SIZE, PRIORITY_3);

        // t=20
        assert_eq!(produce(&mut s, MTU), Some((StreamId(3), SIZE)));
        s.set_bytes_remaining(StreamId(3), SIZE, PRIORITY_3);
        // t=40
        assert_eq!(produce(&mut s, MTU), Some((StreamId(3), SIZE)));
        s.set_bytes_remaining(StreamId(3), SIZE, PRIORITY_3);
        // t=50
        assert_eq!(produce(&mut s, MTU), Some((StreamId(2), SIZE)));
        s.set_bytes_remaining(StreamId(2), SIZE, PRIORITY_2);
        // t=60
        assert_eq!(produce(&mut s, MTU), Some((StreamId(3), SIZE)));
        // No more on SID=3
        // t=80
        assert_eq!(produce(&mut s, MTU), Some((StreamId(1), SIZE)));
        s.set_bytes_remaining(StreamId(1), SIZE, PRIORITY_1);
        // t=100
        assert_eq!(produce(&mut s, MTU), Some((StreamId(2), SIZE)));
        s.set_bytes_remaining(StreamId(2), SIZE, PRIORITY_2);
        // t=150
        assert_eq!(produce(&mut s, MTU), Some((StreamId(2), SIZE)));
        // No more on SID=2
        // t=160
        assert_eq!(produce(&mut s, MTU), Some((StreamId(1), SIZE)));
        s.set_bytes_remaining(StreamId(1), SIZE, PRIORITY_1);
        // t=240
        assert_eq!(produce(&mut s, MTU), Some((StreamId(1), SIZE)));
        // No more on SID=1

        assert_eq!(produce(&mut s, MTU), None);
    }

    #[test]
    fn will_do_weighted_fair_queuing_different_size_and_priority() {
        // Will do weighted fair queuing with three streams having different priority and sending
        // different payload sizes.
        let mut s = StreamScheduler::new(MTU);
        // Priority 125 -> allowed to produce every 1000/125 ~= 80 time units.
        const PRIORITY_1: Option<u16> = Some(125);
        // Priority 200 -> allowed to produce every 1000/200 ~= 50 time units.
        const PRIORITY_2: Option<u16> = Some(200);
        // Priority 500 -> allowed to produce every 1000/500 ~= 20 time units.
        const PRIORITY_3: Option<u16> = Some(500);

        // Expire at 50*80=4000 vs 50*50=2500 vs 20*20=400
        s.set_bytes_remaining(StreamId(1), 50, PRIORITY_1);
        s.set_bytes_remaining(StreamId(2), 50, PRIORITY_2);
        s.set_bytes_remaining(StreamId(3), 20, PRIORITY_3);

        // t=400
        assert_eq!(produce(&mut s, MTU), Some((StreamId(3), 20)));
        // Expires at t=400+50*20=1400
        s.set_bytes_remaining(StreamId(3), 50, PRIORITY_3);
        // t=1400
        assert_eq!(produce(&mut s, MTU), Some((StreamId(3), 50)));
        // Expires at t=1400+70*20=2800
        s.set_bytes_remaining(StreamId(3), 70, PRIORITY_3);
        // t=2500
        assert_eq!(produce(&mut s, MTU), Some((StreamId(2), 50)));
        // Expires at t=2500+70*50=6000
        s.set_bytes_remaining(StreamId(2), 70, PRIORITY_2);
        // t=2800
        assert_eq!(produce(&mut s, MTU), Some((StreamId(3), 70)));
        // No more on SID=3
        // t=4000
        assert_eq!(produce(&mut s, MTU), Some((StreamId(1), 50)));
        // Expires at t=4000+20*80=5600
        s.set_bytes_remaining(StreamId(1), 20, PRIORITY_1);
        // t=5600
        assert_eq!(produce(&mut s, MTU), Some((StreamId(1), 20)));
        // Expires at t=5600+70*80=11200
        s.set_bytes_remaining(StreamId(1), 70, PRIORITY_1);
        // t=6000
        assert_eq!(produce(&mut s, MTU), Some((StreamId(2), 70)));
        // Expires at t=6000+20*50=7000
        s.set_bytes_remaining(StreamId(2), 20, PRIORITY_2);
        // t=7000
        assert_eq!(produce(&mut s, MTU), Some((StreamId(2), 20)));
        // No more on SID=2
        // t=11200
        assert_eq!(produce(&mut s, MTU), Some((StreamId(1), 70)));
        // No more on SID=1

        assert_eq!(produce(&mut s, MTU), None);
    }

    #[test]
    fn will_distribute_wfq_packets_in_two_streams_by_priority() {
        // A simple test with two streams of different priority, but sending packets of identical
        // size. Verifies that the ratio of sent packets represent their priority.
        let mut s = StreamScheduler::new(MTU);

        let counts = send_packets(
            &mut s,
            &[TestStreamConfig::new(Some(100), 10), TestStreamConfig::new(Some(200), 10)],
            15,
        );
        assert_eq!(counts, &[5, 10])
    }

    #[test]
    fn will_distribute_wfq_packets_in_four_streams_by_priority() {
        // Same as `will_distribute_wfq_packets_in_two_streams_by_priority` but with more streams.
        let mut s = StreamScheduler::new(MTU);

        let counts = send_packets(
            &mut s,
            &[
                TestStreamConfig::new(Some(100), 10),
                TestStreamConfig::new(Some(200), 10),
                TestStreamConfig::new(Some(300), 10),
                TestStreamConfig::new(Some(400), 10),
            ],
            50,
        );
        assert_eq!(counts, &[5, 10, 15, 20])
    }

    #[test]
    fn will_distribute_from_two_streams_fairly() {
        // A simple test with two streams of different priority, but sending packets of different
        // size. Verifies that the ratio of total packet payload represent their priority. In this
        // example
        //
        // * stream1 has priority 100 and sends packets of size 8, and
        // * stream2 has priority 400 and sends packets of size 4.
        //
        // With round robin, stream1 would get twice as many payload bytes on the wire as stream2,
        // but with WFQ and a 4x priority increase, stream2 should 4x as many payload bytes on the
        // wire. That translates to stream2 getting 8x as many packets on the wire as they are half
        // as large.
        let mut s = StreamScheduler::new(MTU);

        let counts = send_packets(
            &mut s,
            &[TestStreamConfig::new(Some(100), 8), TestStreamConfig::new(Some(400), 4)],
            90,
        );
        assert_eq!(counts, &[10, 80])
    }

    #[test]
    fn will_distribute_from_four_streams_fairly() {
        // Same as `will_distribute_from_four_streams_fairly` but more complicated.
        let mut s = StreamScheduler::new(MTU);

        let counts = send_packets(
            &mut s,
            &[
                TestStreamConfig::new(Some(100), 10),
                TestStreamConfig::new(Some(200), 10),
                TestStreamConfig::new(Some(200), 20),
                TestStreamConfig::new(Some(400), 30),
            ],
            80,
        );

        // 15 packets * 10 bytes = 150 bytes at priority 100.
        // 30 packets * 10 bytes = 300 bytes at priority 200.
        // 15 packets * 20 bytes = 300 bytes at priority 200.
        // 20 packets * 30 bytes = 600 bytes at priority 400.
        assert_eq!(counts, &[15, 30, 15, 20])
    }

    #[test]
    fn send_large_message_with_small_mtu() {
        // Sending large messages with small MTU will fragment the messages and produce a first
        // fragment not larger than the MTU, and will then not first send from the stream with the
        // smallest message, as their first fragment will be equally small for both streams. See
        // `test_send_large_message_with_large_mtu` for the same test, but with a larger MTU.
        let mut s = StreamScheduler::new(/* max_payload_bytes */ 100);

        s.set_bytes_remaining(StreamId(1), 100, Some(1));
        s.set_bytes_remaining(StreamId(2), 100, Some(1));

        // t=100
        assert_eq!(produce(&mut s, MTU), Some((StreamId(1), 100)));
        s.set_bytes_remaining(StreamId(1), 100, Some(1));
        // t=100
        assert_eq!(produce(&mut s, MTU), Some((StreamId(2), 100)));
        s.set_bytes_remaining(StreamId(2), 50, Some(1));
        // t=150
        assert_eq!(produce(&mut s, MTU), Some((StreamId(2), 50)));
        // No more on SID=2
        // t=200
        assert_eq!(produce(&mut s, MTU), Some((StreamId(1), 100)));
        // No more on SID=1

        assert_eq!(produce(&mut s, MTU), None);
    }

    #[test]
    fn send_large_message_with_large_mtu() {
        // Sending large messages with large MTU will not fragment messages and will send the
        // message first from the stream that has the smallest message.
        let mut s = StreamScheduler::new(/* max_payload_bytes */ 200);

        s.set_bytes_remaining(StreamId(1), 200, Some(1));
        s.set_bytes_remaining(StreamId(2), 150, Some(1));

        // t=150
        assert_eq!(produce(&mut s, MTU), Some((StreamId(2), 150)));
        // No more on SID=2
        // t=200
        assert_eq!(produce(&mut s, MTU), Some((StreamId(1), 200)));
        // No more on SID=1

        assert_eq!(produce(&mut s, MTU), None);
    }
}
