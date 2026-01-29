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

use crate::api::Options;
use crate::api::SocketTime;
use crate::api::handover::HandoverReadiness;
use crate::api::handover::SocketHandoverState;
use crate::packet::sack_chunk::GapAckBlock;
use crate::packet::sack_chunk::SackChunk;
use crate::timer::Timer;
use crate::types::Tsn;
use std::cmp::min;
use std::ops::Range;
use std::time::Duration;

/// The maximum number of accepted in-flight DATA chunks. This indicates the maximum difference from
/// this buffer's last cumulative ack TSN, and any received data. Data received beyond this limit
/// will be dropped, which will force the transmitter to send data that actually increases the last
/// cumulative acked TSN.
const MAX_ACCEPTED_OUTSTANDING_FRAGMENTS: u32 = 100000;

/// The maximum number of duplicate TSNs that will be reported in a SACK.
const MAX_DUPLICATE_TSN_REPORTED: usize = 20;

/// The maximum number of gap-ack-blocks that will be reported in a SACK.
const MAX_GAP_ACK_BLOCKS_REPORTED: usize = 20;

#[derive(Debug, PartialEq)]
enum AckState {
    /// No need to send an ACK.
    Idle,

    /// Has received data chunks (but not yet end of packet).
    BecomingDelayed,

    /// Has received data chunks and the end of a packet. Delayed ack timer is running and a SACK
    /// will be sent on expiry, or if DATA is sent, or after next packet with data.
    Delayed,

    /// Send a SACK immediately after handling this packet.
    Immediate,
}

/// Keeps track of received DATA chunks and handles all logic for _when_ to create SACKs and also
/// _how_ to generate them.
///
/// It only uses TSNs to track delivery and doesn't need to be aware of streams.
///
/// SACKs are optimally sent every second packet on connections with no packet loss. When packet
/// loss is detected, it's sent for every packet. When SACKs are not sent directly, a timer is used
/// to send a SACK delayed (by RTO/2, or 200 ms, whatever is smallest).
pub struct DataTracker {
    seen_packet: bool,
    ack_state: AckState,

    /// All TSNs up until (and including) this value have been seen.
    last_cumulative_acked_tsn: Tsn,

    /// Received TSNs that are not directly following `last_cumulative_acked_tsn`. Note that these
    /// are open ranges, with the `end` value not being included.
    additional_tsn_blocks: Vec<Range<Tsn>>,

    duplicates: Vec<Tsn>,
    delayed_ack_timer: Timer,
    delayed_ack_max_timeout: Duration,
}

impl DataTracker {
    pub fn new(peer_initial_tsn: Tsn, options: &Options) -> DataTracker {
        DataTracker {
            seen_packet: false,
            ack_state: AckState::Idle,
            last_cumulative_acked_tsn: peer_initial_tsn - 1,
            additional_tsn_blocks: vec![],
            duplicates: vec![],
            delayed_ack_timer: Timer::new(
                options.delayed_ack_max_timeout,
                crate::timer::BackoffAlgorithm::Exponential,
                Some(0),
                None,
            ),
            delayed_ack_max_timeout: options.delayed_ack_max_timeout,
        }
    }

    pub fn update_rto(&mut self, rto: Duration) {
        let delayed_ack_tmo = min(rto / 2, self.delayed_ack_max_timeout);
        self.delayed_ack_timer.set_duration(delayed_ack_tmo);
    }

    pub fn next_timeout(&self) -> Option<SocketTime> {
        self.delayed_ack_timer.next_expiry()
    }

    /// Returns the last cumulative ack TSN - the last seen data chunk's TSN value before any packet
    /// loss was detected.
    pub fn last_cumulative_acked_tsn(&self) -> Tsn {
        self.last_cumulative_acked_tsn
    }

    pub fn is_tsn_valid(&self, tsn: Tsn) -> bool {
        // Note that this method doesn't return `false` for old DATA chunks, as those are actually
        // valid, and receiving those may affect the generated SACK response (by setting "duplicate
        // TSNs").

        let difference = tsn.distance_to(self.last_cumulative_acked_tsn);
        difference <= MAX_ACCEPTED_OUTSTANDING_FRAGMENTS
    }

    fn maybe_add_duplicate_tsn(&mut self, tsn: Tsn) {
        if self.duplicates.len() < MAX_DUPLICATE_TSN_REPORTED {
            self.duplicates.push(tsn);
        }
    }

    fn add_additional_tsn(&mut self, tsn: Tsn) -> bool {
        let idx = self.additional_tsn_blocks.partition_point(|r| r.start <= tsn);

        // Check if it's a duplicate in the block before insertion point.
        if idx > 0 && self.additional_tsn_blocks[idx - 1].contains(&tsn) {
            return false;
        }

        let extend_prev = idx > 0 && self.additional_tsn_blocks[idx - 1].end == tsn;
        let extend_next = idx < self.additional_tsn_blocks.len()
            && self.additional_tsn_blocks[idx].start == tsn + 1;

        match (extend_prev, extend_next) {
            (true, true) => {
                // Merge with previous and next block.
                let next_end = self.additional_tsn_blocks[idx].end;
                self.additional_tsn_blocks[idx - 1].end = next_end;
                self.additional_tsn_blocks.remove(idx);
            }
            (true, false) => {
                // Extend previous block.
                self.additional_tsn_blocks[idx - 1].end = tsn + 1;
            }
            (false, true) => {
                // Extend next block.
                self.additional_tsn_blocks[idx].start = tsn;
            }
            (false, false) => {
                // Insert new block.
                self.additional_tsn_blocks.insert(idx, tsn..tsn + 1);
            }
        }
        true
    }

    /// Call for every incoming data chunk. Returns `true` if `tsn` was seen for the first time, and
    /// `false` if it has been seen before (a duplicate `tsn`).
    pub fn observe(&mut self, now: SocketTime, tsn: Tsn, immediate_ack: bool) -> bool {
        let mut is_duplicate = false;

        // is_tsn_valid must be called prior to calling this method.
        debug_assert!(self.is_tsn_valid(tsn));

        // Old chunk already seen before?
        if tsn <= self.last_cumulative_acked_tsn {
            self.maybe_add_duplicate_tsn(tsn);
            is_duplicate = true;
        } else if tsn == self.last_cumulative_acked_tsn + 1 {
            self.last_cumulative_acked_tsn = tsn;
            // The cumulative acked tsn may be moved even further, if a gap was filled.
            if !self.additional_tsn_blocks.is_empty()
                && self.additional_tsn_blocks[0].start == self.last_cumulative_acked_tsn + 1
            {
                self.last_cumulative_acked_tsn = self.additional_tsn_blocks[0].end - 1;
                self.additional_tsn_blocks.remove(0);
            }
        } else {
            let inserted = self.add_additional_tsn(tsn);
            if !inserted {
                // Already seen before.
                self.maybe_add_duplicate_tsn(tsn);
                is_duplicate = true;
            }
        }

        // From <https://datatracker.ietf.org/doc/html/rfc9260#section-6.2>:
        //
        //   When a packet arrives with duplicate DATA chunk(s) and with no new DATA chunk(s), the
        //   endpoint MUST immediately send a SACK with no delay. If a packet arrives with duplicate
        //   DATA chunk(s) bundled with new DATA chunks, the endpoint MAY immediately send a SACK.
        if is_duplicate {
            self.update_ack_state(now, AckState::Immediate);
        }

        // From <https://datatracker.ietf.org/doc/html/rfc9260#section-6.7>:
        //
        //   Upon the reception of a new DATA chunk, an endpoint shall examine the continuity of the
        //   TSNs received. If the endpoint detects a gap in the received DATA chunk sequence, it
        //   SHOULD send a SACK with Gap Ack Blocks immediately. The data receiver continues sending
        //   a SACK after receipt of each SCTP packet that doesn't fill the gap.
        if !self.additional_tsn_blocks.is_empty() {
            self.update_ack_state(now, AckState::Immediate);
        }

        // From <https://datatracker.ietf.org/doc/html/rfc9260#section-6.2-9>:
        //
        //   Upon receipt of an SCTP packet containing a DATA chunk with the I bit set, the receiver
        //   SHOULD NOT delay the sending of the corresponding SACK chunk, i.e., the receiver SHOULD
        //   immediately respond with the corresponding SACK chunk.
        if immediate_ack {
            self.update_ack_state(now, AckState::Immediate);
        }

        if !self.seen_packet {
            // From <https://datatracker.ietf.org/doc/html/rfc9260#section-5.1-8>:
            //
            //   After the reception of the first DATA chunk in an association, the endpoint MUST
            //   immediately respond with a SACK chunk to acknowledge the DATA chunk.
            self.seen_packet = true;
            self.update_ack_state(now, AckState::Immediate);
        }

        // From <https://datatracker.ietf.org/doc/html/rfc9260#section-6.2-3>:
        //
        //   Specifically, an acknowledgement SHOULD be generated for at least every second packet
        //   (not every second DATA chunk) received and SHOULD be generated within 200 ms of the
        //   arrival of any unacknowledged DATA chunk."
        match &self.ack_state {
            AckState::Idle => self.update_ack_state(now, AckState::BecomingDelayed),
            AckState::Delayed => self.update_ack_state(now, AckState::Immediate),
            _ => {}
        }
        !is_duplicate
    }

    /// Called for incoming FORWARD-TSN/I-FORWARD-TSN chunks. Indicates if the chunk had any effect.
    pub fn handle_forward_tsn(&mut self, now: SocketTime, new_cumulative_tsn: Tsn) -> bool {
        // ForwardTSN is sent to make the receiver (this socket) "forget" about partly received (or
        // not received at all) data, up until `new_cumulative_ack`.

        // Old chunk already seen before?
        if new_cumulative_tsn <= self.last_cumulative_acked_tsn {
            // From <https://datatracker.ietf.org/doc/html/rfc3758#section-3.6>:
            //
            //   Note, if the "New Cumulative TSN" value carried in the arrived FORWARD TSN chunk is
            //   found to be behind or at the current cumulative TSN point, the data receiver MUST
            //   treat this FORWARD TSN as out-of-date and MUST NOT update its Cumulative TSN. The
            //   receiver SHOULD send a SACK to its peer (the sender of the FORWARD TSN) since such
            //   a duplicate may indicate the previous SACK was lost in the network."
            self.update_ack_state(now, AckState::Immediate);
            return false;
        }

        // From <https://datatracker.ietf.org/doc/html/rfc3758#section-3.6>:
        //
        //   When a FORWARD TSN chunk arrives, the data receiver MUST first update its cumulative
        //   TSN point to the value carried in the FORWARD TSN chunk, and then MUST further advance
        //   its cumulative TSN point locally if possible, as shown by the following example [...]
        //
        // If there have been prior gaps that are now overlapping with the new value, remove them.
        self.last_cumulative_acked_tsn = new_cumulative_tsn;
        self.additional_tsn_blocks.retain_mut(|b| {
            if b.end <= new_cumulative_tsn {
                false
            } else {
                if b.start <= new_cumulative_tsn {
                    b.start = new_cumulative_tsn + 1;
                }
                true
            }
        });

        // See if the `last_cumulative_acked_tsn` can be moved even further.
        if !self.additional_tsn_blocks.is_empty()
            && self.additional_tsn_blocks[0].start == new_cumulative_tsn + 1
        {
            self.last_cumulative_acked_tsn = self.additional_tsn_blocks[0].end - 1;
            self.additional_tsn_blocks.remove(0);
        }

        // From <https://datatracker.ietf.org/doc/html/rfc3758#section-3.6>:
        //
        //   Any time a FORWARD TSN chunk arrives, for the purposes of sending a SACK, the receiver
        //   MUST follow the same rules as if a DATA chunk had been received (i.e., follow the
        //   delayed sack rules specified in [...]
        if self.ack_state == AckState::Idle {
            self.update_ack_state(now, AckState::BecomingDelayed);
        } else if self.ack_state == AckState::Delayed {
            self.update_ack_state(now, AckState::Immediate);
        }
        true
    }

    /// Creates a selective ack and returns it. Note that this will modify state, so the chunk must
    /// be sent.
    pub fn create_selective_ack(&mut self, a_rwnd: u32) -> SackChunk {
        // Note that in SCTP, the receiver side is allowed to discard received data and signal that
        // to the sender, but only chunks that have previously been reported in the gap-ack-blocks.
        // However, this implementation will never do that. So this SACK produced is more like a
        // NR-SACK, as explained in <https://ieeexplore.ieee.org/document/4697037>, for which there
        // is an RFC draft at
        // <https://datatracker.ietf.org/doc/html/draft-tuexen-tsvwg-sctp-multipath>.
        let cumulative_tsn_ack = self.last_cumulative_acked_tsn;

        let gap_ack_blocks: Vec<GapAckBlock> = self
            .additional_tsn_blocks
            .iter()
            .take(MAX_GAP_ACK_BLOCKS_REPORTED)
            .filter_map(|b| {
                let start = u16::try_from(b.start.distance_to(cumulative_tsn_ack)).ok()?;
                let end = u16::try_from(b.end.distance_to(cumulative_tsn_ack) - 1).ok()?;
                Some(GapAckBlock { start, end })
            })
            .collect();

        SackChunk {
            cumulative_tsn_ack,
            a_rwnd,
            gap_ack_blocks,
            duplicate_tsns: std::mem::take(&mut self.duplicates),
        }
    }

    /// Indicates if a SACK should be sent. There may be many reasons to send a SACK, and if this
    /// function indicates so, it should be sent as soon as possible. Calling this function will
    /// make it clear a flag so that if it's called again, it will probably return false.
    ///
    /// If the delayed ack timer is running, this method will return false _unless_
    /// `also_if_delayed` is set to true. Then it will return true as well.
    pub fn should_send_ack(&mut self, now: SocketTime, also_if_delayed: bool) -> bool {
        if self.ack_state == AckState::Immediate
            || (also_if_delayed
                && (self.ack_state == AckState::BecomingDelayed
                    || self.ack_state == AckState::Delayed))
        {
            self.update_ack_state(now, AckState::Idle);
            return true;
        }

        false
    }

    pub fn will_increase_cum_ack_tsn(&self, tsn: Tsn) -> bool {
        tsn == self.last_cumulative_acked_tsn + 1
    }

    pub fn force_immediate_sack(&mut self, now: SocketTime) {
        self.update_ack_state(now, AckState::Immediate);
    }

    pub fn handle_timeout(&mut self, now: SocketTime) {
        if self.delayed_ack_timer.expire(now) {
            self.update_ack_state(now, AckState::Immediate);
        }
    }

    /// Called at the end of processing an SCTP packet.
    pub fn observe_packet_end(&mut self, now: SocketTime) {
        if self.ack_state == AckState::BecomingDelayed {
            self.update_ack_state(now, AckState::Delayed);
        }
    }

    fn update_ack_state(&mut self, now: SocketTime, new_state: AckState) {
        if self.ack_state != new_state {
            if self.ack_state == AckState::Delayed {
                self.delayed_ack_timer.stop();
            } else if new_state == AckState::Delayed {
                self.delayed_ack_timer.start(now);
            }
            self.ack_state = new_state;
        }
    }

    pub(crate) fn get_handover_readiness(&self) -> HandoverReadiness {
        HandoverReadiness::DATA_TRACKER_TSN_BLOCKS_PENDING & !self.additional_tsn_blocks.is_empty()
    }

    pub(crate) fn add_to_handover_state(&self, state: &mut SocketHandoverState) {
        state.rx.last_cumulative_acked_tsn = self.last_cumulative_acked_tsn.0;
        state.rx.seen_packet = self.seen_packet;
    }

    pub(crate) fn restore_from_state(&mut self, state: &SocketHandoverState) {
        debug_assert!(self.additional_tsn_blocks.is_empty());
        debug_assert!(self.duplicates.is_empty());
        debug_assert!(!self.seen_packet);

        self.last_cumulative_acked_tsn = Tsn(state.rx.last_cumulative_acked_tsn);
        self.seen_packet = state.rx.seen_packet;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const INITIAL_TSN: Tsn = Tsn(11);
    const A_RWND: u32 = 10000;
    const START_TIME: SocketTime = SocketTime::zero();

    fn observe(d: &mut DataTracker, now: SocketTime, tsns: &[u32]) {
        for tsn in tsns {
            d.observe(now, Tsn(*tsn), /* immediate_ack */ false);
        }
    }

    fn expect_gaps(d: &SackChunk, offsets: &[u16]) {
        assert!(offsets.len().is_multiple_of(2));
        let count = offsets.len() / 2;
        assert!(d.gap_ack_blocks.len() == count);
        let mut idx = 0;
        while idx < count {
            assert!(d.gap_ack_blocks[idx].start == offsets[idx * 2]);
            assert!(d.gap_ack_blocks[idx].end == offsets[idx * 2 + 1]);
            idx += 1;
        }
    }

    fn handover_data_tracker(d: DataTracker) -> DataTracker {
        let mut d2 = DataTracker::new(INITIAL_TSN, &Options::default());
        let mut state = SocketHandoverState::default();
        d.add_to_handover_state(&mut state);
        d2.restore_from_state(&state);
        d2
    }

    #[test]
    fn empty() {
        let mut d = DataTracker::new(INITIAL_TSN, &Options::default());
        let sack = d.create_selective_ack(A_RWND);
        assert_eq!(sack.cumulative_tsn_ack, Tsn(10));
        assert!(sack.gap_ack_blocks.is_empty());
        assert!(sack.duplicate_tsns.is_empty());
    }

    #[test]
    fn observer_single_in_order_packet() {
        let now = START_TIME;
        let mut d = DataTracker::new(INITIAL_TSN, &Options::default());
        d.observe(now, Tsn(11), false);
        let sack = d.create_selective_ack(A_RWND);
        assert_eq!(sack.cumulative_tsn_ack, Tsn(11));
        assert!(sack.gap_ack_blocks.is_empty());
        assert!(sack.duplicate_tsns.is_empty());
    }

    #[test]
    fn observer_many_in_order_moves_cumulative_tsn_ack() {
        let now = START_TIME;
        let mut d = DataTracker::new(INITIAL_TSN, &Options::default());
        observe(&mut d, now, &[11, 12, 13]);
        let sack = d.create_selective_ack(A_RWND);
        assert_eq!(sack.cumulative_tsn_ack, Tsn(13));
        assert!(sack.gap_ack_blocks.is_empty());
        assert!(sack.duplicate_tsns.is_empty());
    }

    #[test]
    fn observe_out_of_order_moves_cumulative_tsn_ack() {
        let now = START_TIME;
        let mut d = DataTracker::new(INITIAL_TSN, &Options::default());
        observe(&mut d, now, &[12, 13, 14, 11]);
        let sack = d.create_selective_ack(A_RWND);
        assert_eq!(sack.cumulative_tsn_ack, Tsn(14));
        assert!(sack.gap_ack_blocks.is_empty());
        assert!(sack.duplicate_tsns.is_empty());
    }

    #[test]
    fn single_gap() {
        let now = START_TIME;
        let mut d = DataTracker::new(INITIAL_TSN, &Options::default());
        d.observe(now, Tsn(12), false);
        let sack = d.create_selective_ack(A_RWND);
        assert_eq!(sack.cumulative_tsn_ack, Tsn(10));
        assert_eq!(sack.gap_ack_blocks.len(), 1);
        assert_eq!(sack.gap_ack_blocks[0].start, 2);
        assert_eq!(sack.gap_ack_blocks[0].end, 2);
        assert!(sack.duplicate_tsns.is_empty());
    }

    #[test]
    fn example_from_rfc9260_section334() {
        let now = START_TIME;
        let mut d = DataTracker::new(INITIAL_TSN, &Options::default());
        observe(&mut d, now, &[11, 12, 14, 15, 17]);
        let sack = d.create_selective_ack(A_RWND);
        assert_eq!(sack.cumulative_tsn_ack, Tsn(12));
        expect_gaps(&sack, &[2, 3, 5, 5]);
        assert!(sack.duplicate_tsns.is_empty());
    }

    #[test]
    fn ack_already_received_chunk() {
        let now = START_TIME;
        let mut d = DataTracker::new(INITIAL_TSN, &Options::default());
        d.observe(now, Tsn(11), false);
        let sack = d.create_selective_ack(A_RWND);
        assert_eq!(sack.cumulative_tsn_ack, Tsn(11));
        assert!(sack.gap_ack_blocks.is_empty());

        d.observe(now, Tsn(8), false);
        let sack = d.create_selective_ack(A_RWND);
        assert_eq!(sack.cumulative_tsn_ack, Tsn(11));
        assert!(sack.gap_ack_blocks.is_empty());
    }

    #[test]
    fn double_send_retransmitted_chunk() {
        let now = START_TIME;
        let mut d = DataTracker::new(INITIAL_TSN, &Options::default());
        observe(&mut d, now, &[11, 13, 14, 15]);
        let sack = d.create_selective_ack(A_RWND);
        assert_eq!(sack.cumulative_tsn_ack, Tsn(11));
        assert_eq!(sack.gap_ack_blocks.len(), 1);
        assert_eq!(sack.gap_ack_blocks[0].start, 2);
        assert_eq!(sack.gap_ack_blocks[0].end, 4);

        // Fill in the hole.
        observe(&mut d, now, &[12, 16, 17, 18]);
        let sack2 = d.create_selective_ack(A_RWND);
        assert_eq!(sack2.cumulative_tsn_ack, Tsn(18));
        assert!(sack2.gap_ack_blocks.is_empty());

        // Receive chunk 12 again.
        observe(&mut d, now, &[12, 19, 20, 21]);
        let sack3 = d.create_selective_ack(A_RWND);
        assert_eq!(sack3.cumulative_tsn_ack, Tsn(21));
        assert!(sack3.gap_ack_blocks.is_empty());
    }

    #[test]
    fn forward_tsn_simple() {
        let now = START_TIME;
        let mut d = DataTracker::new(INITIAL_TSN, &Options::default());
        observe(&mut d, now, &[11, 12, 15]);
        d.handle_forward_tsn(now, Tsn(13));
        let sack = d.create_selective_ack(A_RWND);
        assert_eq!(sack.cumulative_tsn_ack, Tsn(13));
        expect_gaps(&sack, &[2, 2]);
    }

    #[test]
    fn forward_tsn_skips_from_gap_block() {
        let now = START_TIME;
        let mut d = DataTracker::new(INITIAL_TSN, &Options::default());
        observe(&mut d, now, &[11, 12, 14]);
        d.handle_forward_tsn(now, Tsn(13));
        let sack = d.create_selective_ack(A_RWND);
        assert_eq!(sack.cumulative_tsn_ack, Tsn(14));
        assert!(sack.gap_ack_blocks.is_empty());
    }

    #[test]
    fn example_from_rfc3758() {
        let now = START_TIME;
        let mut d = DataTracker::new(INITIAL_TSN, &Options::default());
        observe(&mut d, now, &[102, 104, 105, 107]);

        d.handle_forward_tsn(now, Tsn(103));
        let sack = d.create_selective_ack(A_RWND);
        assert_eq!(sack.cumulative_tsn_ack, Tsn(105));
        expect_gaps(&sack, &[2, 2]);
    }

    #[test]
    fn empty_all_acks() {
        let now = START_TIME;
        let mut d = DataTracker::new(INITIAL_TSN, &Options::default());
        observe(&mut d, now, &[11, 13, 14, 15]);

        d.handle_forward_tsn(now, Tsn(100));

        let sack = d.create_selective_ack(A_RWND);
        assert_eq!(sack.cumulative_tsn_ack, Tsn(100));
        assert!(sack.gap_ack_blocks.is_empty());
    }

    #[test]
    fn sets_arwnd_correctly() {
        let mut d = DataTracker::new(INITIAL_TSN, &Options::default());
        let sack = d.create_selective_ack(100);
        assert_eq!(sack.a_rwnd, 100);

        let sack = d.create_selective_ack(101);
        assert_eq!(sack.a_rwnd, 101);
    }

    #[test]
    fn will_increase_cum_ack_tsn() {
        let now = START_TIME;
        let mut d = DataTracker::new(INITIAL_TSN, &Options::default());
        assert_eq!(d.last_cumulative_acked_tsn(), Tsn(10));
        assert!(!d.will_increase_cum_ack_tsn(Tsn(10)));
        assert!(d.will_increase_cum_ack_tsn(Tsn(11)));
        assert!(!d.will_increase_cum_ack_tsn(Tsn(12)));

        observe(&mut d, now, &[11, 12, 13, 14, 15]);
        assert_eq!(d.last_cumulative_acked_tsn(), Tsn(15));
        assert!(!d.will_increase_cum_ack_tsn(Tsn(15)));
        assert!(d.will_increase_cum_ack_tsn(Tsn(16)));
        assert!(!d.will_increase_cum_ack_tsn(Tsn(17)));
    }

    #[test]
    fn force_should_send_sack_immediately() {
        let now = START_TIME;
        let mut d = DataTracker::new(INITIAL_TSN, &Options::default());
        assert!(!d.should_send_ack(now, false));

        d.force_immediate_sack(now);
        assert!(d.should_send_ack(now, false));
    }

    #[test]
    fn will_accept_valid_tsns() {
        let d = DataTracker::new(INITIAL_TSN, &Options::default());

        assert!(d.is_tsn_valid(INITIAL_TSN - 1 - MAX_ACCEPTED_OUTSTANDING_FRAGMENTS));
        assert!(d.is_tsn_valid(INITIAL_TSN - 1));
        assert!(d.is_tsn_valid(INITIAL_TSN - 1 + MAX_ACCEPTED_OUTSTANDING_FRAGMENTS));
    }

    #[test]
    fn will_not_accept_invalid_tsns() {
        let d = DataTracker::new(INITIAL_TSN, &Options::default());

        assert!(!d.is_tsn_valid(INITIAL_TSN - 1 - MAX_ACCEPTED_OUTSTANDING_FRAGMENTS - 1));
        assert!(!d.is_tsn_valid(INITIAL_TSN - 1 + MAX_ACCEPTED_OUTSTANDING_FRAGMENTS + 1));
    }

    #[test]
    fn report_single_duplicate_tsns() {
        let now = START_TIME;
        let mut d = DataTracker::new(INITIAL_TSN, &Options::default());
        assert!(d.observe(now, Tsn(11), false));
        assert!(d.observe(now, Tsn(12), false));
        assert!(!d.observe(now, Tsn(11), false));
        let sack = d.create_selective_ack(A_RWND);
        assert_eq!(sack.cumulative_tsn_ack, Tsn(12));
        assert!(sack.gap_ack_blocks.is_empty());
        assert!(sack.duplicate_tsns.contains(&Tsn(11)));
    }

    #[test]
    fn report_multiple_duplicate_tsns() {
        let now = START_TIME;
        let mut d = DataTracker::new(INITIAL_TSN, &Options::default());
        observe(&mut d, now, &[11, 12, 13, 14]);
        observe(&mut d, now, &[12, 13, 12, 13]);
        observe(&mut d, now, &[15, 16]);
        let sack = d.create_selective_ack(A_RWND);
        assert_eq!(sack.cumulative_tsn_ack, Tsn(16));
        assert!(sack.gap_ack_blocks.is_empty());
        assert!(sack.duplicate_tsns.contains(&Tsn(12)));
        assert!(sack.duplicate_tsns.contains(&Tsn(13)));
    }

    #[test]
    fn report_duplicate_tsns_in_gap_ack_blocks() {
        let now = START_TIME;
        let mut d = DataTracker::new(INITIAL_TSN, &Options::default());
        observe(&mut d, now, &[11, /* 12, */ 13, 14]);
        observe(&mut d, now, &[13, 14]);
        observe(&mut d, now, &[15, 16]);
        let sack = d.create_selective_ack(A_RWND);
        assert_eq!(sack.cumulative_tsn_ack, Tsn(11));
        expect_gaps(&sack, &[2, 5]);
        assert!(sack.duplicate_tsns.contains(&Tsn(13)));
        assert!(sack.duplicate_tsns.contains(&Tsn(14)));
    }

    #[test]
    fn clears_duplicate_tsns_after_creating_sack() {
        let now = START_TIME;
        let mut d = DataTracker::new(INITIAL_TSN, &Options::default());
        observe(&mut d, now, &[11, 12, 13, 14]);
        observe(&mut d, now, &[12, 13, 12, 13]);
        observe(&mut d, now, &[15, 16]);

        let sack1 = d.create_selective_ack(A_RWND);
        assert_eq!(sack1.cumulative_tsn_ack, Tsn(16));
        assert!(sack1.gap_ack_blocks.is_empty());
        assert!(sack1.duplicate_tsns.contains(&Tsn(12)));
        assert!(sack1.duplicate_tsns.contains(&Tsn(13)));

        observe(&mut d, now, &[17]);
        let sack2 = d.create_selective_ack(A_RWND);
        assert_eq!(sack2.cumulative_tsn_ack, Tsn(17));
        assert!(sack2.gap_ack_blocks.is_empty());
        assert!(sack2.duplicate_tsns.is_empty());
    }

    #[test]
    fn limits_number_of_duplicates_reported() {
        let now = START_TIME;
        let mut d = DataTracker::new(INITIAL_TSN, &Options::default());
        for i in 0..MAX_DUPLICATE_TSN_REPORTED + 10 {
            let tsn = Tsn(11 + i as u32);
            d.observe(now, tsn, false);
            d.observe(now, tsn, false);
        }

        let sack2 = d.create_selective_ack(A_RWND);
        assert_eq!(sack2.duplicate_tsns.len(), MAX_DUPLICATE_TSN_REPORTED);
        assert!(sack2.gap_ack_blocks.is_empty());
    }

    #[test]
    fn limits_number_of_gap_ack_blocks_reported() {
        let now = START_TIME;
        let mut d = DataTracker::new(INITIAL_TSN, &Options::default());
        for i in 0..MAX_GAP_ACK_BLOCKS_REPORTED + 10 {
            let tsn = Tsn(11 + (i * 2) as u32);
            d.observe(now, tsn, false);
        }

        let sack2 = d.create_selective_ack(A_RWND);
        assert_eq!(sack2.cumulative_tsn_ack, Tsn(11));
        assert_eq!(sack2.gap_ack_blocks.len(), MAX_GAP_ACK_BLOCKS_REPORTED);
    }

    #[test]
    fn sends_sack_for_first_packet_observed() {
        let now = START_TIME;
        let mut d = DataTracker::new(INITIAL_TSN, &Options::default());
        d.observe(now, Tsn(11), false);

        assert!(d.should_send_ack(now, false));
        assert!(d.next_timeout().is_none());
    }

    #[test]
    fn sends_sack_every_second_packet_when_there_is_no_packet_loss() {
        let now = START_TIME;
        let mut d = DataTracker::new(INITIAL_TSN, &Options::default());

        d.observe(now, Tsn(11), false);
        d.observe_packet_end(now);
        assert!(d.next_timeout().is_none());
        assert!(d.should_send_ack(now, false));

        d.observe(now, Tsn(12), false);
        d.observe_packet_end(now);
        assert!(d.next_timeout().is_some());
        assert!(!d.should_send_ack(now, false));

        d.observe(now, Tsn(13), false);
        d.observe_packet_end(now);
        assert!(d.next_timeout().is_none());
        assert!(d.should_send_ack(now, false));

        d.observe(now, Tsn(14), false);
        d.observe_packet_end(now);
        assert!(d.next_timeout().is_some());
        assert!(!d.should_send_ack(now, false));

        d.observe(now, Tsn(15), false);
        d.observe_packet_end(now);
        assert!(d.next_timeout().is_none());
        assert!(d.should_send_ack(now, false));
    }

    #[test]
    fn sends_sack_every_packet_on_packet_loss() {
        let now = START_TIME;
        let mut d = DataTracker::new(INITIAL_TSN, &Options::default());

        d.observe(now, Tsn(11), false);
        d.observe_packet_end(now);
        assert!(d.next_timeout().is_none());
        assert!(d.should_send_ack(now, false));

        d.observe(now, Tsn(13), false);
        d.observe_packet_end(now);
        assert!(d.next_timeout().is_none());
        assert!(d.should_send_ack(now, false));

        d.observe(now, Tsn(14), false);
        d.observe_packet_end(now);
        assert!(d.next_timeout().is_none());
        assert!(d.should_send_ack(now, false));

        d.observe(now, Tsn(15), false);
        d.observe_packet_end(now);
        assert!(d.next_timeout().is_none());
        assert!(d.should_send_ack(now, false));

        d.observe(now, Tsn(16), false);
        d.observe_packet_end(now);
        assert!(d.next_timeout().is_none());
        assert!(d.should_send_ack(now, false));

        // Fill the hole.
        d.observe(now, Tsn(12), false);
        d.observe_packet_end(now);
        assert!(d.next_timeout().is_some());
        assert!(!d.should_send_ack(now, false));

        d.observe(now, Tsn(17), false);
        d.observe_packet_end(now);
        assert!(d.next_timeout().is_none());
        assert!(d.should_send_ack(now, false));

        d.observe(now, Tsn(18), false);
        d.observe_packet_end(now);
        assert!(d.next_timeout().is_some());
        assert!(!d.should_send_ack(now, false));
    }

    #[test]
    fn sends_sack_on_duplicate_data_chunks() {
        let now = START_TIME;
        let mut d = DataTracker::new(INITIAL_TSN, &Options::default());

        d.observe(now, Tsn(11), false);
        d.observe_packet_end(now);
        assert!(d.next_timeout().is_none());
        assert!(d.should_send_ack(now, false));

        d.observe(now, Tsn(11), false);
        d.observe_packet_end(now);
        assert!(d.next_timeout().is_none());
        assert!(d.should_send_ack(now, false));

        d.observe(now, Tsn(12), false);
        d.observe_packet_end(now);
        assert!(d.next_timeout().is_some());
        assert!(!d.should_send_ack(now, false));

        // Goes back to every second packet
        d.observe(now, Tsn(13), false);
        d.observe_packet_end(now);
        assert!(d.next_timeout().is_none());
        assert!(d.should_send_ack(now, false));

        // Duplicate again
        d.observe(now, Tsn(12), false);
        d.observe_packet_end(now);
        assert!(d.next_timeout().is_none());
        assert!(d.should_send_ack(now, false));
    }

    #[test]
    fn gap_ack_block_add_single_block() {
        let now = START_TIME;
        let mut d = DataTracker::new(INITIAL_TSN, &Options::default());
        observe(&mut d, now, &[12]);
        let sack = d.create_selective_ack(A_RWND);
        assert_eq!(sack.cumulative_tsn_ack, Tsn(10));
        expect_gaps(&sack, &[2, 2]);
    }

    #[test]
    fn gap_ack_block_adds_another() {
        let now = START_TIME;
        let mut d = DataTracker::new(INITIAL_TSN, &Options::default());
        observe(&mut d, now, &[12, 14]);
        let sack = d.create_selective_ack(A_RWND);
        assert_eq!(sack.cumulative_tsn_ack, Tsn(10));
        expect_gaps(&sack, &[2, 2, 4, 4]);
    }

    #[test]
    fn gap_ack_block_adds_duplicate() {
        let now = START_TIME;
        let mut d = DataTracker::new(INITIAL_TSN, &Options::default());
        observe(&mut d, now, &[12, 12]);
        let sack = d.create_selective_ack(A_RWND);
        assert_eq!(sack.cumulative_tsn_ack, Tsn(10));
        expect_gaps(&sack, &[2, 2]);
        assert!(sack.duplicate_tsns.contains(&Tsn(12)));
    }

    #[test]
    fn gap_ack_block_expands_to_right() {
        let now = START_TIME;
        let mut d = DataTracker::new(INITIAL_TSN, &Options::default());
        observe(&mut d, now, &[12, 13]);
        let sack = d.create_selective_ack(A_RWND);
        assert_eq!(sack.cumulative_tsn_ack, Tsn(10));
        expect_gaps(&sack, &[2, 3]);
    }

    #[test]
    fn gap_ack_block_expands_to_right_with_other() {
        let now = START_TIME;
        let mut d = DataTracker::new(INITIAL_TSN, &Options::default());
        observe(&mut d, now, &[12, 20, 30, 21]);
        let sack = d.create_selective_ack(A_RWND);
        assert_eq!(sack.cumulative_tsn_ack, Tsn(10));
        expect_gaps(&sack, &[2, 2, 10, 11, 20, 20]);
    }

    #[test]
    fn gap_ack_block_expands_to_left() {
        let now = START_TIME;
        let mut d = DataTracker::new(INITIAL_TSN, &Options::default());
        observe(&mut d, now, &[13, 12]);
        let sack = d.create_selective_ack(A_RWND);
        assert_eq!(sack.cumulative_tsn_ack, Tsn(10));
        expect_gaps(&sack, &[2, 3]);
    }

    #[test]
    fn gap_ack_block_expands_to_left_with_other() {
        let now = START_TIME;
        let mut d = DataTracker::new(INITIAL_TSN, &Options::default());
        observe(&mut d, now, &[12, 21, 30, 20]);
        let sack = d.create_selective_ack(A_RWND);
        assert_eq!(sack.cumulative_tsn_ack, Tsn(10));
        expect_gaps(&sack, &[2, 2, 10, 11, 20, 20]);
    }

    #[test]
    fn gap_ack_block_expands_to_l_right_and_merges() {
        let now = START_TIME;
        let mut d = DataTracker::new(INITIAL_TSN, &Options::default());
        observe(&mut d, now, &[12, 20, 22, 30, 21]);
        let sack = d.create_selective_ack(A_RWND);
        assert_eq!(sack.cumulative_tsn_ack, Tsn(10));
        expect_gaps(&sack, &[2, 2, 10, 12, 20, 20]);
    }

    #[test]
    fn gap_ack_block_merges_many_blocks_into_one() {
        let now = START_TIME;
        let mut d = DataTracker::new(INITIAL_TSN, &Options::default());
        observe(&mut d, now, &[22]);
        expect_gaps(&d.create_selective_ack(A_RWND), &[12, 12]);
        observe(&mut d, now, &[30]);
        expect_gaps(&d.create_selective_ack(A_RWND), &[12, 12, 20, 20]);
        observe(&mut d, now, &[24]);
        expect_gaps(&d.create_selective_ack(A_RWND), &[12, 12, 14, 14, 20, 20]);
        observe(&mut d, now, &[28]);
        expect_gaps(&d.create_selective_ack(A_RWND), &[12, 12, 14, 14, 18, 18, 20, 20]);
        observe(&mut d, now, &[26]);
        expect_gaps(&d.create_selective_ack(A_RWND), &[12, 12, 14, 14, 16, 16, 18, 18, 20, 20]);
        observe(&mut d, now, &[29]);
        expect_gaps(&d.create_selective_ack(A_RWND), &[12, 12, 14, 14, 16, 16, 18, 20]);
        observe(&mut d, now, &[23]);
        expect_gaps(&d.create_selective_ack(A_RWND), &[12, 14, 16, 16, 18, 20]);
        observe(&mut d, now, &[27]);
        expect_gaps(&d.create_selective_ack(A_RWND), &[12, 14, 16, 20]);
        observe(&mut d, now, &[25]);
        expect_gaps(&d.create_selective_ack(A_RWND), &[12, 20]);
        observe(&mut d, now, &[20]);
        expect_gaps(&d.create_selective_ack(A_RWND), &[10, 10, 12, 20]);
        observe(&mut d, now, &[32]);
        expect_gaps(&d.create_selective_ack(A_RWND), &[10, 10, 12, 20, 22, 22]);
        observe(&mut d, now, &[21]);
        expect_gaps(&d.create_selective_ack(A_RWND), &[10, 20, 22, 22]);
        observe(&mut d, now, &[31]);
        expect_gaps(&d.create_selective_ack(A_RWND), &[10, 22]);
    }

    #[test]
    fn gap_ack_block_remove_before_cum_ack_tsn() {
        let now = START_TIME;
        let mut d = DataTracker::new(INITIAL_TSN, &Options::default());
        observe(&mut d, now, &[12, 13, 14, 20, 21, 22, 30, 31]);

        d.handle_forward_tsn(now, Tsn(8));
        let sack = d.create_selective_ack(A_RWND);
        assert_eq!(sack.cumulative_tsn_ack, Tsn(10));
        expect_gaps(&sack, &[2, 4, 10, 12, 20, 21]);
    }

    #[test]
    fn gap_ack_block_remove_before_first_block() {
        let now = START_TIME;
        let mut d = DataTracker::new(INITIAL_TSN, &Options::default());
        observe(&mut d, now, &[12, 13, 14, 20, 21, 22, 30, 31]);

        d.handle_forward_tsn(now, Tsn(11));
        let sack = d.create_selective_ack(A_RWND);
        assert_eq!(sack.cumulative_tsn_ack, Tsn(14));
        expect_gaps(&sack, &[6, 8, 16, 17]);
    }

    #[test]
    fn gap_ack_block_remove_at_beginning_of_first_block() {
        let now = START_TIME;
        let mut d = DataTracker::new(INITIAL_TSN, &Options::default());
        observe(&mut d, now, &[12, 13, 14, 20, 21, 22, 30, 31]);

        d.handle_forward_tsn(now, Tsn(12));
        let sack = d.create_selective_ack(A_RWND);
        assert_eq!(sack.cumulative_tsn_ack, Tsn(14));
        expect_gaps(&sack, &[6, 8, 16, 17]);
    }

    #[test]
    fn gap_ack_block_remove_at_middle_of_first_block() {
        let now = START_TIME;
        let mut d = DataTracker::new(INITIAL_TSN, &Options::default());
        observe(&mut d, now, &[12, 13, 14, 20, 21, 22, 30, 31]);

        d.handle_forward_tsn(now, Tsn(13));
        let sack = d.create_selective_ack(A_RWND);
        assert_eq!(sack.cumulative_tsn_ack, Tsn(14));
        expect_gaps(&sack, &[6, 8, 16, 17]);
    }

    #[test]
    fn gap_ack_block_remove_at_end_of_first_block() {
        let now = START_TIME;
        let mut d = DataTracker::new(INITIAL_TSN, &Options::default());
        observe(&mut d, now, &[12, 13, 14, 20, 21, 22, 30, 31]);

        d.handle_forward_tsn(now, Tsn(14));
        let sack = d.create_selective_ack(A_RWND);
        assert_eq!(sack.cumulative_tsn_ack, Tsn(14));
        expect_gaps(&sack, &[6, 8, 16, 17]);
    }

    #[test]
    fn gap_ack_block_remove_right_after_first_block() {
        let now = START_TIME;
        let mut d = DataTracker::new(INITIAL_TSN, &Options::default());
        observe(&mut d, now, &[12, 13, 14, 20, 21, 22, 30, 31]);

        d.handle_forward_tsn(now, Tsn(18));
        let sack = d.create_selective_ack(A_RWND);
        assert_eq!(sack.cumulative_tsn_ack, Tsn(18));
        expect_gaps(&sack, &[2, 4, 12, 13]);
    }

    #[test]
    fn gap_ack_block_remove_right_before_second_block() {
        let now = START_TIME;
        let mut d = DataTracker::new(INITIAL_TSN, &Options::default());
        observe(&mut d, now, &[12, 13, 14, 20, 21, 22, 30, 31]);

        d.handle_forward_tsn(now, Tsn(19));
        let sack = d.create_selective_ack(A_RWND);
        assert_eq!(sack.cumulative_tsn_ack, Tsn(22));
        expect_gaps(&sack, &[8, 9]);
    }

    #[test]
    fn gap_ack_block_remove_right_at_start_of_second_block() {
        let now = START_TIME;
        let mut d = DataTracker::new(INITIAL_TSN, &Options::default());
        observe(&mut d, now, &[12, 13, 14, 20, 21, 22, 30, 31]);

        d.handle_forward_tsn(now, Tsn(20));
        let sack = d.create_selective_ack(A_RWND);
        assert_eq!(sack.cumulative_tsn_ack, Tsn(22));
        expect_gaps(&sack, &[8, 9]);
    }

    #[test]
    fn gap_ack_block_remove_right_at_middle_of_second_block() {
        let now = START_TIME;
        let mut d = DataTracker::new(INITIAL_TSN, &Options::default());
        observe(&mut d, now, &[12, 13, 14, 20, 21, 22, 30, 31]);

        d.handle_forward_tsn(now, Tsn(21));
        let sack = d.create_selective_ack(A_RWND);
        assert_eq!(sack.cumulative_tsn_ack, Tsn(22));
        expect_gaps(&sack, &[8, 9]);
    }

    #[test]
    fn gap_ack_block_remove_right_at_end_of_second_block() {
        let now = START_TIME;
        let mut d = DataTracker::new(INITIAL_TSN, &Options::default());
        observe(&mut d, now, &[12, 13, 14, 20, 21, 22, 30, 31]);

        d.handle_forward_tsn(now, Tsn(22));
        let sack = d.create_selective_ack(A_RWND);
        assert_eq!(sack.cumulative_tsn_ack, Tsn(22));
        expect_gaps(&sack, &[8, 9]);
    }

    #[test]
    fn gap_ack_block_remove_far_after_all_blocks() {
        let now = START_TIME;
        let mut d = DataTracker::new(INITIAL_TSN, &Options::default());
        observe(&mut d, now, &[12, 13, 14, 20, 21, 22, 30, 31]);

        d.handle_forward_tsn(now, Tsn(40));
        let sack = d.create_selective_ack(A_RWND);
        assert_eq!(sack.cumulative_tsn_ack, Tsn(40));
        assert!(sack.gap_ack_blocks.is_empty());
    }

    #[test]
    fn handover_empty() {
        let now = START_TIME;
        let d = DataTracker::new(INITIAL_TSN, &Options::default());
        let mut d2 = handover_data_tracker(d);

        observe(&mut d2, now, &[11]);
        let sack = d2.create_selective_ack(A_RWND);
        assert_eq!(sack.cumulative_tsn_ack, Tsn(11));
        assert!(sack.gap_ack_blocks.is_empty());
    }

    #[test]
    fn handover_while_sending_sack_every_second_packet_when_there_is_no_packet_loss() {
        let now = START_TIME;
        let mut d = DataTracker::new(INITIAL_TSN, &Options::default());

        observe(&mut d, now, &[11]);
        d.observe_packet_end(now);
        assert!(d.should_send_ack(now, false));

        let mut d2 = handover_data_tracker(d);

        observe(&mut d2, now, &[12]);
        d2.observe_packet_end(now);
        assert!(!d2.should_send_ack(now, false));

        observe(&mut d2, now, &[13]);
        d2.observe_packet_end(now);
        assert!(d2.should_send_ack(now, false));

        observe(&mut d2, now, &[14]);
        d2.observe_packet_end(now);
        assert!(!d2.should_send_ack(now, false));

        observe(&mut d2, now, &[15]);
        d2.observe_packet_end(now);
        assert!(d2.should_send_ack(now, false));
    }

    #[test]
    fn handover_while_sending_sack_every_packet_on_packet_loss() {
        let now = START_TIME;
        let mut d = DataTracker::new(INITIAL_TSN, &Options::default());

        observe(&mut d, now, &[11]);
        d.observe_packet_end(now);

        observe(&mut d, now, &[13]);
        d.observe_packet_end(now);
        assert_eq!(d.get_handover_readiness(), HandoverReadiness::DATA_TRACKER_TSN_BLOCKS_PENDING);

        observe(&mut d, now, &[14, 15, 16]);
        d.observe_packet_end(now);
        assert_eq!(d.get_handover_readiness(), HandoverReadiness::DATA_TRACKER_TSN_BLOCKS_PENDING);

        // Fill the hole.
        observe(&mut d, now, &[12]);
        d.observe_packet_end(now);
        assert!(d.get_handover_readiness().is_ready());

        observe(&mut d, now, &[17]);
        d.observe_packet_end(now);
        assert!(d.get_handover_readiness().is_ready());
    }

    #[test]
    fn does_not_accept_data_before_forward_tsn() {
        let now = START_TIME;
        let mut d = DataTracker::new(INITIAL_TSN, &Options::default());
        observe(&mut d, now, &[12, 13, 14, 15, 17]);
        d.observe_packet_end(now);

        d.handle_forward_tsn(now, Tsn(13));

        assert!(!d.observe(now, Tsn(11), false));
    }

    #[test]
    fn does_not_accept_data_at_forward_tsn() {
        let now = START_TIME;
        let mut d = DataTracker::new(INITIAL_TSN, &Options::default());
        observe(&mut d, now, &[12, 13, 14, 15, 17]);
        d.observe_packet_end(now);

        d.handle_forward_tsn(now, Tsn(16));

        assert!(!d.observe(now, Tsn(16), false));
    }

    #[test]
    fn does_not_accept_data_before_cum_ack_tsn() {
        let now = START_TIME;
        let mut d = DataTracker::new(INITIAL_TSN, &Options::default());

        assert!(!d.observe(now, Tsn(10), false));
    }

    #[test]
    fn does_not_accept_contiguous_duplicate_data() {
        let now = START_TIME;
        let mut d = DataTracker::new(INITIAL_TSN, &Options::default());
        assert!(d.observe(now, Tsn(11), false));
        assert!(!d.observe(now, Tsn(11), false));
        assert!(d.observe(now, Tsn(12), false));
        assert!(!d.observe(now, Tsn(12), false));
        assert!(!d.observe(now, Tsn(11), false));
        assert!(!d.observe(now, Tsn(10), false));
    }

    #[test]
    fn does_not_accept_gaps_with_duplicate_data() {
        let now = START_TIME;
        let mut d = DataTracker::new(INITIAL_TSN, &Options::default());
        assert!(d.observe(now, Tsn(11), false));
        assert!(!d.observe(now, Tsn(11), false));

        assert!(d.observe(now, Tsn(14), false));
        assert!(!d.observe(now, Tsn(14), false));

        assert!(d.observe(now, Tsn(13), false));
        assert!(!d.observe(now, Tsn(13), false));

        assert!(d.observe(now, Tsn(12), false));
        assert!(!d.observe(now, Tsn(12), false));
    }

    #[test]
    fn not_ready_for_handover_when_having_tsn_gaps() {
        let now = START_TIME;
        let mut d = DataTracker::new(INITIAL_TSN, &Options::default());

        observe(&mut d, now, &[10, 12]);
        assert_eq!(d.get_handover_readiness(), HandoverReadiness::DATA_TRACKER_TSN_BLOCKS_PENDING);

        observe(&mut d, now, &[11]);
        assert!(d.get_handover_readiness().is_ready());
    }

    #[test]
    fn observe_out_of_order_and_fill_gap_moves_cumulative_tsn_ack() {
        let now = START_TIME;
        let mut d = DataTracker::new(INITIAL_TSN, &Options::default());

        // Receive 12, 14, 15. Then 11 (which advances cum_ack), then 13 (which fills the gap).
        observe(&mut d, now, &[12, 14, 15, 11, 13]);

        let sack = d.create_selective_ack(A_RWND);
        assert_eq!(sack.cumulative_tsn_ack, Tsn(15));
        assert!(sack.gap_ack_blocks.is_empty());
        assert!(sack.duplicate_tsns.is_empty());
    }

    #[test]
    fn observe_out_of_order_and_fill_gap_moves_cumulative_tsn_ack_multiple_blocks() {
        let now = START_TIME;
        let mut d = DataTracker::new(INITIAL_TSN, &Options::default());

        // Create two separate blocks: 12-13 and 15-16
        observe(&mut d, now, &[12, 13, 15, 16]);
        // Now fill the gap between them with 14. This should merge the blocks.
        observe(&mut d, now, &[14]);
        assert_eq!(d.additional_tsn_blocks, vec![Tsn(12)..Tsn(17)]);

        // Now receive 11, which should advance the cumulative ack over all blocks.
        observe(&mut d, now, &[11]);

        let sack = d.create_selective_ack(A_RWND);
        assert_eq!(sack.cumulative_tsn_ack, Tsn(16));
        assert!(sack.gap_ack_blocks.is_empty());
        assert!(sack.duplicate_tsns.is_empty());
    }

    #[test]
    fn observe_fill_gap_of_three_blocks_advances_cumulative_tsn() {
        let now = START_TIME;
        let mut d = DataTracker::new(INITIAL_TSN, &Options::default());

        // Create two separate blocks: 13 and 15.
        // State: additional_tsn_blocks = [13..14, 15..16]
        observe(&mut d, now, &[13, 15]);
        assert_eq!(d.additional_tsn_blocks, vec![Tsn(13)..Tsn(14), Tsn(15)..Tsn(16)]);

        // Fill the gap between them with 14.
        observe(&mut d, now, &[14]);
        assert_eq!(d.additional_tsn_blocks, vec![Tsn(13)..Tsn(16)]);

        // Add 12, which expands the first block to the left.
        observe(&mut d, now, &[12]);
        assert_eq!(d.additional_tsn_blocks, vec![Tsn(12)..Tsn(16)]);

        // Now receive 11, which should advance the cumulative ack over all blocks.
        observe(&mut d, now, &[11]);
        assert_eq!(d.last_cumulative_acked_tsn, Tsn(15));
        assert_eq!(d.additional_tsn_blocks, vec![]);

        let sack = d.create_selective_ack(A_RWND);
        assert_eq!(sack.cumulative_tsn_ack, Tsn(15));
        assert!(sack.gap_ack_blocks.is_empty());
        assert!(sack.duplicate_tsns.is_empty());
    }
}
