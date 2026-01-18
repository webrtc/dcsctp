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

use crate::EventSink;
use crate::api::Options;
use crate::api::SocketEvent;
use crate::api::SocketTime;
use crate::api::StreamId;
use crate::api::handover::HandoverReadiness;
use crate::api::handover::SocketHandoverState;
use crate::math::is_divisible_by_4;
use crate::math::round_down_to_4;
use crate::math::round_up_to_4;
use crate::packet::chunk::Chunk;
use crate::packet::data::Data;
use crate::packet::data_chunk;
use crate::packet::idata_chunk;
use crate::packet::sack_chunk::SackChunk;
use crate::timer::Timer;
use crate::timer::{self};
use crate::tx::outstanding_data::ChunkState;
use crate::tx::outstanding_data::OutstandingData;
use crate::tx::send_queue::DataToSend;
use crate::types::OutgoingMessageId;
use crate::types::Tsn;
use std::cell::RefCell;
use std::cmp::max;
use std::cmp::min;
use std::rc::Rc;
use std::time::Duration;

#[derive(Debug, PartialEq)]
enum CongestionAlgorithmPhase {
    SlowStart,
    CongestionAvoidance,
}

const MAX_EXPIRY: Duration = Duration::from_secs(3600);

#[derive(Debug, PartialEq)]
pub enum HandleSackResult {
    Invalid,
    Valid { rtt: Option<Duration>, reset_error_counter: bool },
}

pub struct RetransmissionQueue {
    mtu: usize,

    cwnd_mtus_min: usize,

    avoid_fragmentation_cwnd_mtus: usize,

    /// If the peer supports RFC 3758 - SCTP Partial Reliability Extension.
    partial_reliability: bool,

    /// The size of the data chunk (DATA/I-DATA) header that is used.
    data_chunk_header_size: usize,

    /// If RFC 8260 message interleaving is active.
    use_message_interleaving: bool,

    /// Congestion Window. Number of bytes that may be in-flight (sent, not acked).
    cwnd: usize,

    /// Receive Window. Number of bytes available in the receiver's RX buffer.
    rwnd: usize,

    /// Slow start threshold. See RFC 9260.
    ssthresh: usize,

    /// Partial bytes acked. See RFC 9260.
    partial_bytes_acked: usize,

    /// See [`crate::api::Metrics::rtx_packets_count`].
    rtx_packets_count: usize,

    /// See [`crate::api::Metrics::rtx_bytes_count`].
    rtx_bytes_count: u64,

    /// If set, fast recovery is enabled until this TSN has been cumulative acked.
    fast_recovery_exit_tsn: Option<Tsn>,

    /// All the outstanding data chunks that are in-flight and that have not been cumulative acked.
    /// Note that it also contains chunks that have been acked in gap ack blocks.
    outstanding_data: OutstandingData,

    t3_rtx: Timer,

    events: Rc<RefCell<dyn EventSink>>,
}

impl RetransmissionQueue {
    pub fn new(
        events: Rc<RefCell<dyn EventSink>>,
        my_initial_tsn: Tsn,
        a_rwnd: u32,
        options: &Options,
        supports_partial_reliability: bool,
        use_message_interleaving: bool,
    ) -> Self {
        let data_chunk_header_size = if use_message_interleaving {
            idata_chunk::HEADER_SIZE
        } else {
            data_chunk::HEADER_SIZE
        };
        Self {
            mtu: options.mtu,
            cwnd_mtus_min: options.cwnd_mtus_min,
            avoid_fragmentation_cwnd_mtus: options.avoid_fragmentation_cwnd_mtus,
            partial_reliability: supports_partial_reliability,
            data_chunk_header_size,
            use_message_interleaving,
            cwnd: options.cwnd_mtus_initial * options.mtu,
            rwnd: a_rwnd as usize,
            ssthresh: a_rwnd as usize,
            partial_bytes_acked: 0,
            rtx_packets_count: 0,
            rtx_bytes_count: 0,
            fast_recovery_exit_tsn: None,
            outstanding_data: OutstandingData::new(data_chunk_header_size, my_initial_tsn - 1),
            t3_rtx: Timer::new(
                options.rto_initial,
                timer::BackoffAlgorithm::Exponential,
                None,
                options.max_timer_backoff_duration,
            ),
            events,
        }
    }

    fn start_t3_rtx_if_outstanding_data(&mut self, now: SocketTime) {
        // Note: Can't use `unacked_bytes` as that one doesn't count chunks to be retransmitted.
        if self.outstanding_data.is_empty() {
            // From <https://datatracker.ietf.org/doc/html/rfc9260#section-6.3.2-2.2.1>:
            //
            //   Whenever all outstanding data sent to an address have been acknowledged, turn off
            //   the T3-rtx timer of that address.
        } else {
            // From <https://datatracker.ietf.org/doc/html/rfc9260#section-6.3.2>:
            //
            //   Whenever a SACK chunk is received that acknowledges the DATA chunk with the
            //   earliest outstanding TSN for that address, restart the T3-rtx timer for that
            //   address with its current RTO (if there is still outstanding data on that address).
            //
            //   Whenever a SACK chunk is received missing a TSN that was previously acknowledged
            //   via a Gap Ack Block, start the T3-rtx for the destination address to which the DATA
            //   chunk was originally transmitted if it is not already running.
            if !self.t3_rtx.is_running() {
                self.t3_rtx.start(now);
            }
        }
    }

    pub fn next_timeout(&self) -> Option<SocketTime> {
        self.t3_rtx.next_expiry()
    }

    fn is_sack_valid(&self, sack: &SackChunk) -> bool {
        // Important not to drop SACKs with identical TSN to that previously received, as the gap
        // ACK blocks or dup TSN fields may have changed.
        if sack.cumulative_tsn_ack < self.outstanding_data.last_cumulative_acked_tsn() {
            // From <https://datatracker.ietf.org/doc/html/rfc9260#section-6.2.1-5.4.2.1.1>:
            //
            //   If Cumulative TSN Ack is less than the Cumulative TSN Ack Point, then drop the SACK
            //   chunk. Since Cumulative TSN Ack is monotonically increasing, a SACK chunk whose
            //   Cumulative TSN Ack is less than the Cumulative TSN Ack Point indicates an
            //   out-of-order SACK chunk.
            false
        } else {
            sack.cumulative_tsn_ack <= self.outstanding_data.highest_outstanding_tsn()
        }
    }

    fn maybe_exit_fast_recovery(&mut self, cumulative_tsn_ack: Tsn) {
        if let Some(fast_recovery_exit_tsn) = self.fast_recovery_exit_tsn {
            if cumulative_tsn_ack >= fast_recovery_exit_tsn {
                self.fast_recovery_exit_tsn = None;
            }
        }
    }

    fn is_in_fast_recovery(&self) -> bool {
        self.fast_recovery_exit_tsn.is_some()
    }

    fn update_receiver_window(&mut self, a_rwnd: usize) {
        self.rwnd = a_rwnd.saturating_sub(self.outstanding_data.unacked_bytes());
    }

    fn phase(&self) -> CongestionAlgorithmPhase {
        if self.cwnd <= self.ssthresh {
            CongestionAlgorithmPhase::SlowStart
        } else {
            CongestionAlgorithmPhase::CongestionAvoidance
        }
    }

    fn handle_increased_cumulative_tsn_ack(
        &mut self,
        unacked_bytes: usize,
        total_bytes_acked: usize,
    ) {
        // Allow some margin for classifying as fully utilized, due to e.g. that too small packets
        // are not sent + overhead.
        let is_fully_utilized = unacked_bytes + self.mtu >= self.cwnd;
        let old_cwnd = self.cwnd;

        // TODO: Make the implementation compliant with RFC 9260.
        match self.phase() {
            CongestionAlgorithmPhase::SlowStart => {
                if is_fully_utilized && !self.is_in_fast_recovery() {
                    // From <https://datatracker.ietf.org/doc/html/rfc4960#section-7.2.1>:
                    //
                    //   Only when these three conditions are met can the cwnd be increased;
                    //   otherwise, the cwnd MUST not be increased. If these conditions are met,
                    //   then cwnd MUST be increased by, at most, the lesser of 1) the total size of
                    //   the previously outstanding DATA chunk(s) acknowledged, and 2) the
                    //   destination's path MTU.
                    self.cwnd += min(total_bytes_acked, self.mtu);
                    log::debug!("SS increase cwnd={} ({})", self.cwnd, old_cwnd);
                }
            }
            CongestionAlgorithmPhase::CongestionAvoidance => {
                // From <https://datatracker.ietf.org/doc/html/rfc4960#section-7.2.2>:
                //
                //   Whenever cwnd is greater than ssthresh, upon each SACK arrival that advances
                //   the Cumulative TSN Ack Point, increase partial_bytes_acked by the total number
                //   of bytes of all new chunks acknowledged in that SACK including chunks
                //   acknowledged by the new Cumulative TSN Ack and by Gap Ack Blocks.
                let old_pba = self.partial_bytes_acked;
                self.partial_bytes_acked += total_bytes_acked;
                if self.partial_bytes_acked >= self.cwnd && is_fully_utilized {
                    // From <https://datatracker.ietf.org/doc/html/rfc4960#section-7.2.2>:
                    //
                    //   When partial_bytes_acked is equal to or greater than cwnd and before the
                    //   arrival of the SACK the sender had cwnd or more bytes of data outstanding
                    //   (i.e., before arrival of the SACK, flightsize was greater than or equal to
                    //   cwnd), increase cwnd by MTU, and reset partial_bytes_acked to
                    //   (partial_bytes_acked - cwnd).
                    //
                    // Errata: <https://datatracker.ietf.org/doc/html/rfc8540#section-3.12>
                    self.partial_bytes_acked -= self.cwnd;
                    self.cwnd += self.mtu;
                    log::debug!(
                        "CA increase cwnd={} ({}), ssthresh={}, pba={} ({})",
                        self.cwnd,
                        old_cwnd,
                        self.ssthresh,
                        self.partial_bytes_acked,
                        old_pba
                    );
                } else {
                    log::debug!(
                        "CA unchanged cwnd={} ({}), ssthresh={}, pba={} ({})",
                        self.cwnd,
                        old_cwnd,
                        self.ssthresh,
                        self.partial_bytes_acked,
                        old_pba
                    );
                }
            }
        }
    }

    fn handle_packet_loss(&mut self, _highest_tsn_acked: Tsn) {
        // TODO: Why is `highest_tsn_acked` not used.
        if !self.is_in_fast_recovery() {
            // From <https://datatracker.ietf.org/doc/html/rfc9260#section-7.2.4-5.2.1>:
            //
            //   If not in Fast Recovery, adjust the ssthresh and cwnd of the destination
            //   address(es) to which the missing DATA chunks were last sent, according to the
            //   formula described in Section 7.2.3.
            let old_cwnd = self.cwnd;
            let old_pba = self.partial_bytes_acked;
            self.ssthresh = max(self.cwnd / 2, self.cwnd_mtus_min * self.mtu);
            self.cwnd = self.ssthresh;
            self.partial_bytes_acked = 0;
            log::debug!(
                "packet loss detected (not fast recovery). cwnd={} ({}), ssthresh={}, pba={} ({})",
                self.cwnd,
                old_cwnd,
                self.ssthresh,
                self.partial_bytes_acked,
                old_pba
            );

            // From <https://datatracker.ietf.org/doc/html/rfc9260#section-7.2.4-5.6.1>:
            //
            //   If not in Fast Recovery, enter Fast Recovery and mark the highest outstanding TSN
            //   as the Fast Recovery exit point.
            self.fast_recovery_exit_tsn = Some(self.outstanding_data.highest_outstanding_tsn());
            log::debug!(
                "fast recovery initiated with exit_point={}",
                self.fast_recovery_exit_tsn.unwrap()
            );
        } else {
            // From <https://datatracker.ietf.org/doc/html/rfc9260#section-7.2.4-5.6.1>:
            //
            //   While in Fast Recovery, the ssthresh and cwnd SHOULD NOT change for any
            //   destinations due to a subsequent Fast Recovery event (i.e., one SHOULD NOT reduce
            //   the cwnd further due to a subsequent Fast Retransmit).
            log::debug!("packet loss detected (fast recovery). No changes.");
        }
    }

    pub fn update_rto(&mut self, rto: Duration) {
        self.t3_rtx.set_duration(rto);
    }

    // Handles a received SACK. Returns true if the `sack` was processed and false if it was
    // discarded due to received out-of-order and not relevant.
    pub fn handle_sack(&mut self, now: SocketTime, sack: &SackChunk) -> HandleSackResult {
        if !self.is_sack_valid(sack) {
            return HandleSackResult::Invalid;
        }

        let old_last_cumulative_tsn_ack = self.outstanding_data.last_cumulative_acked_tsn();
        let old_unacked_bytes = self.outstanding_data.unacked_bytes();
        let old_rwnd = self.rwnd;

        let rtt = if sack.gap_ack_blocks.is_empty() {
            self.outstanding_data.measure_rtt(now, sack.cumulative_tsn_ack)
        } else {
            None
        };

        // Exit fast recovery before continuing processing, in case it needs to go into fast
        // recovery again due to new reported packet loss.
        self.maybe_exit_fast_recovery(sack.cumulative_tsn_ack);

        let ack_info = self.outstanding_data.handle_sack(
            sack.cumulative_tsn_ack,
            &sack.gap_ack_blocks,
            self.is_in_fast_recovery(),
        );

        // Add lifecycle events for delivered messages.
        for lid in ack_info.acked_lifecycle_ids {
            self.events.borrow_mut().add(SocketEvent::OnLifecycleMessageDelivered(lid.clone()));
            self.events.borrow_mut().add(SocketEvent::OnLifecycleEnd(lid));
        }
        for lid in ack_info.abandoned_lifecycle_ids {
            self.events.borrow_mut().add(SocketEvent::OnLifecycleMessageMaybeExpired(lid.clone()));
            self.events.borrow_mut().add(SocketEvent::OnLifecycleEnd(lid));
        }

        // Update of outstanding_data_ is now done. Congestion control remains.
        self.update_receiver_window(sack.a_rwnd as usize);

        log::debug!(
            "Received SACK, cum_tsn_ack={} ({}), unacked_bytes={} ({}), rwnd={} ({})",
            sack.cumulative_tsn_ack,
            old_last_cumulative_tsn_ack,
            self.outstanding_data.unacked_bytes(),
            old_unacked_bytes,
            self.rwnd,
            old_rwnd
        );

        if sack.cumulative_tsn_ack > old_last_cumulative_tsn_ack {
            // From <https://datatracker.ietf.org/doc/html/rfc9260#section-6.3.2-2.3.1>:
            //
            //   Whenever a SACK chunk is received that acknowledges the DATA chunk with the
            //   earliest outstanding TSN for that address, restart the T3-rtx timer for that
            //   address with its current RTO (if there is still outstanding data on that address).
            //
            // Note: It may be started again in a bit further down.
            self.t3_rtx.stop();

            self.handle_increased_cumulative_tsn_ack(old_unacked_bytes, ack_info.bytes_acked);
        }

        if ack_info.has_packet_loss {
            self.handle_packet_loss(ack_info.highest_tsn_acked);
        }

        // From <https://datatracker.ietf.org/doc/html/rfc9260#section-8.2-3>:
        //
        //   When an outstanding TSN is acknowledged [...] the endpoint SHOULD clear the error
        //   counter [...].
        let reset_error_counter = ack_info.bytes_acked > 0;

        self.start_t3_rtx_if_outstanding_data(now);

        HandleSackResult::Valid { rtt, reset_error_counter }
    }

    /// Handles an expired retransmission timer and returns true if it has expired.
    pub fn handle_timeout(&mut self, now: SocketTime) -> bool {
        // TODO: Make the implementation compliant with RFC 9260.

        if !self.t3_rtx.expire(now) {
            return false;
        }

        let old_cwnd = self.cwnd;
        let old_unacked_bytes = self.unacked_bytes();

        // From <https://datatracker.ietf.org/doc/html/rfc4960#section-6.3.3>:
        //
        //   For the destination address for which the timer expires, adjust its ssthresh with rules
        //   defined in Section 7.2.3 and set the cwnd <- MTU.
        self.ssthresh = max(self.cwnd / 2, 4 * self.mtu);

        self.cwnd = self.mtu;

        // Errata: <https://datatracker.ietf.org/doc/html/rfc8540#section-3.11>
        self.partial_bytes_acked = 0;

        // From <https://datatracker.ietf.org/doc/html/rfc4960#section-6.3.3>:
        //
        //   For the destination address for which the timer expires, set RTO <- RTO * 2 ("back off
        //   the timer"). The maximum value discussed in rule C7 above (RTO.max) may be used to
        //   provide an upper bound to this doubling operation.
        //
        // This is already done by the timer implementation.
        //
        //   Determine how many of the earliest (i.e., lowest TSN) outstanding DATA chunks for the
        //   address for which the T3-rtx has expired will fit into a single packet [...]
        //
        //   Note: Any DATA chunks that were sent to the address for which the T3-rtx timer expired
        //   but did not fit in one MTU (rule E3 above) should be marked for retransmission and sent
        //   as soon as cwnd allows (normally, when a SACK arrives).
        self.outstanding_data.nack_all();

        // From <https://datatracker.ietf.org/doc/html/rfc4960#section-6.3.3>:
        //
        //   Start the retransmission timer T3-rtx on the destination address to which the
        //   retransmission is sent, if rule R1 above indicates to do so.
        //
        // This is already done by the timer implementation.

        log::debug!(
            "t3-rtx expired. new cwnd={} ({}), ssthresh={}, unacked_bytes {} ({})",
            self.cwnd,
            old_cwnd,
            self.ssthresh,
            self.unacked_bytes(),
            old_unacked_bytes
        );
        true
    }

    pub fn has_data_to_be_fast_retransmitted(&self) -> bool {
        self.outstanding_data.has_data_to_be_fast_retransmitted()
    }

    /// Returns a list of chunks to "fast retransmit" that would fit in one SCTP packet with
    /// `bytes_in_packet` bytes available. The current value of `cwnd` is ignored.
    pub fn get_chunks_for_fast_retransmit(
        &mut self,
        now: SocketTime,
        bytes_remaining_in_packet: usize,
    ) -> Vec<(Tsn, Data)> {
        debug_assert!(is_divisible_by_4!(bytes_remaining_in_packet));

        let old_unacked_bytes = self.unacked_bytes();

        let to_be_sent =
            self.outstanding_data.get_chunks_to_be_fast_retransmitted(bytes_remaining_in_packet);
        debug_assert!(!to_be_sent.is_empty());

        // From <https://datatracker.ietf.org/doc/html/rfc9260#section-7.2.4-5.4.1>:
        //
        //   Restart the T3-rtx timer only if [...] the endpoint is retransmitting the first
        //   outstanding DATA chunk sent to that address.
        if to_be_sent[0].0 == self.outstanding_data.last_cumulative_acked_tsn() + 1 {
            self.t3_rtx.stop();
        }

        // From <https://datatracker.ietf.org/doc/html/rfc9260#section-6.3.2-2.1.1>:
        //
        //   Every time a DATA chunk is sent to any address (including a retransmission), if the
        //   T3-rtx timer of that address is not running, start it running so that it will expire
        //   after the RTO of that address.
        if !self.t3_rtx.is_running() {
            self.t3_rtx.start(now);
        }

        let bytes_retransmitted: usize = to_be_sent
            .iter()
            .map(|(_, data)| round_up_to_4!(self.data_chunk_header_size + data.payload.len()))
            .sum();

        self.rtx_packets_count += 1;
        self.rtx_bytes_count += bytes_retransmitted as u64;

        log::debug!(
            "Fast-retransmitting TSN {} - {} bytes. unacked_bytes={} ({})",
            to_be_sent.iter().map(|(tsn, _)| tsn.to_string()).collect::<Vec<_>>().join(","),
            bytes_retransmitted,
            self.unacked_bytes(),
            old_unacked_bytes
        );

        to_be_sent
    }

    /// Returns a list of chunks to send.
    ///
    /// Note that [`Self::should_send_forward_tsn`] must be called prior to this method, to abandon
    /// expired chunks, as this method will not expire any chunks.
    ///
    /// # Parameters
    ///
    /// * `now` - The current time.
    ///
    /// * `bytes_remaining_in_packet` - The maximum total size of chunks returned. Note that this
    ///   could be further limited by the congestion control window.
    ///
    /// * `produce` - A function that will be called when it needs to backfill new data. The first
    ///   argument refers to how many payload bytes that may be produced, not including any headers,
    ///   and the second argument contains a list of messages to discard before producing any
    ///   chunks, as those have expired already.
    pub fn get_chunks_to_send(
        &mut self,
        now: SocketTime,
        bytes_remaining_in_packet: usize,
        mut produce: impl FnMut(usize, &[(StreamId, OutgoingMessageId)]) -> Option<DataToSend>,
    ) -> Vec<(Tsn, Data)> {
        debug_assert!(is_divisible_by_4!(bytes_remaining_in_packet));

        let old_unacked_bytes = self.unacked_bytes();
        let old_rwnd = self.rwnd;

        let mut max_bytes =
            round_down_to_4!(min(self.max_bytes_to_send(), bytes_remaining_in_packet));
        let mut to_be_sent = self.outstanding_data.get_chunks_to_be_retransmitted(max_bytes);
        let bytes_retransmitted: usize = to_be_sent
            .iter()
            .map(|(_, data)| round_up_to_4!(self.data_chunk_header_size + data.payload.len()))
            .sum();
        max_bytes -= bytes_retransmitted;

        if !to_be_sent.is_empty() {
            self.rtx_packets_count += 1;
            self.rtx_bytes_count += bytes_retransmitted as u64;
        }

        while max_bytes > self.data_chunk_header_size {
            debug_assert!(is_divisible_by_4!(max_bytes));

            if let Some(chunk) = produce(
                max_bytes - self.data_chunk_header_size,
                &self.outstanding_data.get_unsent_messages_to_discard(),
            ) {
                let chunk_size =
                    round_up_to_4!(self.data_chunk_header_size + chunk.data.payload.len());
                max_bytes -= chunk_size;
                self.rwnd -= chunk_size;
                let max_retransmissions = self.chunk_max_retransmissions(&chunk);
                let expires_at = self.chunk_expires_at(now, &chunk);
                if let Some(tsn) = self.outstanding_data.insert(
                    chunk.message_id,
                    &chunk.data,
                    now,
                    max_retransmissions,
                    expires_at,
                    chunk.lifecycle_id,
                ) {
                    to_be_sent.push((tsn, chunk.data));
                }
            } else {
                break;
            }
        }

        if !to_be_sent.is_empty() {
            if !self.t3_rtx.is_running() {
                self.t3_rtx.start(now);
            }
            let sent_bytes: usize = to_be_sent
                .iter()
                .map(|(_, data)| round_up_to_4!(self.data_chunk_header_size + data.payload.len()))
                .sum();
            log::debug!(
                "Sending TSN {} - {} bytes. unacked_bytes={} ({}),  cwnd={}, rwnd={} ({})",
                to_be_sent.iter().map(|(tsn, _)| tsn.to_string()).collect::<Vec<_>>().join(","),
                sent_bytes,
                self.unacked_bytes(),
                old_unacked_bytes,
                self.cwnd,
                self.rwnd,
                old_rwnd
            );
        }

        to_be_sent
    }

    fn chunk_max_retransmissions(&self, chunk: &DataToSend) -> u16 {
        if self.partial_reliability { chunk.max_retransmissions } else { u16::MAX }
    }

    fn chunk_expires_at(&self, now: SocketTime, chunk: &DataToSend) -> SocketTime {
        if self.partial_reliability { chunk.expires_at } else { now + MAX_EXPIRY }
    }

    /// Returns the internal state of all queued chunks. This is only used in unit-tests.
    pub fn get_chunk_states_for_testing(&self) -> Vec<(Tsn, ChunkState)> {
        self.outstanding_data.get_chunk_states_for_testing()
    }

    /// Returns the next TSN that will be allocated for sent DATA chunks.
    pub fn next_tsn(&self) -> Tsn {
        self.outstanding_data.next_tsn()
    }

    pub fn last_assigned_tsn(&self) -> Tsn {
        self.outstanding_data.next_tsn() - 1
    }

    /// Returns the size of the congestion window, in bytes. This is the number of bytes that may be
    /// in-flight.
    pub fn cwnd(&self) -> usize {
        self.cwnd
    }

    /// Overrides the current congestion window size.
    pub fn set_cwnd(&mut self, cwnd: usize) {
        self.cwnd = cwnd;
    }

    /// Returns the current receiver window size.
    pub fn rwnd(&self) -> usize {
        self.rwnd
    }

    pub fn rtx_packets_count(&self) -> usize {
        self.rtx_packets_count
    }

    pub fn rtx_bytes_count(&self) -> u64 {
        self.rtx_bytes_count
    }

    /// Returns the number of bytes of packets that are in-flight.
    pub fn unacked_bytes(&self) -> usize {
        self.outstanding_data.unacked_bytes()
    }

    /// Returns the number of DATA chunks that are in-flight.
    pub fn unacked_items(&self) -> usize {
        self.outstanding_data.unacked_items()
    }

    /// Returns the number of bytes that may be sent in a single packet according to the congestion
    /// control algorithm.
    fn max_bytes_to_send(&self) -> usize {
        let left = self.cwnd.saturating_sub(self.unacked_bytes());
        if self.unacked_bytes() == 0 {
            // TODO: Make the implementation compliant with RFC 9260.
            //
            // From <https://datatracker.ietf.org/doc/html/rfc4960#section-6.1>:
            //
            //   However, regardless of the value of rwnd (including if it is 0), the data sender
            //   can always have one DATA chunk in flight to the receiver if allowed by cwnd (see
            //   rule B, below).
            return left;
        }
        min(self.rwnd, left)
    }

    pub fn should_send_forward_tsn(&mut self, now: SocketTime) -> bool {
        if !self.partial_reliability {
            return false;
        }

        self.outstanding_data.expire_outstanding_chunks(now);
        self.outstanding_data.should_send_forward_tsn()
    }

    pub fn create_forward_tsn(&mut self) -> Chunk {
        debug_assert!(self.partial_reliability);
        if !self.use_message_interleaving {
            Chunk::ForwardTsn(self.outstanding_data.create_forward_tsn())
        } else {
            Chunk::IForwardTsn(self.outstanding_data.create_iforward_tsn())
        }
    }

    pub fn begin_reset_streams(&mut self) {
        self.outstanding_data.begin_reset_streams();
    }

    pub(crate) fn get_handover_readiness(&self) -> HandoverReadiness {
        HandoverReadiness::RETRANSMISSION_QUEUE_OUTSTANDING_DATA & !self.outstanding_data.is_empty()
            | (HandoverReadiness::RETRANSMISSION_QUEUE_FAST_RECOVERY
                & self.fast_recovery_exit_tsn.is_some())
            | (HandoverReadiness::RETRANSMISSION_QUEUE_NOT_EMPTY
                & self.outstanding_data.has_data_to_be_retransmitted())
    }

    pub(crate) fn add_to_handover_state(&self, state: &mut SocketHandoverState) {
        state.tx.next_tsn = self.next_tsn().0;
        state.tx.cwnd = self.cwnd as u32;
        state.tx.rwnd = self.rwnd as u32;
        state.tx.ssthresh = self.ssthresh as u32;
        state.tx.partial_bytes_acked = self.partial_bytes_acked as u32;
    }

    pub(crate) fn restore_from_state(&mut self, state: &SocketHandoverState) {
        self.outstanding_data.reset_sequence_numbers(Tsn(state.tx.next_tsn.wrapping_sub(1)));
        self.cwnd = state.tx.cwnd as usize;
        self.rwnd = state.tx.rwnd as usize;
        self.ssthresh = state.tx.ssthresh as usize;
        self.partial_bytes_acked = state.tx.partial_bytes_acked as usize;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::Message;
    use crate::api::PpId;
    use crate::api::SendOptions;
    use crate::events::Events;
    use crate::packet::SkippedStream;
    use crate::packet::sack_chunk::GapAckBlock;
    use crate::tx::send_queue::SendQueue;
    use crate::types::Mid;
    use crate::types::Ssn;
    use crate::types::StreamKey;
    use std::collections::VecDeque;

    const A_RWND: u32 = 100000;
    const MTU: usize = 1280;
    const START_TIME: SocketTime = SocketTime::zero();

    fn make_events() -> Rc<RefCell<Events>> {
        Rc::new(RefCell::new(Events::new()))
    }

    fn create_queue(
        supports_partial_reliability: bool,
        use_message_interleaving: bool,
        events: Rc<RefCell<Events>>,
    ) -> RetransmissionQueue {
        RetransmissionQueue::new(
            events,
            Tsn(10),
            A_RWND,
            &Options::default(),
            supports_partial_reliability,
            use_message_interleaving,
        )
    }

    fn get_tsns(chunks: &[(Tsn, Data)]) -> Vec<Tsn> {
        chunks.iter().map(|(tsn, _)| *tsn).collect()
    }

    fn get_sid_tsns(chunks: &[(Tsn, Data)]) -> Vec<(StreamId, Tsn)> {
        chunks.iter().map(|(tsn, data)| (data.stream_key.id(), *tsn)).collect()
    }

    fn add_message(sq: &mut SendQueue, now: SocketTime) {
        sq.add(
            now,
            Message::new(StreamId(1), PpId(53), vec![1, 2, 4, 5, 6]),
            &SendOptions::default(),
        );
    }

    fn handle_sack(
        rtx: &mut RetransmissionQueue,
        now: SocketTime,
        cumulative_tsn_ack: Tsn,
    ) -> HandleSackResult {
        rtx.handle_sack(
            now,
            &SackChunk {
                cumulative_tsn_ack,
                a_rwnd: A_RWND,
                gap_ack_blocks: vec![],
                duplicate_tsns: vec![],
            },
        )
    }

    #[test]
    fn initial_acked_prev_tsn() {
        let events = Rc::new(RefCell::new(Events::new()));
        let rtx = create_queue(false, false, events);
        assert_eq!(rtx.get_chunk_states_for_testing(), vec![(Tsn(9), ChunkState::Acked)]);
    }

    #[test]
    fn send_one_chunk() {
        let now = START_TIME;
        let events = Rc::new(RefCell::new(Events::new()));
        let events_clone = Rc::clone(&events) as Rc<RefCell<dyn EventSink>>;
        let mut sq = SendQueue::new(MTU, &Options::default(), events_clone);
        let mut rtx = create_queue(false, false, Rc::clone(&events));

        add_message(&mut sq, now);

        assert_eq!(
            get_tsns(&rtx.get_chunks_to_send(now, MTU, |bytes, _| sq.produce(now, bytes))),
            vec![Tsn(10)]
        );

        assert_eq!(
            rtx.get_chunk_states_for_testing(),
            vec![(Tsn(9), ChunkState::Acked), (Tsn(10), ChunkState::InFlight)]
        );
    }

    #[test]
    fn send_one_chunk_and_ack() {
        let now = START_TIME;
        let events = Rc::new(RefCell::new(Events::new()));
        let events_clone = Rc::clone(&events) as Rc<RefCell<dyn EventSink>>;
        let mut sq = SendQueue::new(MTU, &Options::default(), events_clone);
        let mut rtx = create_queue(false, false, Rc::clone(&events));

        add_message(&mut sq, now);

        assert_eq!(
            get_tsns(&rtx.get_chunks_to_send(now, MTU, |bytes, _| sq.produce(now, bytes))),
            vec![Tsn(10)]
        );

        handle_sack(&mut rtx, now, Tsn(10));

        assert_eq!(rtx.get_chunk_states_for_testing(), vec![(Tsn(10), ChunkState::Acked)]);
    }

    #[test]
    fn send_three_chunks_and_ack_two() {
        let now = START_TIME;
        let events = Rc::new(RefCell::new(Events::new()));
        let events_clone = Rc::clone(&events) as Rc<RefCell<dyn EventSink>>;
        let mut sq = SendQueue::new(MTU, &Options::default(), events_clone);
        let mut rtx = create_queue(false, false, Rc::clone(&events));

        add_message(&mut sq, now);
        add_message(&mut sq, now);
        add_message(&mut sq, now);

        assert_eq!(
            get_tsns(&rtx.get_chunks_to_send(now, MTU, |bytes, _| sq.produce(now, bytes))),
            (10..=12).map(Tsn).collect::<Vec<_>>()
        );

        handle_sack(&mut rtx, now, Tsn(11));

        assert_eq!(
            rtx.get_chunk_states_for_testing(),
            vec![(Tsn(11), ChunkState::Acked), (Tsn(12), ChunkState::InFlight)]
        );
    }

    #[test]
    fn ack_with_gap_blocks_from_rfc4960_section334() {
        let now = START_TIME;
        let events = Rc::new(RefCell::new(Events::new()));
        let events_clone = Rc::clone(&events) as Rc<RefCell<dyn EventSink>>;
        let mut sq = SendQueue::new(MTU, &Options::default(), events_clone);
        let mut rtx = create_queue(false, false, Rc::clone(&events));

        for _ in 0..8 {
            add_message(&mut sq, now);
        }

        assert_eq!(
            get_tsns(&rtx.get_chunks_to_send(now, MTU, |bytes, _| sq.produce(now, bytes))),
            (10..=17).map(Tsn).collect::<Vec<_>>()
        );

        rtx.handle_sack(
            now,
            &SackChunk {
                cumulative_tsn_ack: Tsn(12),
                a_rwnd: A_RWND,
                gap_ack_blocks: vec![GapAckBlock::new(2, 3), GapAckBlock::new(5, 5)],
                duplicate_tsns: vec![],
            },
        );

        assert_eq!(
            rtx.get_chunk_states_for_testing(),
            vec![
                (Tsn(12), ChunkState::Acked),
                (Tsn(13), ChunkState::Nacked),
                (Tsn(14), ChunkState::Acked),
                (Tsn(15), ChunkState::Acked),
                (Tsn(16), ChunkState::Nacked),
                (Tsn(17), ChunkState::Acked),
            ]
        );
    }

    #[test]
    fn resend_packets_when_nacked_three_times() {
        let now = START_TIME;
        let events = Rc::new(RefCell::new(Events::new()));
        let events_clone = Rc::clone(&events) as Rc<RefCell<dyn EventSink>>;
        let mut sq = SendQueue::new(MTU, &Options::default(), events_clone);
        let mut rtx = create_queue(false, false, Rc::clone(&events));

        for _ in 0..8 {
            add_message(&mut sq, now);
        }
        assert_eq!(
            get_tsns(&rtx.get_chunks_to_send(now, MTU, |bytes, _| sq.produce(now, bytes))),
            [Tsn(10), Tsn(11), Tsn(12), Tsn(13), Tsn(14), Tsn(15), Tsn(16), Tsn(17)]
        );

        // Send more chunks, but leave some as gaps to force retransmission after three NACKs.
        add_message(&mut sq, now);
        assert_eq!(
            get_tsns(&rtx.get_chunks_to_send(now, MTU, |bytes, _| sq.produce(now, bytes))),
            [Tsn(18)]
        );

        // Ack 12, 14-15, 17-18
        rtx.handle_sack(
            now,
            &SackChunk {
                cumulative_tsn_ack: Tsn(12),
                a_rwnd: A_RWND,
                gap_ack_blocks: vec![GapAckBlock::new(2, 3), GapAckBlock::new(5, 6)],
                duplicate_tsns: vec![],
            },
        );

        assert_eq!(
            rtx.get_chunk_states_for_testing(),
            vec![
                (Tsn(12), ChunkState::Acked),
                (Tsn(13), ChunkState::Nacked),
                (Tsn(14), ChunkState::Acked),
                (Tsn(15), ChunkState::Acked),
                (Tsn(16), ChunkState::Nacked),
                (Tsn(17), ChunkState::Acked),
                (Tsn(18), ChunkState::Acked),
            ]
        );

        // Send 19
        add_message(&mut sq, now);
        assert_eq!(
            get_tsns(&rtx.get_chunks_to_send(now, MTU, |bytes, _| sq.produce(now, bytes))),
            [Tsn(19)]
        );

        // Ack 12, 14-15, 17-19
        rtx.handle_sack(
            now,
            &SackChunk {
                cumulative_tsn_ack: Tsn(12),
                a_rwnd: A_RWND,
                gap_ack_blocks: vec![GapAckBlock::new(2, 3), GapAckBlock::new(5, 7)],
                duplicate_tsns: vec![],
            },
        );

        assert_eq!(
            rtx.get_chunk_states_for_testing(),
            vec![
                (Tsn(12), ChunkState::Acked),
                (Tsn(13), ChunkState::Nacked),
                (Tsn(14), ChunkState::Acked),
                (Tsn(15), ChunkState::Acked),
                (Tsn(16), ChunkState::Nacked),
                (Tsn(17), ChunkState::Acked),
                (Tsn(18), ChunkState::Acked),
                (Tsn(19), ChunkState::Acked),
            ]
        );

        // Send 20
        add_message(&mut sq, now);
        assert_eq!(
            get_tsns(&rtx.get_chunks_to_send(now, MTU, |bytes, _| sq.produce(now, bytes))),
            [Tsn(20)]
        );

        // Ack 12, 14-15, 17-20
        rtx.handle_sack(
            now,
            &SackChunk {
                cumulative_tsn_ack: Tsn(12),
                a_rwnd: A_RWND,
                gap_ack_blocks: vec![GapAckBlock::new(2, 3), GapAckBlock::new(5, 8)],
                duplicate_tsns: vec![],
            },
        );

        assert_eq!(
            rtx.get_chunk_states_for_testing(),
            vec![
                (Tsn(12), ChunkState::Acked),
                (Tsn(13), ChunkState::ToBeRetransmitted),
                (Tsn(14), ChunkState::Acked),
                (Tsn(15), ChunkState::Acked),
                (Tsn(16), ChunkState::ToBeRetransmitted),
                (Tsn(17), ChunkState::Acked),
                (Tsn(18), ChunkState::Acked),
                (Tsn(19), ChunkState::Acked),
                (Tsn(20), ChunkState::Acked),
            ]
        );

        // This will trigger "fast retransmit" mode and only chunks 13 and 16 will be resent.
        assert_eq!(get_tsns(&rtx.get_chunks_for_fast_retransmit(now, MTU)), vec![Tsn(13), Tsn(16)]);

        assert_eq!(
            rtx.get_chunk_states_for_testing(),
            vec![
                (Tsn(12), ChunkState::Acked),
                (Tsn(13), ChunkState::InFlight),
                (Tsn(14), ChunkState::Acked),
                (Tsn(15), ChunkState::Acked),
                (Tsn(16), ChunkState::InFlight),
                (Tsn(17), ChunkState::Acked),
                (Tsn(18), ChunkState::Acked),
                (Tsn(19), ChunkState::Acked),
                (Tsn(20), ChunkState::Acked),
            ]
        );
    }

    #[test]
    fn restarts_t3_rtx_on_retransmit_first_outstanding_tsn() {
        // Verifies that if fast retransmit is retransmitting the first outstanding TSN, it will
        // also restart T3-RTX.
        let mut now = START_TIME;
        let events = Rc::new(RefCell::new(Events::new()));
        let events_clone = Rc::clone(&events) as Rc<RefCell<dyn EventSink>>;
        let mut sq = SendQueue::new(MTU, &Options::default(), events_clone);
        let mut rtx = create_queue(false, false, Rc::clone(&events));

        for _ in 0..3 {
            add_message(&mut sq, now);
        }
        assert_eq!(
            get_tsns(&rtx.get_chunks_to_send(now, MTU, |bytes, _| sq.produce(now, bytes))),
            [Tsn(10), Tsn(11), Tsn(12)]
        );

        // Ack 10, 12, after 100ms.
        now = now + Duration::from_millis(100);
        rtx.handle_sack(
            now,
            &SackChunk {
                cumulative_tsn_ack: Tsn(10),
                a_rwnd: A_RWND,
                gap_ack_blocks: vec![GapAckBlock::new(2, 2)],
                duplicate_tsns: vec![],
            },
        );
        assert_eq!(
            rtx.get_chunk_states_for_testing(),
            vec![
                (Tsn(10), ChunkState::Acked),
                (Tsn(11), ChunkState::Nacked),
                (Tsn(12), ChunkState::Acked),
            ]
        );

        // Send 13
        add_message(&mut sq, now);
        assert_eq!(
            get_tsns(&rtx.get_chunks_to_send(now, MTU, |bytes, _| sq.produce(now, bytes))),
            [Tsn(13)]
        );

        // Ack 10, 12-13, after 100ms.
        now = now + Duration::from_millis(100);
        rtx.handle_sack(
            now,
            &SackChunk {
                cumulative_tsn_ack: Tsn(10),
                a_rwnd: A_RWND,
                gap_ack_blocks: vec![GapAckBlock::new(2, 3)],
                duplicate_tsns: vec![],
            },
        );
        assert_eq!(
            rtx.get_chunk_states_for_testing(),
            vec![
                (Tsn(10), ChunkState::Acked),
                (Tsn(11), ChunkState::Nacked),
                (Tsn(12), ChunkState::Acked),
                (Tsn(13), ChunkState::Acked),
            ]
        );

        // Send 14
        add_message(&mut sq, now);
        assert_eq!(
            get_tsns(&rtx.get_chunks_to_send(now, MTU, |bytes, _| sq.produce(now, bytes))),
            [Tsn(14)]
        );

        // Ack 10, 12-14, after 100ms.
        now = now + Duration::from_millis(100);
        rtx.handle_sack(
            now,
            &SackChunk {
                cumulative_tsn_ack: Tsn(10),
                a_rwnd: A_RWND,
                gap_ack_blocks: vec![GapAckBlock::new(2, 4)],
                duplicate_tsns: vec![],
            },
        );
        assert_eq!(
            rtx.get_chunk_states_for_testing(),
            vec![
                (Tsn(10), ChunkState::Acked),
                (Tsn(11), ChunkState::ToBeRetransmitted),
                (Tsn(12), ChunkState::Acked),
                (Tsn(13), ChunkState::Acked),
                (Tsn(14), ChunkState::Acked),
            ]
        );

        let prev_timeout = rtx.next_timeout().unwrap();

        // This will trigger "fast retransmit" mode and only chunks 11 will be resent.
        assert_eq!(get_tsns(&rtx.get_chunks_for_fast_retransmit(now, MTU)), vec![Tsn(11)]);
        assert_eq!(
            rtx.get_chunk_states_for_testing(),
            vec![
                (Tsn(10), ChunkState::Acked),
                (Tsn(11), ChunkState::InFlight),
                (Tsn(12), ChunkState::Acked),
                (Tsn(13), ChunkState::Acked),
                (Tsn(14), ChunkState::Acked),
            ]
        );

        // Verify that the timer was really restarted when fast-retransmitting.
        assert!(rtx.next_timeout().unwrap() > prev_timeout);
    }

    #[test]
    fn can_only_produce_two_packets_but_wants_to_send_three() {
        // Verifies that if fast retransmit is retransmitting the first outstanding TSN, it will
        // also restart T3-RTX.
        let now = START_TIME;
        let events = Rc::new(RefCell::new(Events::new()));
        let events_clone = Rc::clone(&events) as Rc<RefCell<dyn EventSink>>;
        let mut sq = SendQueue::new(MTU, &Options::default(), events_clone);
        let mut rtx = create_queue(false, false, Rc::clone(&events));

        for _ in 0..2 {
            add_message(&mut sq, now);
        }
        assert_eq!(
            get_tsns(&rtx.get_chunks_to_send(now, MTU, |bytes, _| sq.produce(now, bytes))),
            [Tsn(10), Tsn(11)]
        );

        assert_eq!(
            rtx.get_chunk_states_for_testing(),
            vec![
                (Tsn(9), ChunkState::Acked),
                (Tsn(10), ChunkState::InFlight),
                (Tsn(11), ChunkState::InFlight),
            ]
        );
    }

    #[test]
    fn retransmits_on_t3_expiry() {
        let mut now = START_TIME;
        let events = Rc::new(RefCell::new(Events::new()));
        let events_clone = Rc::clone(&events) as Rc<RefCell<dyn EventSink>>;
        let mut sq = SendQueue::new(MTU, &Options::default(), events_clone);
        let mut rtx = create_queue(false, false, Rc::clone(&events));

        add_message(&mut sq, now);

        assert!(!rtx.should_send_forward_tsn(now));
        assert_eq!(
            get_tsns(&rtx.get_chunks_to_send(now, MTU, |bytes, _| sq.produce(now, bytes))),
            [Tsn(10)]
        );
        assert_eq!(
            rtx.get_chunk_states_for_testing(),
            [(Tsn(9), ChunkState::Acked), (Tsn(10), ChunkState::InFlight),]
        );

        // Will force chunks to be retransmitted
        now = rtx.next_timeout().unwrap();
        rtx.handle_timeout(now);

        assert_eq!(
            rtx.get_chunk_states_for_testing(),
            [(Tsn(9), ChunkState::Acked), (Tsn(10), ChunkState::ToBeRetransmitted),]
        );

        assert!(!rtx.should_send_forward_tsn(now));

        assert_eq!(
            rtx.get_chunk_states_for_testing(),
            [(Tsn(9), ChunkState::Acked), (Tsn(10), ChunkState::ToBeRetransmitted),]
        );

        assert_eq!(
            get_tsns(&rtx.get_chunks_to_send(now, MTU, |bytes, _| sq.produce(now, bytes))),
            [Tsn(10)]
        );
        assert_eq!(
            rtx.get_chunk_states_for_testing(),
            [(Tsn(9), ChunkState::Acked), (Tsn(10), ChunkState::InFlight),]
        );
    }

    #[test]
    fn limited_retransmission_only_with_rfc3758_support() {
        let mut now = START_TIME;
        let events = Rc::new(RefCell::new(Events::new()));
        let events_clone = Rc::clone(&events) as Rc<RefCell<dyn EventSink>>;
        let mut sq = SendQueue::new(MTU, &Options::default(), events_clone);
        let mut rtx = create_queue(/* supports_partial_reliability */ false, false, events);

        sq.add(
            now,
            Message::new(StreamId(1), PpId(53), vec![1, 2, 4, 5, 6]),
            &SendOptions { max_retransmissions: Some(0), ..SendOptions::default() },
        );

        assert!(!rtx.should_send_forward_tsn(now));
        assert_eq!(
            get_tsns(&rtx.get_chunks_to_send(now, MTU, |bytes, _| sq.produce(now, bytes))),
            [Tsn(10)]
        );
        assert_eq!(
            rtx.get_chunk_states_for_testing(),
            [(Tsn(9), ChunkState::Acked), (Tsn(10), ChunkState::InFlight),]
        );

        // Will force chunks to be retransmitted
        now = rtx.next_timeout().unwrap();
        rtx.handle_timeout(now);
        assert_eq!(
            rtx.get_chunk_states_for_testing(),
            [(Tsn(9), ChunkState::Acked), (Tsn(10), ChunkState::ToBeRetransmitted),]
        );
        assert!(!rtx.should_send_forward_tsn(now));
    }

    #[test]
    fn limits_retransmissions_as_udp() {
        let mut now = START_TIME;
        let events = Rc::new(RefCell::new(Events::new()));
        let events_clone = Rc::clone(&events) as Rc<RefCell<dyn EventSink>>;
        let mut sq = SendQueue::new(MTU, &Options::default(), events_clone);
        let mut rtx = create_queue(/* supports_partial_reliability */ true, false, events);

        sq.add(
            now,
            Message::new(StreamId(1), PpId(53), vec![1, 2, 4, 5, 6]),
            &SendOptions { max_retransmissions: Some(0), ..SendOptions::default() },
        );

        assert!(!rtx.should_send_forward_tsn(now));
        assert_eq!(
            get_tsns(&rtx.get_chunks_to_send(now, MTU, |bytes, _| sq.produce(now, bytes))),
            [Tsn(10)]
        );
        assert_eq!(
            rtx.get_chunk_states_for_testing(),
            [(Tsn(9), ChunkState::Acked), (Tsn(10), ChunkState::InFlight),]
        );

        // Will force chunks to be retransmitted
        now = rtx.next_timeout().unwrap();
        rtx.handle_timeout(now);
        assert_eq!(
            rtx.get_chunk_states_for_testing(),
            [(Tsn(9), ChunkState::Acked), (Tsn(10), ChunkState::Abandoned),]
        );
        assert!(rtx.should_send_forward_tsn(now));
        assert!(rtx.get_chunks_to_send(now, MTU, |bytes, _| sq.produce(now, bytes)).is_empty());
    }

    #[test]
    fn limits_retransmissions_to_three_sends() {
        let mut now = START_TIME;
        let events = Rc::new(RefCell::new(Events::new()));
        let events_clone = Rc::clone(&events) as Rc<RefCell<dyn EventSink>>;
        let mut sq = SendQueue::new(MTU, &Options::default(), events_clone);
        let mut rtx = create_queue(/* supports_partial_reliability */ true, false, events);

        sq.add(
            now,
            Message::new(StreamId(1), PpId(53), vec![1, 2, 4, 5, 6]),
            &SendOptions { max_retransmissions: Some(3), ..SendOptions::default() },
        );

        assert_eq!(
            get_tsns(&rtx.get_chunks_to_send(now, MTU, |bytes, _| sq.produce(now, bytes))),
            [Tsn(10)]
        );

        // Retransmission 1
        now = rtx.next_timeout().unwrap();
        rtx.handle_timeout(now);
        assert!(!rtx.should_send_forward_tsn(now));
        assert_eq!(
            get_tsns(&rtx.get_chunks_to_send(now, MTU, |bytes, _| sq.produce(now, bytes))),
            [Tsn(10)]
        );

        // Retransmission 2
        now = rtx.next_timeout().unwrap();
        rtx.handle_timeout(now);
        assert!(!rtx.should_send_forward_tsn(now));
        assert_eq!(
            get_tsns(&rtx.get_chunks_to_send(now, MTU, |bytes, _| sq.produce(now, bytes))),
            [Tsn(10)]
        );

        // Retransmission 3
        now = rtx.next_timeout().unwrap();
        rtx.handle_timeout(now);
        assert!(!rtx.should_send_forward_tsn(now));
        assert_eq!(
            get_tsns(&rtx.get_chunks_to_send(now, MTU, |bytes, _| sq.produce(now, bytes))),
            [Tsn(10)]
        );

        // Retransmission 4 - not allowed.
        now = rtx.next_timeout().unwrap();
        rtx.handle_timeout(now);
        assert!(rtx.should_send_forward_tsn(now));
        assert_eq!(
            get_tsns(&rtx.get_chunks_to_send(now, MTU, |bytes, _| sq.produce(now, bytes))),
            []
        );
        assert_eq!(
            rtx.get_chunk_states_for_testing(),
            [(Tsn(9), ChunkState::Acked), (Tsn(10), ChunkState::Abandoned),]
        );
    }

    #[test]
    fn retransmits_when_send_buffer_is_full_t3_expiry() {
        let mut now = START_TIME;
        let events = Rc::new(RefCell::new(Events::new()));
        let events_clone = Rc::clone(&events) as Rc<RefCell<dyn EventSink>>;
        let mut sq = SendQueue::new(MTU, &Options::default(), events_clone);
        let mut rtx = create_queue(/* supports_partial_reliability */ true, false, events);
        const CWND: usize = 1200;

        rtx.set_cwnd(CWND);
        assert_eq!(rtx.cwnd(), CWND);
        assert_eq!(rtx.unacked_bytes(), 0);
        assert_eq!(rtx.unacked_items(), 0);

        sq.add(
            now,
            Message::new(StreamId(1), PpId(53), vec![0; 1000]),
            &SendOptions { max_retransmissions: Some(3), ..SendOptions::default() },
        );

        assert_eq!(
            get_tsns(&rtx.get_chunks_to_send(now, 1500, |bytes, _| sq.produce(now, bytes))),
            [Tsn(10)]
        );
        assert_eq!(
            rtx.get_chunk_states_for_testing(),
            [(Tsn(9), ChunkState::Acked), (Tsn(10), ChunkState::InFlight),]
        );
        assert_eq!(rtx.unacked_bytes(), 1000 + data_chunk::HEADER_SIZE);
        assert_eq!(rtx.unacked_items(), 1);

        // Will force chunks to be retransmitted
        now = rtx.next_timeout().unwrap();
        rtx.handle_timeout(now);

        assert_eq!(
            rtx.get_chunk_states_for_testing(),
            [(Tsn(9), ChunkState::Acked), (Tsn(10), ChunkState::ToBeRetransmitted),]
        );
        assert_eq!(rtx.unacked_bytes(), 0);
        assert_eq!(rtx.unacked_items(), 0);
        assert_eq!(
            get_tsns(&rtx.get_chunks_to_send(now, 1500, |bytes, _| sq.produce(now, bytes))),
            [Tsn(10)]
        );
        assert_eq!(rtx.unacked_bytes(), 1000 + data_chunk::HEADER_SIZE);
        assert_eq!(rtx.unacked_items(), 1);
    }

    #[test]
    fn produces_valid_forward_tsn() {
        let mut now = START_TIME;
        let events = Rc::new(RefCell::new(Events::new()));
        let events_clone = Rc::clone(&events) as Rc<RefCell<dyn EventSink>>;
        let mut sq = SendQueue::new(MTU, &Options::default(), events_clone);
        let mut rtx = create_queue(/* supports_partial_reliability */ true, false, events);

        sq.add(
            now,
            Message::new(StreamId(1), PpId(53), vec![0; 4 * 4]),
            &SendOptions { max_retransmissions: Some(0), ..SendOptions::default() },
        );

        let bytes = 4 + data_chunk::HEADER_SIZE;
        assert_eq!(
            get_tsns(&rtx.get_chunks_to_send(now, bytes, |bytes, _| sq.produce(now, bytes))),
            [Tsn(10)]
        );
        assert_eq!(
            get_tsns(&rtx.get_chunks_to_send(now, bytes, |bytes, _| sq.produce(now, bytes))),
            [Tsn(11)]
        );
        assert_eq!(
            get_tsns(&rtx.get_chunks_to_send(now, bytes, |bytes, _| sq.produce(now, bytes))),
            [Tsn(12)]
        );
        assert_eq!(
            rtx.get_chunk_states_for_testing(),
            [
                (Tsn(9), ChunkState::Acked),
                (Tsn(10), ChunkState::InFlight),
                (Tsn(11), ChunkState::InFlight),
                (Tsn(12), ChunkState::InFlight),
            ]
        );

        // Chunk 10 is acked, but the remaining are lost
        handle_sack(&mut rtx, now, Tsn(10));

        now = rtx.next_timeout().unwrap();
        rtx.handle_timeout(now);
        assert_eq!(
            rtx.get_chunk_states_for_testing(),
            [
                (Tsn(10), ChunkState::Acked),
                (Tsn(11), ChunkState::Abandoned),
                (Tsn(12), ChunkState::Abandoned),
                (Tsn(13), ChunkState::Abandoned),
            ]
        );
        assert!(rtx.should_send_forward_tsn(now));

        let Chunk::ForwardTsn(fwd) = rtx.create_forward_tsn() else {
            panic!();
        };
        assert_eq!(fwd.new_cumulative_tsn, Tsn(13));
        assert_eq!(fwd.skipped_streams, vec![SkippedStream::ForwardTsn(StreamId(1), Ssn(0))]);
    }

    #[test]
    fn produces_valid_forward_tsn_when_fully_sent() {
        let mut now = START_TIME;
        let events = Rc::new(RefCell::new(Events::new()));
        let events_clone = Rc::clone(&events) as Rc<RefCell<dyn EventSink>>;
        let mut sq = SendQueue::new(MTU, &Options::default(), events_clone);
        let mut rtx = create_queue(/* supports_partial_reliability */ true, false, events);

        sq.add(
            now,
            Message::new(StreamId(1), PpId(53), vec![0; 3 * 4]),
            &SendOptions { max_retransmissions: Some(0), ..SendOptions::default() },
        );

        let bytes = 4 + data_chunk::HEADER_SIZE;
        assert_eq!(
            get_tsns(&rtx.get_chunks_to_send(now, bytes, |bytes, _| sq.produce(now, bytes))),
            [Tsn(10)]
        );
        assert_eq!(
            get_tsns(&rtx.get_chunks_to_send(now, bytes, |bytes, _| sq.produce(now, bytes))),
            [Tsn(11)]
        );
        assert_eq!(
            get_tsns(&rtx.get_chunks_to_send(now, bytes, |bytes, _| sq.produce(now, bytes))),
            [Tsn(12)]
        );
        assert_eq!(
            rtx.get_chunk_states_for_testing(),
            [
                (Tsn(9), ChunkState::Acked),
                (Tsn(10), ChunkState::InFlight),
                (Tsn(11), ChunkState::InFlight),
                (Tsn(12), ChunkState::InFlight),
            ]
        );

        // Chunk 10 is acked, but the remaining are lost
        handle_sack(&mut rtx, now, Tsn(10));

        now = rtx.next_timeout().unwrap();
        rtx.handle_timeout(now);
        assert_eq!(
            rtx.get_chunk_states_for_testing(),
            [
                (Tsn(10), ChunkState::Acked),
                (Tsn(11), ChunkState::Abandoned),
                (Tsn(12), ChunkState::Abandoned),
            ]
        );
        assert!(rtx.should_send_forward_tsn(now));

        let Chunk::ForwardTsn(fwd) = rtx.create_forward_tsn() else {
            panic!();
        };
        assert_eq!(fwd.new_cumulative_tsn, Tsn(12));
        assert_eq!(fwd.skipped_streams, vec![SkippedStream::ForwardTsn(StreamId(1), Ssn(0))]);
    }

    #[test]
    #[ignore]
    fn produces_valid_i_forward_tsn() {
        let mut now = START_TIME;
        let events = Rc::new(RefCell::new(Events::new()));
        let mut sq = SendQueue::new(MTU, &Options::default(), events.clone());
        let mut rtx = create_queue(
            /* supports_partial_reliability */ true, /* use_message_interleaving */ true,
            events,
        );

        let s = SendOptions { max_retransmissions: Some(0), ..SendOptions::default() };

        sq.set_priority(StreamId(1), 1);
        sq.set_priority(StreamId(2), 1);
        sq.set_priority(StreamId(3), 1);
        sq.set_priority(StreamId(4), 1);
        sq.add(now, Message::new(StreamId(1), PpId(53), vec![0; 2 * MTU]), &s);
        sq.add(now, Message::new(StreamId(2), PpId(53), vec![0; 2 * MTU]), &s);
        sq.add(now, Message::new(StreamId(3), PpId(53), vec![0; 2 * MTU]), &s);
        sq.add(now, Message::new(StreamId(4), PpId(53), vec![0; 2 * MTU]), &s);

        let bytes = MTU;
        assert_eq!(
            get_sid_tsns(&rtx.get_chunks_to_send(now, bytes, |bytes, _| sq.produce(now, bytes))),
            [(StreamId(1), Tsn(10))]
        );
        assert_eq!(
            get_sid_tsns(&rtx.get_chunks_to_send(now, bytes, |bytes, _| sq.produce(now, bytes))),
            [(StreamId(2), Tsn(11))]
        );
        assert_eq!(
            get_sid_tsns(&rtx.get_chunks_to_send(now, bytes, |bytes, _| sq.produce(now, bytes))),
            [(StreamId(3), Tsn(12))]
        );
        assert_eq!(
            get_sid_tsns(&rtx.get_chunks_to_send(now, bytes, |bytes, _| sq.produce(now, bytes))),
            [(StreamId(4), Tsn(13))]
        );

        assert_eq!(
            rtx.get_chunk_states_for_testing(),
            [
                (Tsn(9), ChunkState::Acked),
                (Tsn(10), ChunkState::InFlight),
                (Tsn(11), ChunkState::InFlight),
                (Tsn(12), ChunkState::InFlight),
                (Tsn(13), ChunkState::InFlight),
            ]
        );

        // Chunk 13 is acked, but the remaining are lost
        rtx.handle_sack(
            now,
            &SackChunk {
                cumulative_tsn_ack: Tsn(9),
                a_rwnd: A_RWND,
                gap_ack_blocks: vec![GapAckBlock::new(4, 4)],
                duplicate_tsns: vec![],
            },
        );
        assert_eq!(
            rtx.get_chunk_states_for_testing(),
            [
                (Tsn(9), ChunkState::Acked),
                (Tsn(10), ChunkState::Nacked),
                (Tsn(11), ChunkState::Nacked),
                (Tsn(12), ChunkState::Nacked),
                (Tsn(13), ChunkState::Acked),
            ]
        );

        now = rtx.next_timeout().unwrap();
        rtx.handle_timeout(now);
        assert_eq!(
            rtx.get_chunk_states_for_testing(),
            [
                (Tsn(9), ChunkState::Acked),
                (Tsn(10), ChunkState::Abandoned),
                (Tsn(11), ChunkState::Abandoned),
                (Tsn(12), ChunkState::Abandoned),
                (Tsn(13), ChunkState::Acked),
                // Representing end fragments of stream 1-3
                (Tsn(14), ChunkState::Abandoned),
                (Tsn(15), ChunkState::Abandoned),
                (Tsn(16), ChunkState::Abandoned),
            ]
        );
        assert!(rtx.should_send_forward_tsn(now));

        let Chunk::IForwardTsn(fwd) = rtx.create_forward_tsn() else {
            panic!();
        };
        assert_eq!(fwd.new_cumulative_tsn, Tsn(12));
        assert_eq!(
            fwd.skipped_streams,
            vec![
                SkippedStream::IForwardTsn(StreamKey::Ordered(StreamId(1)), Mid(0)),
                SkippedStream::IForwardTsn(StreamKey::Ordered(StreamId(2)), Mid(0)),
                SkippedStream::IForwardTsn(StreamKey::Ordered(StreamId(3)), Mid(0))
            ]
        );

        // TODO: Continue migrating this test case.
    }

    #[test]
    fn measure_rtt() {
        let mut now = START_TIME;
        let events = Rc::new(RefCell::new(Events::new()));
        let events_clone = Rc::clone(&events) as Rc<RefCell<dyn EventSink>>;
        let mut sq = SendQueue::new(MTU, &Options::default(), events_clone);
        let mut rtx = create_queue(/* supports_partial_reliability */ true, false, events);

        add_message(&mut sq, now);
        assert_eq!(
            get_tsns(&rtx.get_chunks_to_send(now, MTU, |bytes, _| sq.produce(now, bytes))),
            [Tsn(10)]
        );

        now = now + Duration::from_millis(123);

        let HandleSackResult::Valid { rtt, .. } = handle_sack(&mut rtx, now, Tsn(10)) else {
            panic!()
        };

        assert_eq!(rtt.unwrap(), Duration::from_millis(123));
    }

    #[test]
    fn validate_cum_tsn_at_rest() {
        let now = START_TIME;
        let events = Rc::new(RefCell::new(Events::new()));
        let mut rtx = create_queue(/* supports_partial_reliability */ true, false, events);

        assert_eq!(handle_sack(&mut rtx, now, Tsn(8)), HandleSackResult::Invalid);
        assert_eq!(
            handle_sack(&mut rtx, now, Tsn(9)),
            HandleSackResult::Valid { rtt: None, reset_error_counter: false }
        );
        assert_eq!(handle_sack(&mut rtx, now, Tsn(10)), HandleSackResult::Invalid);
    }

    #[test]
    fn validate_cum_tsn_ack_on_inflight_data() {
        let now = START_TIME;
        let events = Rc::new(RefCell::new(Events::new()));
        let events_clone = Rc::clone(&events) as Rc<RefCell<dyn EventSink>>;
        let mut sq = SendQueue::new(MTU, &Options::default(), events_clone);
        let mut rtx = create_queue(/* supports_partial_reliability */ true, false, events);

        add_message(&mut sq, now);
        add_message(&mut sq, now);

        assert_eq!(
            get_tsns(&rtx.get_chunks_to_send(now, MTU, |bytes, _| sq.produce(now, bytes))),
            vec![Tsn(10), Tsn(11)]
        );

        assert_eq!(handle_sack(&mut rtx, now, Tsn(8)), HandleSackResult::Invalid);
        assert_eq!(
            handle_sack(&mut rtx, now, Tsn(9)),
            HandleSackResult::Valid { rtt: None, reset_error_counter: false }
        );
        assert_eq!(
            handle_sack(&mut rtx, now, Tsn(10)),
            HandleSackResult::Valid { rtt: Some(Duration::ZERO), reset_error_counter: true }
        );
        assert_eq!(
            handle_sack(&mut rtx, now, Tsn(11)),
            HandleSackResult::Valid { rtt: Some(Duration::ZERO), reset_error_counter: true }
        );
        assert_eq!(handle_sack(&mut rtx, now, Tsn(12)), HandleSackResult::Invalid);
    }

    #[test]
    fn handle_gap_ack_blocks_matching_no_inflight_data() {
        let now = START_TIME;
        let events = Rc::new(RefCell::new(Events::new()));
        let mut sq = SendQueue::new(MTU, &Options::default(), events.clone());
        let mut rtx = create_queue(/* supports_partial_reliability */ true, false, events);

        sq.add(now, Message::new(StreamId(1), PpId(53), vec![0; 4 * 8]), &SendOptions::default());

        for _ in 0..8 {
            rtx.get_chunks_to_send(now, data_chunk::HEADER_SIZE + 4, |bytes, _| {
                sq.produce(now, bytes)
            });
        }

        assert_eq!(
            rtx.get_chunk_states_for_testing(),
            [
                (Tsn(9), ChunkState::Acked),
                (Tsn(10), ChunkState::InFlight),
                (Tsn(11), ChunkState::InFlight),
                (Tsn(12), ChunkState::InFlight),
                (Tsn(13), ChunkState::InFlight),
                (Tsn(14), ChunkState::InFlight),
                (Tsn(15), ChunkState::InFlight),
                (Tsn(16), ChunkState::InFlight),
                (Tsn(17), ChunkState::InFlight),
            ]
        );

        // Ack 9, 20-25. This is an invalid SACK, but should still be handled.
        rtx.handle_sack(
            now,
            &SackChunk {
                cumulative_tsn_ack: Tsn(9),
                a_rwnd: A_RWND,
                gap_ack_blocks: vec![GapAckBlock::new(11, 16)],
                duplicate_tsns: vec![],
            },
        );

        assert_eq!(
            rtx.get_chunk_states_for_testing(),
            [
                (Tsn(9), ChunkState::Acked),
                (Tsn(10), ChunkState::InFlight),
                (Tsn(11), ChunkState::InFlight),
                (Tsn(12), ChunkState::InFlight),
                (Tsn(13), ChunkState::InFlight),
                (Tsn(14), ChunkState::InFlight),
                (Tsn(15), ChunkState::InFlight),
                (Tsn(16), ChunkState::InFlight),
                (Tsn(17), ChunkState::InFlight),
            ]
        );
    }

    #[test]
    fn handle_invalid_gap_ack_blocks() {
        let now = START_TIME;
        let events = Rc::new(RefCell::new(Events::new()));
        let mut rtx = create_queue(/* supports_partial_reliability */ true, false, events);

        // Nothing produced - nothing in retransmission queue

        // Ack 9, 12-13
        rtx.handle_sack(
            now,
            &SackChunk {
                cumulative_tsn_ack: Tsn(9),
                a_rwnd: A_RWND,
                gap_ack_blocks: vec![GapAckBlock::new(3, 4)],
                duplicate_tsns: vec![],
            },
        );

        assert_eq!(rtx.get_chunk_states_for_testing(), [(Tsn(9), ChunkState::Acked)]);
    }

    #[test]
    fn gap_ack_blocks_do_not_move_cum_tsn_ack() {
        let now = START_TIME;
        let events = Rc::new(RefCell::new(Events::new()));
        let events_clone = Rc::clone(&events) as Rc<RefCell<dyn EventSink>>;
        let mut sq = SendQueue::new(MTU, &Options::default(), events_clone);
        let mut rtx = create_queue(false, false, events);

        for _ in 0..8 {
            add_message(&mut sq, now);
        }

        assert_eq!(
            get_tsns(&rtx.get_chunks_to_send(now, MTU, |bytes, _| sq.produce(now, bytes))),
            (10..=17).map(Tsn).collect::<Vec<_>>()
        );

        // Ack 9, 10-14. This is actually an invalid ACK as the first gap can't be adjacent to the
        // cum-tsn-ack, but it's not strictly forbidden. However, the cum-tsn-ack should not move,
        // as the gap-ack-blocks are just advisory.
        rtx.handle_sack(
            now,
            &SackChunk {
                cumulative_tsn_ack: Tsn(9),
                a_rwnd: A_RWND,
                gap_ack_blocks: vec![GapAckBlock::new(1, 5)],
                duplicate_tsns: vec![],
            },
        );

        assert_eq!(
            rtx.get_chunk_states_for_testing(),
            vec![
                (Tsn(9), ChunkState::Acked),
                (Tsn(10), ChunkState::Acked),
                (Tsn(11), ChunkState::Acked),
                (Tsn(12), ChunkState::Acked),
                (Tsn(13), ChunkState::Acked),
                (Tsn(14), ChunkState::Acked),
                (Tsn(15), ChunkState::InFlight),
                (Tsn(16), ChunkState::InFlight),
                (Tsn(17), ChunkState::InFlight),
            ]
        );
    }

    #[test]
    fn stays_within_available_size() {
        let now = START_TIME;
        let events = Rc::new(RefCell::new(Events::new()));
        let events_clone = Rc::clone(&events) as Rc<RefCell<dyn EventSink>>;
        const MTU: usize = 1191;
        let mut sq = SendQueue::new(MTU, &Options::default(), events_clone);
        let mut rtx = create_queue(false, false, events);

        // Assume a MTU of 1191, which rounded down to even divisible by 4 becomes 1188, and reserve
        // space for the SCTP common header size (12 bytes), which leaves 1176 bytes.
        const BYTES_REMAINING_STEP_0: usize = 1176;

        // Then a data payload of 183 bytes is to be produced.
        const FIRST_DATA_PAYLOAD_SIZE: usize = 183;

        // This is the amount of space available in the packet after that has been added together
        // with its DATA chunk header.
        const BYTES_REMAINING_STEP_1: usize = BYTES_REMAINING_STEP_0
            - round_up_to_4!(FIRST_DATA_PAYLOAD_SIZE + data_chunk::HEADER_SIZE);

        // Then a data payload of 957 is to be produced.
        const SECOND_DATA_PAYLOAD_SIZE: usize = 957;

        // This is the amount of space available in the packet after that has been added together
        // with its DATA chunk header.
        const BYTES_REMAINING_STEP_2: usize = BYTES_REMAINING_STEP_1
            - round_up_to_4!(SECOND_DATA_PAYLOAD_SIZE + data_chunk::HEADER_SIZE);

        // The numbers are crafted so that they should really fill the rest of the packet.
        assert_eq!(BYTES_REMAINING_STEP_2, 0);

        sq.add(
            now,
            Message::new(StreamId(1), PpId(53), vec![0; FIRST_DATA_PAYLOAD_SIZE]),
            &SendOptions::default(),
        );
        sq.add(
            now,
            Message::new(StreamId(1), PpId(53), vec![0; SECOND_DATA_PAYLOAD_SIZE]),
            &SendOptions::default(),
        );

        let mut expected_sizes = VecDeque::from(vec![
            BYTES_REMAINING_STEP_0 - data_chunk::HEADER_SIZE,
            BYTES_REMAINING_STEP_1 - data_chunk::HEADER_SIZE,
        ]);
        assert_eq!(
            get_tsns(&rtx.get_chunks_to_send(now, BYTES_REMAINING_STEP_0, |bytes, _| {
                assert_eq!(bytes, expected_sizes.pop_front().unwrap());
                sq.produce(now, bytes)
            })),
            vec![Tsn(10), Tsn(11)]
        );
        assert!(expected_sizes.is_empty());
    }

    #[test]
    fn accounts_nacked_abandoned_chunks_as_not_outstanding() {
        // Verifies that unacked_bytes/unacked_items are set correctly for abandoned items, and when
        // acking them.
        let mut now = START_TIME;
        let events = Rc::new(RefCell::new(Events::new()));
        let events_clone = Rc::clone(&events) as Rc<RefCell<dyn EventSink>>;
        let mut sq = SendQueue::new(MTU, &Options::default(), events_clone);
        let mut rtx = create_queue(true, false, events);

        sq.add(
            now,
            Message::new(StreamId(1), PpId(53), vec![0; 16]),
            &SendOptions { max_retransmissions: Some(0), ..SendOptions::default() },
        );

        assert_eq!(
            get_tsns(&rtx.get_chunks_to_send(now, data_chunk::HEADER_SIZE + 4, |bytes, _| {
                sq.produce(now, bytes)
            })),
            vec![Tsn(10)]
        );
        assert_eq!(
            get_tsns(&rtx.get_chunks_to_send(now, data_chunk::HEADER_SIZE + 4, |bytes, _| {
                sq.produce(now, bytes)
            })),
            vec![Tsn(11)]
        );
        assert_eq!(
            get_tsns(&rtx.get_chunks_to_send(now, data_chunk::HEADER_SIZE + 4, |bytes, _| {
                sq.produce(now, bytes)
            })),
            vec![Tsn(12)]
        );

        assert_eq!(sq.total_buffered_amount(), 4);
        assert_eq!(
            rtx.get_chunk_states_for_testing(),
            [
                (Tsn(9), ChunkState::Acked),
                (Tsn(10), ChunkState::InFlight),
                (Tsn(11), ChunkState::InFlight),
                (Tsn(12), ChunkState::InFlight),
            ]
        );
        assert_eq!(rtx.unacked_bytes(), (data_chunk::HEADER_SIZE + 4) * 3);
        assert_eq!(rtx.unacked_items(), 3);

        // Will force chunks to be retransmitted
        now = rtx.next_timeout().unwrap();
        rtx.handle_timeout(now);
        assert_eq!(
            rtx.get_chunk_states_for_testing(),
            [
                (Tsn(9), ChunkState::Acked),
                (Tsn(10), ChunkState::Abandoned),
                (Tsn(11), ChunkState::Abandoned),
                (Tsn(12), ChunkState::Abandoned),
                (Tsn(13), ChunkState::Abandoned),
            ]
        );
        assert_eq!(rtx.unacked_bytes(), 0);
        assert_eq!(rtx.unacked_items(), 0);

        assert_eq!(
            get_tsns(&rtx.get_chunks_to_send(now, MTU, |bytes, discard| {
                for (stream_id, message_id) in discard {
                    sq.discard(*stream_id, *message_id);
                }
                sq.produce(now, bytes)
            })),
            vec![]
        );
        assert_eq!(sq.total_buffered_amount(), 0);

        // Now ACK those, one at a time.
        handle_sack(&mut rtx, now, Tsn(10));
        assert_eq!(rtx.unacked_bytes(), 0);
        assert_eq!(rtx.unacked_items(), 0);

        handle_sack(&mut rtx, now, Tsn(11));
        assert_eq!(rtx.unacked_bytes(), 0);
        assert_eq!(rtx.unacked_items(), 0);

        handle_sack(&mut rtx, now, Tsn(12));
        assert_eq!(rtx.unacked_bytes(), 0);
        assert_eq!(rtx.unacked_items(), 0);

        handle_sack(&mut rtx, now, Tsn(13));
        assert_eq!(rtx.unacked_bytes(), 0);
        assert_eq!(rtx.unacked_items(), 0);
    }

    #[test]
    fn expire_from_send_queue_when_partially_sent() {
        // Add a 16 byte message, consume 3*4 bytes, leave 4 bytes in the send queue, then expire
        // the message.
        let mut now = START_TIME;
        let events = Rc::new(RefCell::new(Events::new()));
        let events_clone = Rc::clone(&events) as Rc<RefCell<dyn EventSink>>;
        let mut sq = SendQueue::new(MTU, &Options::default(), events_clone);
        let mut rtx = create_queue(true, false, events);

        sq.add(
            now,
            Message::new(StreamId(1), PpId(53), vec![0; 16]),
            &SendOptions { max_retransmissions: Some(0), ..SendOptions::default() },
        );

        assert_eq!(
            get_tsns(&rtx.get_chunks_to_send(now, data_chunk::HEADER_SIZE + 4, |bytes, _| {
                sq.produce(now, bytes)
            })),
            vec![Tsn(10)]
        );
        assert_eq!(
            get_tsns(&rtx.get_chunks_to_send(now, data_chunk::HEADER_SIZE + 4, |bytes, _| {
                sq.produce(now, bytes)
            })),
            vec![Tsn(11)]
        );
        assert_eq!(
            get_tsns(&rtx.get_chunks_to_send(now, data_chunk::HEADER_SIZE + 4, |bytes, _| {
                sq.produce(now, bytes)
            })),
            vec![Tsn(12)]
        );

        assert_eq!(sq.total_buffered_amount(), 4);
        assert_eq!(
            rtx.get_chunk_states_for_testing(),
            [
                (Tsn(9), ChunkState::Acked),
                (Tsn(10), ChunkState::InFlight),
                (Tsn(11), ChunkState::InFlight),
                (Tsn(12), ChunkState::InFlight),
            ]
        );

        // Will force chunks to be abandoned.
        now = rtx.next_timeout().unwrap();
        rtx.handle_timeout(now);
        assert_eq!(
            rtx.get_chunk_states_for_testing(),
            [
                (Tsn(9), ChunkState::Acked),
                (Tsn(10), ChunkState::Abandoned),
                (Tsn(11), ChunkState::Abandoned),
                (Tsn(12), ChunkState::Abandoned),
                (Tsn(13), ChunkState::Abandoned),
            ]
        );
    }

    #[test]
    fn expire_correct_message_from_send_queue() {
        // Add two messages, interleaved, and make sure the right one is discarded when expired.

        let mut now = START_TIME;
        let events = Rc::new(RefCell::new(Events::new()));
        let events_clone = Rc::clone(&events) as Rc<RefCell<dyn EventSink>>;
        let mut sq = SendQueue::new(MTU, &Options::default(), events_clone);
        let mut rtx = create_queue(true, /* use_message_interleaving */ true, events);

        const MAX_SIZE_IN_FRAGMENT: usize = round_down_to_4!(MTU - idata_chunk::HEADER_SIZE);
        sq.enable_message_interleaving(true);
        sq.set_priority(StreamId(1), 1);
        sq.set_priority(StreamId(2), 1);
        sq.add(
            now,
            Message::new(StreamId(1), PpId(53), vec![0; MAX_SIZE_IN_FRAGMENT * 2]),
            &SendOptions { max_retransmissions: Some(0), ..SendOptions::default() },
        );
        sq.add(
            now,
            Message::new(StreamId(2), PpId(54), vec![0; MAX_SIZE_IN_FRAGMENT * 2]),
            &SendOptions::default(),
        );

        let (_, chunk) =
            rtx.get_chunks_to_send(now, MTU, |bytes, _| sq.produce(now, bytes)).pop().unwrap();
        assert_eq!(chunk.stream_key, StreamKey::Ordered(StreamId(1)));
        assert!(!chunk.is_end);

        let (_, chunk) =
            rtx.get_chunks_to_send(now, MTU, |bytes, _| sq.produce(now, bytes)).pop().unwrap();
        assert_eq!(chunk.stream_key, StreamKey::Ordered(StreamId(2)));
        assert!(!chunk.is_end);

        assert_eq!(sq.total_buffered_amount(), MAX_SIZE_IN_FRAGMENT * 2);
        assert_eq!(
            rtx.get_chunk_states_for_testing(),
            [
                (Tsn(9), ChunkState::Acked),
                (Tsn(10), ChunkState::InFlight),
                (Tsn(11), ChunkState::InFlight),
            ]
        );

        now = rtx.next_timeout().unwrap();
        rtx.handle_timeout(now);

        assert_eq!(
            rtx.get_chunk_states_for_testing(),
            [
                (Tsn(9), ChunkState::Acked),
                (Tsn(10), ChunkState::Abandoned),
                (Tsn(11), ChunkState::ToBeRetransmitted),
                (Tsn(12), ChunkState::Abandoned),
            ]
        );

        let mut discarded_stream_ids = Vec::<StreamId>::new();
        rtx.get_chunks_to_send(now, MTU, |bytes, discard| {
            for (stream_id, message_id) in discard {
                discarded_stream_ids.push(*stream_id);
                sq.discard(*stream_id, *message_id);
            }
            sq.produce(now, bytes)
        });
        assert_eq!(discarded_stream_ids, vec![StreamId(1)]);
    }

    #[test]
    fn inserts_placeholder_for_every_discarded_stream() {
        // Add two messages, interleaved. They both expire, and placeholder end chunks should be
        // created for both messages

        let mut now = START_TIME;
        let events = Rc::new(RefCell::new(Events::new()));
        let events_clone = Rc::clone(&events) as Rc<RefCell<dyn EventSink>>;
        let mut sq = SendQueue::new(MTU, &Options::default(), events_clone);
        let mut rtx = create_queue(true, /* use_message_interleaving */ true, events);

        const MAX_SIZE_IN_FRAGMENT: usize = round_down_to_4!(MTU - idata_chunk::HEADER_SIZE);
        sq.enable_message_interleaving(true);
        sq.set_priority(StreamId(1), 1);
        sq.set_priority(StreamId(2), 1);
        sq.add(
            now,
            Message::new(StreamId(1), PpId(53), vec![0; MAX_SIZE_IN_FRAGMENT * 2]),
            &SendOptions { max_retransmissions: Some(0), ..SendOptions::default() },
        );
        sq.add(
            now,
            Message::new(StreamId(2), PpId(54), vec![0; MAX_SIZE_IN_FRAGMENT * 2]),
            &SendOptions { max_retransmissions: Some(0), ..SendOptions::default() },
        );

        let (_, chunk) =
            rtx.get_chunks_to_send(now, MTU, |bytes, _| sq.produce(now, bytes)).pop().unwrap();
        assert_eq!(chunk.stream_key, StreamKey::Ordered(StreamId(1)));
        assert!(!chunk.is_end);

        let (_, chunk) =
            rtx.get_chunks_to_send(now, MTU, |bytes, _| sq.produce(now, bytes)).pop().unwrap();
        assert_eq!(chunk.stream_key, StreamKey::Ordered(StreamId(2)));
        assert!(!chunk.is_end);

        assert_eq!(sq.total_buffered_amount(), MAX_SIZE_IN_FRAGMENT * 2);
        assert_eq!(
            rtx.get_chunk_states_for_testing(),
            [
                (Tsn(9), ChunkState::Acked),
                (Tsn(10), ChunkState::InFlight),
                (Tsn(11), ChunkState::InFlight),
            ]
        );

        now = rtx.next_timeout().unwrap();
        rtx.handle_timeout(now);

        assert_eq!(
            rtx.get_chunk_states_for_testing(),
            [
                (Tsn(9), ChunkState::Acked),
                (Tsn(10), ChunkState::Abandoned),
                (Tsn(11), ChunkState::Abandoned),
                (Tsn(12), ChunkState::Abandoned),
                (Tsn(13), ChunkState::Abandoned),
            ]
        );

        let mut discarded_stream_ids = Vec::<StreamId>::new();
        rtx.get_chunks_to_send(now, MTU, |bytes, discard| {
            for (stream_id, message_id) in discard {
                discarded_stream_ids.push(*stream_id);
                sq.discard(*stream_id, *message_id);
            }
            sq.produce(now, bytes)
        });
        discarded_stream_ids.sort();
        assert_eq!(discarded_stream_ids, vec![StreamId(1), StreamId(2)]);
    }

    #[test]
    fn limits_retransmissions_only_when_nacked_three_times() {
        let now = START_TIME;
        let events = Rc::new(RefCell::new(Events::new()));
        let events_clone = Rc::clone(&events) as Rc<RefCell<dyn EventSink>>;
        let mut sq = SendQueue::new(MTU, &Options::default(), events_clone);
        let mut rtx = create_queue(true, false, Rc::clone(&events));

        for _ in 0..8 {
            sq.add(
                now,
                Message::new(StreamId(1), PpId(53), vec![0; 4]),
                &SendOptions { max_retransmissions: Some(0), ..SendOptions::default() },
            );
        }
        assert_eq!(
            get_tsns(&rtx.get_chunks_to_send(now, MTU, |bytes, _| sq.produce(now, bytes))),
            [Tsn(10), Tsn(11), Tsn(12), Tsn(13), Tsn(14), Tsn(15), Tsn(16), Tsn(17)]
        );

        // Send more chunks, but leave some as gaps to force retransmission after three NACKs.
        add_message(&mut sq, now);
        assert_eq!(
            get_tsns(&rtx.get_chunks_to_send(now, MTU, |bytes, _| sq.produce(now, bytes))),
            [Tsn(18)]
        );

        // Ack 12, 14-15, 17-18
        rtx.handle_sack(
            now,
            &SackChunk {
                cumulative_tsn_ack: Tsn(12),
                a_rwnd: A_RWND,
                gap_ack_blocks: vec![GapAckBlock::new(2, 3), GapAckBlock::new(5, 6)],
                duplicate_tsns: vec![],
            },
        );
        assert!(!rtx.should_send_forward_tsn(now));

        // Send 19
        add_message(&mut sq, now);
        assert_eq!(
            get_tsns(&rtx.get_chunks_to_send(now, MTU, |bytes, _| sq.produce(now, bytes))),
            [Tsn(19)]
        );

        // Ack 12, 14-15, 17-19
        rtx.handle_sack(
            now,
            &SackChunk {
                cumulative_tsn_ack: Tsn(12),
                a_rwnd: A_RWND,
                gap_ack_blocks: vec![GapAckBlock::new(2, 3), GapAckBlock::new(5, 7)],
                duplicate_tsns: vec![],
            },
        );
        assert!(!rtx.should_send_forward_tsn(now));

        // Send 20
        add_message(&mut sq, now);
        assert_eq!(
            get_tsns(&rtx.get_chunks_to_send(now, MTU, |bytes, _| sq.produce(now, bytes))),
            [Tsn(20)]
        );

        // Ack 12, 14-15, 17-20
        rtx.handle_sack(
            now,
            &SackChunk {
                cumulative_tsn_ack: Tsn(12),
                a_rwnd: A_RWND,
                gap_ack_blocks: vec![GapAckBlock::new(2, 3), GapAckBlock::new(5, 8)],
                duplicate_tsns: vec![],
            },
        );

        assert!(rtx.should_send_forward_tsn(now));
    }

    #[test]
    fn abandons_rtx_limit2_when_nacked_nine_times() {
        // Sends a lot of messages with max_retransmissions=2, then let one message become nacked 9
        // times, which will make it abandon at that time.
        let now = START_TIME;
        let events = Rc::new(RefCell::new(Events::new()));
        let events_clone = Rc::clone(&events) as Rc<RefCell<dyn EventSink>>;
        let mut sq = SendQueue::new(MTU, &Options::default(), events_clone);
        let mut rtx = create_queue(true, false, Rc::clone(&events));

        for _ in 0..10 {
            sq.add(
                now,
                Message::new(StreamId(1), PpId(53), vec![0; 4]),
                &SendOptions { max_retransmissions: Some(2), ..SendOptions::default() },
            );
        }
        assert_eq!(
            get_tsns(&rtx.get_chunks_to_send(now, MTU, |bytes, _| sq.produce(now, bytes))),
            (10..=19).map(Tsn).collect::<Vec<_>>()
        );

        for x in 11..=18 {
            // Ack 9, 11->x->18
            rtx.handle_sack(
                now,
                &SackChunk {
                    cumulative_tsn_ack: Tsn(9),
                    a_rwnd: A_RWND,
                    gap_ack_blocks: vec![GapAckBlock::new(2, x - 9)],
                    duplicate_tsns: vec![],
                },
            );
            assert!(!rtx.should_send_forward_tsn(now));

            // Retransmit any chunks.
            if rtx.has_data_to_be_fast_retransmitted() {
                rtx.get_chunks_for_fast_retransmit(now, MTU);
            } else {
                rtx.get_chunks_to_send(now, MTU, |bytes, _| sq.produce(now, bytes));
            }
        }

        // 9th time for TSN=10.
        rtx.handle_sack(
            now,
            &SackChunk {
                cumulative_tsn_ack: Tsn(9),
                a_rwnd: A_RWND,
                gap_ack_blocks: vec![GapAckBlock::new(2, 10)],
                duplicate_tsns: vec![],
            },
        );
        assert!(rtx.should_send_forward_tsn(now));
        assert_eq!(
            rtx.get_chunk_states_for_testing(),
            [
                (Tsn(9), ChunkState::Acked),
                (Tsn(10), ChunkState::Abandoned),
                (Tsn(11), ChunkState::Acked),
                (Tsn(12), ChunkState::Acked),
                (Tsn(13), ChunkState::Acked),
                (Tsn(14), ChunkState::Acked),
                (Tsn(15), ChunkState::Acked),
                (Tsn(16), ChunkState::Acked),
                (Tsn(17), ChunkState::Acked),
                (Tsn(18), ChunkState::Acked),
                (Tsn(19), ChunkState::Acked),
            ]
        );
    }

    #[test]
    fn cwnd_recovers_when_acking() {
        let now = START_TIME;
        let events = Rc::new(RefCell::new(Events::new()));
        let events_clone = Rc::clone(&events) as Rc<RefCell<dyn EventSink>>;
        let mut sq = SendQueue::new(MTU, &Options::default(), events_clone);
        let mut rtx = create_queue(/* supports_partial_reliability */ true, false, events);
        const CWND: usize = 1200;

        rtx.set_cwnd(CWND);

        sq.add(
            now,
            Message::new(StreamId(1), PpId(53), vec![0; 1000]),
            &SendOptions { max_retransmissions: Some(3), ..SendOptions::default() },
        );

        assert_eq!(
            get_tsns(&rtx.get_chunks_to_send(now, 1500, |bytes, _| sq.produce(now, bytes))),
            [Tsn(10)]
        );
        assert_eq!(rtx.unacked_bytes(), 1000 + data_chunk::HEADER_SIZE);

        handle_sack(&mut rtx, now, Tsn(10));

        assert_eq!(rtx.cwnd(), CWND + 1000 + data_chunk::HEADER_SIZE);
    }

    #[test]
    fn ready_for_handover_when_has_no_outstanding_data() {
        let now = START_TIME;
        let events = Rc::new(RefCell::new(Events::new()));
        let events_clone = Rc::clone(&events) as Rc<RefCell<dyn EventSink>>;
        let mut sq = SendQueue::new(MTU, &Options::default(), events_clone);
        let mut rtx = create_queue(/* supports_partial_reliability */ true, false, events);

        assert!(rtx.get_handover_readiness().is_ready());
        add_message(&mut sq, now);

        assert_eq!(
            get_tsns(&rtx.get_chunks_to_send(now, 1500, |bytes, _| sq.produce(now, bytes))),
            [Tsn(10)]
        );
        assert!(
            rtx.get_handover_readiness()
                .contains(HandoverReadiness::RETRANSMISSION_QUEUE_OUTSTANDING_DATA)
        );

        handle_sack(&mut rtx, now, Tsn(10));
        assert!(rtx.get_handover_readiness().is_ready());
    }

    #[test]
    fn ready_for_handover_when_nothing_to_retransmit() {
        // This is a variant of `test_resend_packets_when_nacked_three_times`` that verifies that
        // the queue is not ready for handover in some scenarios.
        let now = START_TIME;
        let events = Rc::new(RefCell::new(Events::new()));
        let events_clone = Rc::clone(&events) as Rc<RefCell<dyn EventSink>>;
        let mut sq = SendQueue::new(MTU, &Options::default(), events_clone);
        let mut rtx = create_queue(false, false, Rc::clone(&events));

        for _ in 0..8 {
            add_message(&mut sq, now);
        }
        assert_eq!(
            get_tsns(&rtx.get_chunks_to_send(now, MTU, |bytes, _| sq.produce(now, bytes))),
            [Tsn(10), Tsn(11), Tsn(12), Tsn(13), Tsn(14), Tsn(15), Tsn(16), Tsn(17)]
        );
        assert_eq!(
            rtx.get_handover_readiness(),
            HandoverReadiness::RETRANSMISSION_QUEUE_OUTSTANDING_DATA
        );

        // Send more chunks, but leave some as gaps to force retransmission after three NACKs.
        add_message(&mut sq, now);
        assert_eq!(
            get_tsns(&rtx.get_chunks_to_send(now, MTU, |bytes, _| sq.produce(now, bytes))),
            [Tsn(18)]
        );

        // Ack 12, 14-15, 17-18
        rtx.handle_sack(
            now,
            &SackChunk {
                cumulative_tsn_ack: Tsn(12),
                a_rwnd: A_RWND,
                gap_ack_blocks: vec![GapAckBlock::new(2, 3), GapAckBlock::new(5, 6)],
                duplicate_tsns: vec![],
            },
        );

        // Send 19
        add_message(&mut sq, now);
        assert_eq!(
            get_tsns(&rtx.get_chunks_to_send(now, MTU, |bytes, _| sq.produce(now, bytes))),
            [Tsn(19)]
        );

        // Ack 12, 14-15, 17-19
        rtx.handle_sack(
            now,
            &SackChunk {
                cumulative_tsn_ack: Tsn(12),
                a_rwnd: A_RWND,
                gap_ack_blocks: vec![GapAckBlock::new(2, 3), GapAckBlock::new(5, 7)],
                duplicate_tsns: vec![],
            },
        );

        // Send 20
        add_message(&mut sq, now);
        assert_eq!(
            get_tsns(&rtx.get_chunks_to_send(now, MTU, |bytes, _| sq.produce(now, bytes))),
            [Tsn(20)]
        );

        // Ack 12, 14-15, 17-20
        rtx.handle_sack(
            now,
            &SackChunk {
                cumulative_tsn_ack: Tsn(12),
                a_rwnd: A_RWND,
                gap_ack_blocks: vec![GapAckBlock::new(2, 3), GapAckBlock::new(5, 8)],
                duplicate_tsns: vec![],
            },
        );

        assert_eq!(
            rtx.get_handover_readiness(),
            HandoverReadiness::RETRANSMISSION_QUEUE_OUTSTANDING_DATA
                | HandoverReadiness::RETRANSMISSION_QUEUE_NOT_EMPTY
                | HandoverReadiness::RETRANSMISSION_QUEUE_FAST_RECOVERY
        );

        // This will trigger "fast retransmit" mode and only chunks 13 and 16 will be resent.
        assert_eq!(get_tsns(&rtx.get_chunks_for_fast_retransmit(now, MTU)), vec![Tsn(13), Tsn(16)]);

        assert_eq!(
            rtx.get_handover_readiness(),
            HandoverReadiness::RETRANSMISSION_QUEUE_OUTSTANDING_DATA
                | HandoverReadiness::RETRANSMISSION_QUEUE_FAST_RECOVERY
        );

        handle_sack(&mut rtx, now, Tsn(20));
        assert!(rtx.get_handover_readiness().is_ready());
    }

    fn handover_queue(
        rtx: RetransmissionQueue,
        events: Rc<RefCell<Events>>,
    ) -> RetransmissionQueue {
        assert!(rtx.get_handover_readiness().is_ready());
        let mut state = SocketHandoverState::default();
        rtx.add_to_handover_state(&mut state);

        let mut rtx = create_queue(false, false, events);
        rtx.restore_from_state(&state);
        rtx
    }

    #[test]
    fn handover_test() {
        // This is a variant of `test_resend_packets_when_nacked_three_times` that verifies that the
        // queue is not ready for handover in some scenarios.
        let now = START_TIME;
        let events = Rc::new(RefCell::new(Events::new()));
        let events_clone = Rc::clone(&events) as Rc<RefCell<dyn EventSink>>;
        let mut sq = SendQueue::new(MTU, &Options::default(), events_clone);
        let mut rtx = create_queue(false, false, Rc::clone(&events));

        add_message(&mut sq, now);
        add_message(&mut sq, now);

        assert_eq!(
            get_tsns(&rtx.get_chunks_to_send(now, MTU, |bytes, _| sq.produce(now, bytes))),
            [Tsn(10), Tsn(11)]
        );

        handle_sack(&mut rtx, now, Tsn(11));

        let mut rtx = handover_queue(rtx, Rc::clone(&events));
        add_message(&mut sq, now);
        add_message(&mut sq, now);
        add_message(&mut sq, now);

        assert_eq!(
            get_tsns(&rtx.get_chunks_to_send(now, MTU, |bytes, _| sq.produce(now, bytes))),
            [Tsn(12), Tsn(13), Tsn(14)]
        );

        handle_sack(&mut rtx, now, Tsn(13));
        assert_eq!(
            rtx.get_chunk_states_for_testing(),
            [(Tsn(13), ChunkState::Acked), (Tsn(14), ChunkState::InFlight),]
        );
    }

    #[test]
    fn can_always_send_one_packet() {
        let mut now = START_TIME;
        let options = Options { mtu: MTU, ..Default::default() };
        let events = Rc::new(RefCell::new(Events::new()));
        let events_clone = Rc::clone(&events) as Rc<RefCell<dyn EventSink>>;
        let mut sq = SendQueue::new(MTU, &options, events_clone);
        let mut rtx = RetransmissionQueue::new(events, Tsn(10), A_RWND, &options, false, false);

        const MAX_SIZE_IN_FRAGMENT: usize = round_down_to_4!(MTU - data_chunk::HEADER_SIZE);
        for tsn in 10..=14 {
            sq.add(
                now,
                Message::new(StreamId(1), PpId(53), vec![0; MAX_SIZE_IN_FRAGMENT]),
                &SendOptions::default(),
            );
            assert_eq!(
                get_tsns(&rtx.get_chunks_to_send(now, MTU, |bytes, _| sq.produce(now, bytes))),
                [Tsn(tsn)]
            );
        }

        // Ack 12, and report an empty receiver window (the peer obviously has a tiny receive
        // window).
        rtx.handle_sack(
            now,
            &SackChunk {
                cumulative_tsn_ack: Tsn(9),
                a_rwnd: 0,
                gap_ack_blocks: vec![GapAckBlock::new(3, 3)],
                duplicate_tsns: vec![],
            },
        );

        // Force TSN 10 to be retransmitted.
        now = rtx.next_timeout().unwrap();
        rtx.handle_timeout(now);

        assert_eq!(
            rtx.get_chunk_states_for_testing(),
            [
                (Tsn(9), ChunkState::Acked),
                (Tsn(10), ChunkState::ToBeRetransmitted),
                (Tsn(11), ChunkState::ToBeRetransmitted),
                (Tsn(12), ChunkState::Acked),
                (Tsn(13), ChunkState::ToBeRetransmitted),
                (Tsn(14), ChunkState::ToBeRetransmitted),
            ]
        );
        // Even if the receiver window is empty, it will allow TSN 10 to be sent.
        let c = rtx.get_chunks_to_send(now, MTU, |bytes, _| sq.produce(now, bytes));
        assert_eq!(get_tsns(&c), [Tsn(10)]);

        // But not more than that, as there now is outstanding data.
        assert!(rtx.get_chunks_to_send(now, MTU, |bytes, _| sq.produce(now, bytes)).is_empty());

        // Don't ack any new data, and still have receiver window zero.
        rtx.handle_sack(
            now,
            &SackChunk {
                cumulative_tsn_ack: Tsn(9),
                a_rwnd: 0,
                gap_ack_blocks: vec![GapAckBlock::new(3, 3)],
                duplicate_tsns: vec![],
            },
        );

        // There is in-flight data, so new data should not be allowed to be send since the receiver
        // window is full.
        assert!(rtx.get_chunks_to_send(now, MTU, |bytes, _| sq.produce(now, bytes)).is_empty());

        rtx.handle_sack(
            now,
            &SackChunk {
                cumulative_tsn_ack: Tsn(9),
                a_rwnd: 0,
                gap_ack_blocks: vec![GapAckBlock::new(3, 3)],
                duplicate_tsns: vec![],
            },
        );
        rtx.handle_sack(
            now,
            &SackChunk {
                cumulative_tsn_ack: Tsn(10),
                a_rwnd: 0,
                gap_ack_blocks: vec![GapAckBlock::new(2, 2)],
                duplicate_tsns: vec![],
            },
        );

        // Then TSN 11 can be sent, as there is no in-flight data.
        let c = rtx.get_chunks_to_send(now, MTU, |bytes, _| sq.produce(now, bytes));
        assert_eq!(get_tsns(&c), [Tsn(11)]);

        assert!(rtx.get_chunks_to_send(now, MTU, |bytes, _| sq.produce(now, bytes)).is_empty());

        // Ack and recover the receiver window
        rtx.handle_sack(
            now,
            &SackChunk {
                cumulative_tsn_ack: Tsn(12),
                a_rwnd: (5 * MTU) as u32,
                gap_ack_blocks: vec![],
                duplicate_tsns: vec![],
            },
        );

        // That will unblock sending remaining chunks.
        let c = rtx.get_chunks_to_send(now, MTU, |bytes, _| sq.produce(now, bytes));
        assert_eq!(get_tsns(&c), [Tsn(13)]);
        let c = rtx.get_chunks_to_send(now, MTU, |bytes, _| sq.produce(now, bytes));
        assert_eq!(get_tsns(&c), [Tsn(14)]);
        assert!(rtx.get_chunks_to_send(now, MTU, |bytes, _| sq.produce(now, bytes)).is_empty());
    }
}
