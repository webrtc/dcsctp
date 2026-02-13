// Copyright 2026 The dcSCTP Authors
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
use crate::api::ErrorKind;
use crate::api::Options;
use crate::api::SctpImplementation;
use crate::api::SocketEvent;
use crate::api::SocketTime;
use crate::packet::chunk::Chunk;
use crate::packet::sctp_packet::SctpPacketBuilder;
use crate::socket::State;
use crate::socket::transmission_control_block::CurrentResetRequest;
use crate::timer::Timer;
use crate::tx::send_queue::SendQueue;
use std::cell::RefCell;
use std::cmp::min;
use std::rc::Rc;
use std::time::Duration;

pub(crate) struct TxErrorCounter {
    error_counter: u32,
    limit: Option<u32>,
}

impl TxErrorCounter {
    pub fn new(limit: Option<u32>) -> Self {
        Self { error_counter: 0, limit }
    }

    pub fn increment(&mut self) {
        match self.limit {
            Some(limit) if self.error_counter <= limit => {
                self.error_counter += 1;
            }
            _ => {}
        }
    }

    pub fn reset(&mut self) {
        self.error_counter = 0;
    }

    pub fn is_exhausted(&self) -> bool {
        if let Some(limit) = self.limit { self.error_counter > limit } else { false }
    }
}

pub(crate) struct Context {
    pub options: Options,
    pub events: Rc<RefCell<dyn EventSink>>,
    pub send_queue: SendQueue,

    pub limit_forward_tsn_until: SocketTime,

    pub heartbeat_interval: Timer,
    pub heartbeat_timeout: Timer,
    pub heartbeat_counter: u32,
    pub heartbeat_sent_time: SocketTime,

    pub rx_packets_count: usize,
    pub tx_packets_count: usize,
    pub tx_messages_count: usize,
    pub peer_implementation: SctpImplementation,

    pub tx_error_counter: TxErrorCounter,
}

impl Context {
    pub fn send_buffered_packets(&mut self, state: &mut State, now: SocketTime) {
        if let Some(tcb) = &state.tcb_mut() {
            let mut packet = tcb.new_packet();
            self.send_buffered_packets_with(state, now, &mut packet);
        }
    }

    /// Given a builder that is either empty, or only contains control chunks, add more control
    /// chunks and data chunks to it, and send it and possibly more packets, as is allowed by the
    /// congestion window.
    pub fn send_buffered_packets_with(
        &mut self,
        state: &mut State,
        now: SocketTime,
        builder: &mut SctpPacketBuilder,
    ) {
        for packet_idx in 0..self.options.max_burst {
            if let Some(tcb) = state.tcb_mut() {
                if packet_idx == 0 {
                    // Add SACKs if it's likely that a DATA chunk would also be added.
                    let also_if_delayed = self.send_queue.has_data_to_send()
                        || tcb.retransmission_queue.can_send_data();
                    if tcb.data_tracker.should_send_ack(now, also_if_delayed) {
                        builder.add(
                            &Chunk::Sack(tcb.data_tracker.create_selective_ack(
                                tcb.reassembly_queue.remaining_bytes() as u32,
                            )),
                        );
                    }
                    if now >= self.limit_forward_tsn_until
                        && tcb.retransmission_queue.should_send_forward_tsn(now)
                    {
                        builder.add(&tcb.retransmission_queue.create_forward_tsn());
                        // From <https://datatracker.ietf.org/doc/html/rfc3758#section-3.5>:
                        //
                        //   IMPLEMENTATION NOTE: An implementation may wish to limit the number of
                        //   duplicate FORWARD TSN chunks it sends by [...] waiting a full RTT
                        //   before sending a duplicate FORWARD TSN. [...] Any delay applied to the
                        //   sending of FORWARD TSN chunk SHOULD NOT exceed 200ms and MUST NOT
                        //   exceed 500ms.
                        self.limit_forward_tsn_until =
                            now + min(Duration::from_millis(200), tcb.rto.srtt());
                    }

                    if matches!(tcb.current_reset_request, CurrentResetRequest::None)
                        && self.send_queue.has_streams_ready_to_be_reset()
                    {
                        tcb.start_ssn_reset_request(
                            now,
                            self.send_queue.get_streams_ready_to_reset(),
                            builder,
                        );
                    }
                }
                let chunks = tcb.retransmission_queue.get_chunks_to_send(
                    now,
                    builder.bytes_remaining(),
                    |max_size, discard| {
                        for (stream_id, message_id) in discard {
                            self.send_queue.discard(*stream_id, *message_id);
                        }
                        self.send_queue.produce(now, max_size)
                    },
                );

                if !chunks.is_empty() {
                    // Sending data means that the path is not idle - restart heartbeat timer.
                    self.heartbeat_interval.start(now);
                }

                for (tsn, data) in chunks {
                    builder.add(&tcb.make_data_chunk(tsn, data));
                }
            }

            if builder.is_empty() {
                break;
            }
            self.events.borrow_mut().add(SocketEvent::SendPacket(builder.build()));
            self.tx_packets_count += 1;

            // From <https://datatracker.ietf.org/doc/html/rfc9260#section-5.1-2.3.2>:
            //
            //   [...] until the COOKIE ACK chunk is returned, the sender MUST NOT send any other
            //   packets to the peer.
            //
            // Let the cookie echo timeout drive sending that chunk and any data
            if matches!(state, State::CookieEchoed(_)) {
                return;
            }
        }
    }

    pub fn internal_close(&mut self, state: &mut State, error: ErrorKind, message: String) {
        if !matches!(state, State::Closed) {
            self.heartbeat_interval.stop();
            self.heartbeat_timeout.stop();
            if error == ErrorKind::NoError {
                self.events.borrow_mut().add(SocketEvent::OnClosed());
            } else {
                self.events.borrow_mut().add(SocketEvent::OnAborted(error, message));
            }
            *state = State::Closed;
        }
    }
}
