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
use crate::api::BatchSendError;
use crate::api::DcSctpSocket;
use crate::api::ErrorKind;
use crate::api::HandoverError;
use crate::api::Message;
use crate::api::Metrics;
use crate::api::Options;
use crate::api::ResetStreamsError;
use crate::api::RestoreError;
use crate::api::SctpImplementation;
use crate::api::SendError;
use crate::api::SendOptions;
use crate::api::SocketEvent;
use crate::api::SocketState;
use crate::api::SocketTime;
use crate::api::StreamId;
use crate::api::handover::HandoverReadiness;
use crate::api::handover::HandoverSocketState;
use crate::api::handover::SocketHandoverState;
use crate::events::Events;
use crate::logging::log_packet;
use crate::packet::SerializableTlv;
use crate::packet::abort_chunk::AbortChunk;
use crate::packet::chunk::Chunk;
use crate::packet::data_chunk;
use crate::packet::data_chunk::DataChunk;
use crate::packet::error_causes::ErrorCause;
use crate::packet::error_chunk::ErrorChunk;
use crate::packet::forward_tsn_chunk::ForwardTsnChunk;
use crate::packet::idata_chunk::IDataChunk;
use crate::packet::iforward_tsn_chunk::IForwardTsnChunk;
use crate::packet::sctp_packet;
use crate::packet::sctp_packet::SctpPacket;
use crate::packet::unknown_chunk::UnknownChunk;
use crate::packet::unrecognized_chunk_error_cause::UnrecognizedChunkErrorCause;
use crate::packet::user_initiated_abort_error_cause::UserInitiatedAbortErrorCause;
use crate::socket::capabilities::Capabilities;
use crate::socket::connect::do_connect;
use crate::socket::connect::handle_cookie_ack;
use crate::socket::connect::handle_cookie_echo;
use crate::socket::connect::handle_init;
use crate::socket::connect::handle_init_ack;
use crate::socket::connect::handle_t1cookie_timeout;
use crate::socket::connect::handle_t1init_timeout;
use crate::socket::context::Context;
use crate::socket::context::TxErrorCounter;
use crate::socket::data::handle_data;
use crate::socket::data::handle_forward_tsn;
use crate::socket::data::handle_sack;
use crate::socket::data::maybe_send_sack;
use crate::socket::data::validate_send;
use crate::socket::heartbeat::handle_heartbeat_ack;
use crate::socket::heartbeat::handle_heartbeat_req;
use crate::socket::heartbeat::handle_heartbeat_timeouts;
use crate::socket::shutdown::do_shutdown;
use crate::socket::shutdown::handle_shutdown;
use crate::socket::shutdown::handle_shutdown_ack;
use crate::socket::shutdown::handle_shutdown_complete;
use crate::socket::shutdown::handle_t2_shutdown_timeout;
use crate::socket::shutdown::maybe_send_shutdown_on_packet_received;
use crate::socket::state::ShutdownSentState;
use crate::socket::state::State;
use crate::socket::stream_reset::do_reset_streams;
use crate::socket::stream_reset::handle_reconfig;
use crate::socket::stream_reset::handle_reconfig_timeout;
use crate::socket::transmission_control_block::TransmissionControlBlock;
use crate::timer::BackoffAlgorithm;
use crate::timer::Timer;
use crate::tx::send_queue::SendQueue;
use crate::types::Tsn;
#[cfg(not(test))]
use log::info;
#[cfg(not(test))]
use log::warn;
use std::cell::RefCell;
use std::cmp::min;
#[cfg(test)]
use std::println as info;
#[cfg(test)]
use std::println as warn;
use std::rc::Rc;

pub mod capabilities;
pub mod connect;
pub mod context;
pub mod data;
pub mod heartbeat;
pub mod shutdown;
pub mod state;
pub mod state_cookie;
pub mod stream_reset;
pub mod transmission_control_block;

#[cfg(test)]
pub mod socket_tests;

struct LoggingEvents {
    parent: Rc<RefCell<dyn EventSink>>,
    name: String,
    now: Rc<RefCell<SocketTime>>,
}

impl LoggingEvents {
    pub fn new(
        parent: Rc<RefCell<dyn EventSink>>,
        name: String,
        now: Rc<RefCell<SocketTime>>,
    ) -> LoggingEvents {
        Self { parent, name, now }
    }
}

impl EventSink for LoggingEvents {
    fn add(&mut self, event: SocketEvent) {
        match event {
            SocketEvent::SendPacket(ref e) => {
                let now = *self.now.borrow();
                log_packet(&self.name, now, true, e);
            }
            SocketEvent::OnConnected() => info!("OnConnected"),
            SocketEvent::OnError(kind, ref e) => info!("OnError: {:?}, {}", kind, e),
            SocketEvent::OnBufferedAmountLow(e) => info!("OnBufferedAmountLow: {}", e),
            SocketEvent::OnTotalBufferedAmountLow() => info!("OnTotalBufferedAmountLow"),
            SocketEvent::OnLifecycleMessageFullySent(ref id) => {
                info!("OnLifecycleMessageFullySent({})", id);
            }
            SocketEvent::OnLifecycleMessageExpired(ref id) => {
                info!("OnLifecycleMessageExpired({})", id);
            }
            SocketEvent::OnLifecycleMessageMaybeExpired(ref id) => {
                info!("OnLifecycleMessageMaybeExpired({})", id);
            }
            SocketEvent::OnLifecycleMessageDelivered(ref id) => {
                info!("OnLifecycleMessageDelivered({})", id);
            }
            SocketEvent::OnLifecycleEnd(ref id) => {
                info!("OnLifecycleEnd({})", id);
            }
            SocketEvent::OnStreamsResetFailed(ref streams) => {
                info!("OnStreamsResetFailed({:?})", streams);
            }
            SocketEvent::OnStreamsResetPerformed(ref streams) => {
                info!("OnStreamsResetPerformed({:?})", streams);
            }
            SocketEvent::OnIncomingStreamReset(ref streams) => {
                info!("OnIncomingStreamReset({:?})", streams);
            }
            SocketEvent::OnClosed() => {
                info!("OnClosed()");
            }
            SocketEvent::OnAborted(ref error, ref reason) => {
                info!("OnAborted({:?}, {})", error, reason);
            }
            SocketEvent::OnConnectionRestarted() => {
                info!("OnConnectionRestarted()");
            }
        }
        self.parent.borrow_mut().add(event);
    }

    fn next_event(&mut self) -> Option<SocketEvent> {
        self.parent.borrow_mut().next_event()
    }
}

/// An SCTP socket.
///
/// The socket is the main entry point for using the `dcsctp` library. It is used to send and
/// receive messages, and to manage the connection.
///
/// To create a socket, use the [`Socket::new`] method.
pub struct Socket {
    name: String,
    now: Rc<RefCell<SocketTime>>,
    state: State,
    ctx: Context,
}

fn closest_timeout(a: Option<SocketTime>, b: Option<SocketTime>) -> Option<SocketTime> {
    match (a, b) {
        (None, None) => None,
        (None, Some(_)) => b,
        (Some(_), None) => a,
        (Some(t1), Some(t2)) => Some(min(t1, t2)),
    }
}

impl Socket {
    /// Creates a new `Socket`.
    ///
    /// The provided `name` is only used for logging to identify this socket, and `start_time`
    /// is the initial time, used as a basline for all time-based operations.
    pub fn new(name: &str, options: &Options) -> Self {
        let now = Rc::new(RefCell::new(SocketTime::zero()));
        let events: Rc<RefCell<Events>> = Rc::new(RefCell::new(Events::new()));
        let events: Rc<RefCell<dyn EventSink>> =
            Rc::new(RefCell::new(LoggingEvents::new(events, name.into(), Rc::clone(&now))));
        let sqe = Rc::clone(&events);
        let ctx = Context {
            options: options.clone(),
            events,
            send_queue: SendQueue::new(options.mtu, options, sqe),
            limit_forward_tsn_until: SocketTime::zero(),
            heartbeat_interval: Timer::new(
                options.heartbeat_interval,
                BackoffAlgorithm::Fixed,
                None,
                None,
            ),
            heartbeat_timeout: Timer::new(
                options.rto_initial,
                BackoffAlgorithm::Exponential,
                Some(0),
                None,
            ),
            heartbeat_counter: 0,
            heartbeat_sent_time: SocketTime::zero(),
            rx_packets_count: 0,
            tx_packets_count: 0,
            tx_messages_count: 0,
            peer_implementation: SctpImplementation::Unknown,
            tx_error_counter: TxErrorCounter::new(options.max_retransmissions),
        };
        Socket { name: name.into(), now, state: State::Closed, ctx }
    }

    fn handle_abort(&mut self, chunk: AbortChunk) {
        if self.state.tcb().is_none() {
            // From <https://datatracker.ietf.org/doc/html/rfc9260#section-3.3.7>:
            //
            //   If an endpoint receives an ABORT chunk with a format error or no TCB is found, it
            //   MUST silently discard it.
            return;
        }
        let reason =
            chunk.error_causes.into_iter().map(|c| c.to_string()).collect::<Vec<_>>().join(",");
        self.ctx.internal_close(&mut self.state, ErrorKind::PeerReported, reason);
    }

    fn handle_error(&mut self, chunk: ErrorChunk) {
        if self.state.tcb().is_none() {
            return;
        }
        let message =
            chunk.error_causes.into_iter().map(|c| c.to_string()).collect::<Vec<_>>().join(",");
        self.ctx.events.borrow_mut().add(SocketEvent::OnError(ErrorKind::PeerReported, message));
    }

    pub fn verification_tag(&self) -> u32 {
        self.state.tcb().map_or(0, |tcb| tcb.my_verification_tag)
    }

    fn handle_unrecognized_chunk(&mut self, chunk: UnknownChunk) -> bool {
        // From <https://datatracker.ietf.org/doc/html/rfc9260#section-3.2-3.2.5>:
        //
        //   Chunk Types are encoded such that the highest-order 2 bits specify the action that is
        //   taken if the processing endpoint does not recognize the Chunk Type.
        let typ = chunk.typ;
        let report_as_error = (typ & 0x40) != 0;
        let continue_processing = (typ & 0x80) != 0;
        if report_as_error {
            self.ctx
                .events
                .borrow_mut()
                .add(SocketEvent::OnError(ErrorKind::ParseFailed, format!("Received {}, ", chunk)));
            // From <https://datatracker.ietf.org/doc/html/rfc9260#section-3.2-3.2.6.1.2.2.1>:
            //
            //   [...] report the unrecognized chunk in an ERROR chunk using the 'Unrecognized Chunk
            //   Type' error cause.
            if let Some(tcb) = self.state.tcb() {
                let mut serialized = vec![0; chunk.serialized_size()];
                chunk.serialize_to(&mut serialized);
                self.ctx.events.borrow_mut().add(SocketEvent::SendPacket(
                    tcb.new_packet()
                        .add(&Chunk::Error(ErrorChunk {
                            error_causes: vec![ErrorCause::UnrecognizedChunk(
                                UnrecognizedChunkErrorCause { chunk: serialized },
                            )],
                        }))
                        .build(),
                ));
                self.ctx.tx_packets_count += 1;
            }
        }
        continue_processing
    }
}

impl DcSctpSocket for Socket {
    fn poll_event(&mut self) -> Option<SocketEvent> {
        self.ctx.events.borrow_mut().next_event()
    }

    fn get_next_message(&mut self) -> Option<Message> {
        self.state.tcb_mut()?.reassembly_queue.get_next_message()
    }

    fn connect(&mut self) {
        let State::Closed = self.state else {
            warn!("Called connect on a socket that is not closed");
            return;
        };
        let now = *self.now.borrow();
        do_connect(&mut self.state, &mut self.ctx, now);
    }

    fn handle_input(&mut self, packet: &[u8]) {
        self.ctx.rx_packets_count += 1;
        let now = *self.now.borrow();
        log_packet(&self.name, now, false, packet);

        match SctpPacket::from_bytes(packet, &self.ctx.options) {
            Err(_e) => {
                self.ctx.events.borrow_mut().add(SocketEvent::OnError(
                    ErrorKind::ParseFailed,
                    "Failed to parse SCTP packet".into(),
                ));
            }
            Ok(packet) => {
                maybe_send_shutdown_on_packet_received(
                    &mut self.state,
                    &mut self.ctx,
                    now,
                    &packet.chunks,
                );
                for chunk in packet.chunks {
                    match chunk {
                        Chunk::Data(DataChunk { tsn, data })
                        | Chunk::IData(IDataChunk { tsn, data }) => {
                            handle_data(&mut self.state, &mut self.ctx, now, tsn, data);
                        }
                        Chunk::Init(c) => handle_init(&mut self.state, &mut self.ctx, c),
                        Chunk::InitAck(c) => {
                            handle_init_ack(&mut self.state, &mut self.ctx, now, c);
                        }
                        Chunk::Sack(c) => handle_sack(&mut self.state, &mut self.ctx, now, c),
                        Chunk::Abort(c) => self.handle_abort(c),
                        Chunk::Shutdown(_) => handle_shutdown(&mut self.state, &mut self.ctx),
                        Chunk::ShutdownAck(_) => handle_shutdown_ack(
                            &mut self.state,
                            &mut self.ctx,
                            &packet.common_header,
                        ),
                        Chunk::Error(c) => self.handle_error(c),
                        Chunk::CookieEcho(c) => {
                            handle_cookie_echo(
                                &mut self.state,
                                &mut self.ctx,
                                now,
                                &packet.common_header,
                                c,
                            );
                        }
                        Chunk::CookieAck(_) => {
                            handle_cookie_ack(&mut self.state, &mut self.ctx, now);
                        }
                        Chunk::HeartbeatRequest(c) => {
                            handle_heartbeat_req(&mut self.state, &mut self.ctx, c);
                        }
                        Chunk::HeartbeatAck(c) => handle_heartbeat_ack(&mut self.ctx, now, c),
                        Chunk::ShutdownComplete(c) => {
                            handle_shutdown_complete(&mut self.state, &mut self.ctx, c);
                        }
                        Chunk::ReConfig(c) => {
                            handle_reconfig(&mut self.state, &mut self.ctx, now, c);
                        }
                        Chunk::ForwardTsn(ForwardTsnChunk {
                            new_cumulative_tsn,
                            skipped_streams,
                        })
                        | Chunk::IForwardTsn(IForwardTsnChunk {
                            new_cumulative_tsn,
                            skipped_streams,
                        }) => handle_forward_tsn(
                            &mut self.state,
                            now,
                            new_cumulative_tsn,
                            skipped_streams,
                        ),
                        Chunk::Unknown(c) => {
                            if !self.handle_unrecognized_chunk(c) {
                                break;
                            }
                        }
                    }
                }
                maybe_send_sack(&mut self.state, &mut self.ctx, now);
            }
        }
    }

    fn advance_time(&mut self, now: SocketTime) {
        if now < *self.now.borrow() {
            // Time is not allowed to go backwards.
            return;
        }
        self.now.replace(now);
        match &mut self.state {
            State::Closed => {}
            &mut State::CookieWait(ref s) => {
                debug_assert!(s.t1_init.is_running());
                handle_t1init_timeout(&mut self.state, &mut self.ctx, now);
            }
            State::CookieEchoed(s) => {
                // NOTE: Only let the t1-cookie timer drive retransmissions.
                debug_assert!(s.t1_cookie.is_running());
                s.tcb.data_tracker.handle_timeout(now);
                handle_t1cookie_timeout(&mut self.state, &mut self.ctx, now);
            }
            State::Established(tcb)
            | State::ShutdownPending(tcb)
            | State::ShutdownSent(ShutdownSentState { tcb, .. })
            | State::ShutdownReceived(tcb)
            | State::ShutdownAckSent(tcb) => {
                tcb.data_tracker.handle_timeout(now);
                if tcb.retransmission_queue.handle_timeout(now) {
                    self.ctx.tx_error_counter.increment();
                }
                handle_heartbeat_timeouts(&mut self.state, &mut self.ctx, now);
                handle_reconfig_timeout(&mut self.state, &mut self.ctx, now);
                handle_t2_shutdown_timeout(&mut self.state, &mut self.ctx, now);
            }
        }
        if let Some(tcb) = self.state.tcb_mut() {
            if self.ctx.tx_error_counter.is_exhausted() {
                self.ctx.events.borrow_mut().add(SocketEvent::SendPacket(
                    tcb.new_packet()
                        .add(&Chunk::Abort(AbortChunk {
                            error_causes: vec![ErrorCause::UserInitiatedAbort(
                                UserInitiatedAbortErrorCause {
                                    reason: "Too many retransmissions".into(),
                                },
                            )],
                        }))
                        .build(),
                ));
                self.ctx.tx_packets_count += 1;
                self.ctx.internal_close(
                    &mut self.state,
                    ErrorKind::TooManyRetries,
                    "Too many retransmissions".into(),
                );
                return;
            }

            // From <https://datatracker.ietf.org/doc/html/rfc9260#section-5.1-2.3.2>:
            //
            //   [...] until the COOKIE ACK chunk is returned, the sender MUST NOT send any other
            //   packets to the peer.
            if !matches!(self.state, State::CookieEchoed(_)) {
                self.ctx.send_buffered_packets(&mut self.state, now);
            }
        }
    }

    fn poll_timeout(&self) -> SocketTime {
        let timeout = match self.state {
            State::Closed => None,
            State::CookieWait(ref s) => {
                debug_assert!(s.t1_init.is_running());
                s.t1_init.next_expiry()
            }
            State::CookieEchoed(ref s) => {
                debug_assert!(s.t1_cookie.is_running());
                s.t1_cookie.next_expiry()
            }
            State::Established(ref tcb)
            | State::ShutdownPending(ref tcb)
            | State::ShutdownSent(ShutdownSentState { ref tcb, .. })
            | State::ShutdownReceived(ref tcb)
            | State::ShutdownAckSent(ref tcb) => {
                let mut timeout = tcb.retransmission_queue.next_timeout();
                timeout = closest_timeout(timeout, tcb.reconfig_timer.next_expiry());
                timeout = closest_timeout(timeout, tcb.data_tracker.next_timeout());
                timeout = closest_timeout(timeout, self.ctx.heartbeat_interval.next_expiry());
                timeout = closest_timeout(timeout, self.ctx.heartbeat_timeout.next_expiry());
                if let State::ShutdownSent(ref s) = self.state {
                    timeout = closest_timeout(timeout, s.t2_shutdown.next_expiry());
                }
                timeout
            }
        };

        // Ensure that already expired timers don't return a socket time in the past.
        let now = *self.now.borrow();
        timeout.map(|t| t.max(now)).unwrap_or(SocketTime::infinite_future())
    }

    fn shutdown(&mut self) {
        do_shutdown(&mut self.state, &mut self.ctx, *self.now.borrow());
    }

    fn close(&mut self) {
        if !matches!(self.state, State::Closed) {
            if let Some(tcb) = self.state.tcb() {
                self.ctx.events.borrow_mut().add(SocketEvent::SendPacket(
                    tcb.new_packet()
                        .add(&Chunk::Abort(AbortChunk {
                            error_causes: vec![ErrorCause::UserInitiatedAbort(
                                UserInitiatedAbortErrorCause { reason: "Close called".into() },
                            )],
                        }))
                        .build(),
                ));
                self.ctx.tx_packets_count += 1;
            }
            self.ctx.internal_close(&mut self.state, ErrorKind::NoError, String::new());
        }
    }

    fn state(&self) -> SocketState {
        match self.state {
            State::Closed => SocketState::Closed,
            State::CookieWait(_) | State::CookieEchoed(_) => SocketState::Connecting,
            State::Established(_) => SocketState::Connected,
            State::ShutdownPending(_)
            | State::ShutdownSent(_)
            | State::ShutdownReceived(_)
            | State::ShutdownAckSent(_) => SocketState::ShuttingDown,
        }
    }

    fn messages_ready_count(&self) -> usize {
        let Some(tcb) = self.state.tcb() else {
            return 0;
        };
        tcb.reassembly_queue.messages_ready_count()
    }

    fn options(&self) -> Options {
        self.ctx.options.clone()
    }

    fn set_max_message_size(&mut self, max_message_size: usize) {
        self.ctx.options.max_message_size = max_message_size;
    }

    fn set_stream_priority(&mut self, stream_id: StreamId, priority: u16) {
        self.ctx.send_queue.set_priority(stream_id, priority);
    }

    fn get_stream_priority(&self, stream_id: StreamId) -> u16 {
        self.ctx.send_queue.get_priority(stream_id)
    }

    fn send(&mut self, message: Message, send_options: &SendOptions) -> Result<(), SendError> {
        validate_send(&mut self.state, &mut self.ctx, &message, send_options)?;

        let now = *self.now.borrow();
        self.ctx.tx_messages_count += 1;
        self.ctx.send_queue.add(now, message, send_options);
        self.ctx.send_buffered_packets(&mut self.state, now);
        Ok(())
    }

    fn send_many(
        &mut self,
        messages: Vec<Message>,
        send_options: &SendOptions,
    ) -> Result<(), BatchSendError> {
        let now = *self.now.borrow();
        let mut errors = Vec::new();
        for (idx, message) in messages.into_iter().enumerate() {
            match validate_send(&mut self.state, &mut self.ctx, &message, send_options) {
                Ok(()) => {
                    self.ctx.tx_messages_count += 1;
                    self.ctx.send_queue.add(now, message, send_options);
                }
                Err(e) => {
                    errors.push((idx, e));
                }
            }
        }

        self.ctx.send_buffered_packets(&mut self.state, now);
        if errors.is_empty() { Ok(()) } else { Err(BatchSendError(errors)) }
    }

    fn reset_streams(&mut self, outgoing_streams: &[StreamId]) -> Result<(), ResetStreamsError> {
        let now = *self.now.borrow();
        do_reset_streams(&mut self.state, &mut self.ctx, now, outgoing_streams)
    }

    fn buffered_amount(&self, stream_id: StreamId) -> usize {
        self.ctx.send_queue.buffered_amount(stream_id)
    }

    fn buffered_amount_low_threshold(&self, stream_id: StreamId) -> usize {
        self.ctx.send_queue.buffered_amount_low_threshold(stream_id)
    }

    fn set_buffered_amount_low_threshold(&mut self, stream_id: StreamId, bytes: usize) {
        self.ctx.send_queue.set_buffered_amount_low_threshold(stream_id, bytes);
    }

    fn get_metrics(&self) -> Option<Metrics> {
        let tcb = self.state.tcb()?;

        let packet_payload_size =
            self.ctx.options.mtu - sctp_packet::COMMON_HEADER_SIZE - data_chunk::HEADER_SIZE;
        Some(Metrics {
            tx_packets_count: self.ctx.tx_packets_count,
            tx_messages_count: self.ctx.tx_messages_count,
            rtx_packets_count: tcb.retransmission_queue.rtx_packets_count(),
            rtx_bytes_count: tcb.retransmission_queue.rtx_bytes_count(),
            cwnd_bytes: tcb.retransmission_queue.cwnd(),
            srtt: tcb.rto.srtt(),
            unack_data_count: tcb.retransmission_queue.unacked_items()
                + self.ctx.send_queue.total_buffered_amount().div_ceil(packet_payload_size),
            rx_packets_count: self.ctx.rx_packets_count,
            rx_messages_count: tcb.reassembly_queue.rx_messages_count(),
            peer_rwnd_bytes: tcb.retransmission_queue.rwnd() as u32,
            peer_implementation: self.ctx.peer_implementation,
            uses_message_interleaving: tcb.capabilities.message_interleaving,
            uses_zero_checksum: tcb.capabilities.zero_checksum,
            negotiated_maximum_incoming_streams: tcb
                .capabilities
                .negotiated_maximum_incoming_streams,
            negotiated_maximum_outgoing_streams: tcb
                .capabilities
                .negotiated_maximum_outgoing_streams,
        })
    }

    fn get_handover_readiness(&self) -> HandoverReadiness {
        match &self.state {
            State::Closed => HandoverReadiness::READY,
            State::Established(tcb) => {
                self.ctx.send_queue.get_handover_readiness() | tcb.get_handover_readiness()
            }
            _ => HandoverReadiness::WRONG_CONNECTION_STATE,
        }
    }

    fn restore_from_state(&mut self, state: &SocketHandoverState) -> Result<(), RestoreError> {
        if !matches!(self.state, State::Closed) {
            return Err(RestoreError::SocketNotClosed);
        } else if matches!(state.socket_state, HandoverSocketState::Closed) {
            // Nothing to do.
            return Ok(());
        }

        self.ctx.send_queue.restore_from_state(state);

        let capabilities = Capabilities {
            partial_reliability: state.capabilities.partial_reliability,
            message_interleaving: state.capabilities.message_interleaving,
            reconfig: state.capabilities.reconfig,
            zero_checksum: state.capabilities.zero_checksum,
            negotiated_maximum_incoming_streams: state
                .capabilities
                .negotiated_maximum_incoming_streams,
            negotiated_maximum_outgoing_streams: state
                .capabilities
                .negotiated_maximum_outgoing_streams,
        };
        let mut tcb = TransmissionControlBlock::new(
            &self.ctx.options,
            state.my_verification_tag,
            Tsn(state.my_initial_tsn),
            state.peer_verification_tag,
            Tsn(state.peer_initial_tsn),
            state.tie_tag,
            /* rwnd */ 0,
            capabilities,
            Rc::clone(&self.ctx.events),
        );
        tcb.restore_from_state(state);

        self.state = State::Established(tcb);
        self.ctx.events.borrow_mut().add(SocketEvent::OnConnected());
        Ok(())
    }

    fn get_handover_state_and_close(&mut self) -> Result<SocketHandoverState, HandoverError> {
        let readiness = self.get_handover_readiness();
        if !readiness.is_ready() {
            return Err(HandoverError::NotReady(readiness));
        }

        let mut handover_state = SocketHandoverState::default();

        if let State::Established(tcb) = &self.state {
            handover_state.socket_state = HandoverSocketState::Connected;
            self.ctx.send_queue.add_to_handover_state(&mut handover_state);
            tcb.add_to_handover_state(&mut handover_state);
            self.ctx.events.borrow_mut().add(SocketEvent::OnClosed());
            self.state = State::Closed;
        }
        Ok(handover_state)
    }
}
