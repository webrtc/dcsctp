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
use crate::api::handover::HandoverSocketState;
use crate::api::handover::SocketHandoverState;
use crate::api::DcSctpSocket;
use crate::api::ErrorKind;
use crate::api::Message;
use crate::api::Metrics;
use crate::api::Options;
use crate::api::ResetStreamsStatus;
use crate::api::SctpImplementation;
use crate::api::SendOptions;
use crate::api::SendStatus;
use crate::api::SocketEvent;
use crate::api::SocketState;
use crate::api::StreamId;
use crate::api::ZERO_CHECKSUM_ALTERNATE_ERROR_DETECTION_METHOD_NONE;
use crate::events::Events;
use crate::logging::log_packet;
use crate::math::round_down_to_4;
use crate::packet::abort_chunk::AbortChunk;
use crate::packet::chunk::Chunk;
use crate::packet::chunk_validators::clean_sack;
use crate::packet::cookie_ack_chunk::CookieAckChunk;
use crate::packet::cookie_echo_chunk::CookieEchoChunk;
use crate::packet::cookie_received_while_shutting_down::CookieReceivedWhileShuttingDownErrorCause;
use crate::packet::data::Data;
use crate::packet::data_chunk;
use crate::packet::data_chunk::DataChunk;
use crate::packet::error_causes::ErrorCause;
use crate::packet::error_chunk::ErrorChunk;
use crate::packet::forward_tsn_chunk;
use crate::packet::forward_tsn_chunk::ForwardTsnChunk;
use crate::packet::forward_tsn_chunk::SkippedStream;
use crate::packet::forward_tsn_supported_parameter::ForwardTsnSupportedParameter;
use crate::packet::heartbeat_ack_chunk::HeartbeatAckChunk;
use crate::packet::heartbeat_info_parameter::HeartbeatInfoParameter;
use crate::packet::heartbeat_request_chunk::HeartbeatRequestChunk;
use crate::packet::idata_chunk;
use crate::packet::idata_chunk::IDataChunk;
use crate::packet::iforward_tsn_chunk;
use crate::packet::iforward_tsn_chunk::IForwardTsnChunk;
use crate::packet::incoming_ssn_reset_request_parameter::IncomingSsnResetRequestParameter;
use crate::packet::init_ack_chunk::InitAckChunk;
use crate::packet::init_chunk::InitChunk;
use crate::packet::no_user_data_error_cause::NoUserDataErrorCause;
use crate::packet::outgoing_ssn_reset_request_parameter::OutgoingSsnResetRequestParameter;
use crate::packet::parameter::Parameter;
use crate::packet::protocol_violation_error_cause::ProtocolViolationErrorCause;
use crate::packet::re_config_chunk;
use crate::packet::re_config_chunk::ReConfigChunk;
use crate::packet::read_u32_be;
use crate::packet::reconfiguration_response_parameter::ReconfigurationResponseParameter;
use crate::packet::reconfiguration_response_parameter::ReconfigurationResponseResult;
use crate::packet::sack_chunk::SackChunk;
use crate::packet::sctp_packet;
use crate::packet::sctp_packet::CommonHeader;
use crate::packet::sctp_packet::SctpPacket;
use crate::packet::sctp_packet::SctpPacketBuilder;
use crate::packet::shutdown_ack_chunk::ShutdownAckChunk;
use crate::packet::shutdown_chunk::ShutdownChunk;
use crate::packet::shutdown_complete_chunk::ShutdownCompleteChunk;
use crate::packet::state_cookie_parameter::StateCookieParameter;
use crate::packet::supported_extensions_parameter::SupportedExtensionsParameter;
use crate::packet::unknown_chunk::UnknownChunk;
use crate::packet::unrecognized_chunk_error_cause::UnrecognizedChunkErrorCause;
use crate::packet::user_initiated_abort_error_cause::UserInitiatedAbortErrorCause;
use crate::packet::write_u32_be;
use crate::packet::zero_checksum_acceptable_parameter::ZeroChecksumAcceptableParameter;
use crate::packet::SerializableTlv;
use crate::socket::capabilities::Capabilities;
use crate::socket::state_cookie::StateCookie;
use crate::socket::transmission_control_block::CurrentResetRequest;
use crate::socket::transmission_control_block::InflightResetRequest;
use crate::socket::transmission_control_block::TransmissionControlBlock;
use crate::timer::BackoffAlgorithm;
use crate::timer::Timer;
use crate::tx::retransmission_queue::HandleSackResult;
use crate::tx::send_queue::SendQueue;
use crate::types::Tsn;
use crate::EventSink;
#[cfg(not(test))]
use log::info;
#[cfg(not(test))]
use log::warn;
use rand::Rng;
use std::cell::RefCell;
use std::cmp::min;
use std::collections::HashSet;
use std::mem;
#[cfg(test)]
use std::println as info;
#[cfg(test)]
use std::println as warn;
use std::rc::Rc;
use std::time::Duration;
use std::time::Instant;

pub mod capabilities;
pub mod state_cookie;
pub mod transmission_control_block;

#[cfg(test)]
pub mod socket_tests;

const MIN_VERIFICATION_TAG: u32 = 1;
const MAX_VERIFICATION_TAG: u32 = u32::MAX;
const MIN_INITIAL_TSN: u32 = u32::MIN;
const MAX_INITIAL_TSN: u32 = u32::MAX;

struct CookieWaitState {
    t1_init: Timer,
    initial_tsn: Tsn,
    verification_tag: u32,
}

struct CookieEchoState {
    t1_cookie: Timer,
    cookie_echo_chunk: CookieEchoChunk,
    initial_tsn: Tsn,
    verification_tag: u32,
    tcb: TransmissionControlBlock,
}

struct ShutdownSentState {
    t2_shutdown: Timer,
    tcb: TransmissionControlBlock,
}

enum State {
    Closed,
    CookieWait(CookieWaitState),
    CookieEchoed(CookieEchoState),
    Established(TransmissionControlBlock),
    ShutdownPending(TransmissionControlBlock),
    ShutdownSent(ShutdownSentState),
    ShutdownReceived(TransmissionControlBlock),
    ShutdownAckSent(TransmissionControlBlock),
}

impl State {
    fn tcb_mut(&mut self) -> Option<&mut TransmissionControlBlock> {
        match self {
            State::CookieEchoed(CookieEchoState { tcb, .. })
            | State::Established(tcb)
            | State::ShutdownPending(tcb)
            | State::ShutdownSent(ShutdownSentState { tcb, .. })
            | State::ShutdownReceived(tcb)
            | State::ShutdownAckSent(tcb) => Some(tcb),
            _ => None,
        }
    }

    fn tcb(&self) -> Option<&TransmissionControlBlock> {
        match self {
            State::CookieEchoed(CookieEchoState { tcb, .. })
            | State::Established(tcb)
            | State::ShutdownPending(tcb)
            | State::ShutdownSent(ShutdownSentState { tcb, .. })
            | State::ShutdownReceived(tcb)
            | State::ShutdownAckSent(tcb) => Some(tcb),
            _ => None,
        }
    }
}

struct TxErrorCounter {
    error_counter: u32,
    limit: Option<u32>,
}

impl TxErrorCounter {
    fn increment(&mut self) {
        match self.limit {
            Some(limit) if self.error_counter <= limit => {
                self.error_counter += 1;
            }
            _ => {}
        }
    }

    fn reset(&mut self) {
        self.error_counter = 0;
    }

    fn is_exhausted(&self) -> bool {
        if let Some(limit) = self.limit {
            self.error_counter > limit
        } else {
            false
        }
    }
}

struct LoggingEvents {
    parent: Rc<RefCell<dyn EventSink>>,
    name: String,
    now: Rc<RefCell<Instant>>,
    start_time: Instant,
}

impl LoggingEvents {
    pub fn new(
        parent: Rc<RefCell<dyn EventSink>>,
        name: String,
        now: Rc<RefCell<Instant>>,
    ) -> LoggingEvents {
        let start_time = *now.borrow();
        Self { parent, name, now, start_time }
    }
}

impl EventSink for LoggingEvents {
    fn add(&mut self, event: SocketEvent) {
        match event {
            SocketEvent::SendPacket(ref e) => {
                let now = *self.now.borrow();
                log_packet(&self.name, now - self.start_time, true, e);
            }
            SocketEvent::OnMessage(ref e) => {
                info!("OnMessage: sid={}, ppid={}, len={}", e.stream_id, e.ppid, e.payload.len(),)
            }
            SocketEvent::OnConnected() => info!("OnConnected"),
            SocketEvent::OnError(kind, ref e) => info!("OnError: {:?}, {}", kind, e),
            SocketEvent::OnBufferedAmountLow(e) => info!("OnBufferedAmountLow: {}", e),
            SocketEvent::OnTotalBufferedAmountLow() => info!("OnTotalBufferedAmountLow"),
            SocketEvent::OnLifecycleMessageFullySent(ref id) => {
                info!("OnLifecycleMessageFullySent({})", id)
            }
            SocketEvent::OnLifecycleMessageExpired(ref id) => {
                info!("OnLifecycleMessageExpired({})", id)
            }
            SocketEvent::OnLifecycleMessageMaybeExpired(ref id) => {
                info!("OnLifecycleMessageMaybeExpired({})", id)
            }
            SocketEvent::OnLifecycleMessageDelivered(ref id) => {
                info!("OnLifecycleMessageDelivered({})", id)
            }
            SocketEvent::OnLifecycleEnd(ref id) => {
                info!("OnLifecycleEnd({})", id)
            }
            SocketEvent::OnStreamsResetFailed(ref streams) => {
                info!("OnStreamsResetFailed({:?})", streams)
            }
            SocketEvent::OnStreamsResetPerformed(ref streams) => {
                info!("OnStreamsResetPerformed({:?})", streams)
            }
            SocketEvent::OnIncomingStreamReset(ref streams) => {
                info!("OnIncomingStreamReset({:?})", streams)
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
        self.parent.borrow_mut().add(event)
    }

    fn next_event(&mut self) -> Option<SocketEvent> {
        self.parent.borrow_mut().next_event()
    }
}

/// Facilitates state transitions within a `State` enum, allowing the state enum variant arguments
/// to be moved to the new state, improving code readability.
macro_rules! transition_between {
  ($state:expr, $($from_pat:pat),+ => $to_expr:expr) => {
      $state = match mem::replace(&mut $state, State::Closed) {
          $($from_pat => $to_expr,)+
          _ => unreachable!(),
      };
  };
}

pub struct Socket<'a> {
    name: String,
    start_time: Instant,
    now: Rc<RefCell<Instant>>,
    options: Options,
    state: State,
    events: Rc<RefCell<dyn EventSink>>,
    send_queue: SendQueue<'a>,

    limit_forward_tsn_until: Instant,

    heartbeat_interval: Timer,
    heartbeat_timeout: Timer,
    heartbeat_counter: u32,
    heartbeat_sent_time: Instant,

    rx_packets_count: usize,
    tx_packets_count: usize,
    tx_messages_count: usize,
    peer_implementation: SctpImplementation,

    tx_error_counter: TxErrorCounter,
}

fn closest_timeout(a: Option<Instant>, b: Option<Instant>) -> Option<Instant> {
    match (a, b) {
        (None, None) => None,
        (None, Some(_)) => b,
        (Some(_), None) => a,
        (Some(t1), Some(t2)) => Some(min(t1, t2)),
    }
}

fn detemine_sctp_implementation(cookie: &[u8]) -> SctpImplementation {
    if cookie.len() > 8 {
        return match std::str::from_utf8(&cookie[0..8]) {
            Ok("dcSCTP00") => SctpImplementation::DcsctpCc,
            Ok("dcSCTPr0") => SctpImplementation::DcsctpRs,
            Ok("KAME-BSD") => SctpImplementation::UsrSctp,
            _ => SctpImplementation::Unknown,
        };
    }
    SctpImplementation::Unknown
}

fn make_capability_parameters(options: &Options, support_zero_checksum: bool) -> Vec<Parameter> {
    let mut result: Vec<Parameter> = Vec::new();
    let mut chunk_types: Vec<u8> = Vec::new();
    chunk_types.push(re_config_chunk::CHUNK_TYPE);

    if options.enable_partial_reliability {
        result.push(Parameter::ForwardTsnSupported(ForwardTsnSupportedParameter {}));
        chunk_types.push(forward_tsn_chunk::CHUNK_TYPE);
    }
    if options.enable_message_interleaving {
        chunk_types.push(idata_chunk::CHUNK_TYPE);
        chunk_types.push(iforward_tsn_chunk::CHUNK_TYPE);
    }
    if support_zero_checksum {
        result.push(Parameter::ZeroChecksumAcceptable(ZeroChecksumAcceptableParameter {
            method: options.zero_checksum_alternate_error_detection_method,
        }));
    }
    result.push(Parameter::SupportedExtensions(SupportedExtensionsParameter { chunk_types }));

    result
}

fn compute_capabilities(
    options: &Options,
    peer_nbr_outbound_streams: u16,
    peer_nbr_inbound_streams: u16,
    parameters: &[Parameter],
) -> Capabilities {
    let supported: HashSet<u8> = HashSet::from_iter(
        parameters
            .iter()
            .find_map(|e| match e {
                Parameter::SupportedExtensions(SupportedExtensionsParameter { chunk_types }) => {
                    Some(chunk_types)
                }
                _ => None,
            })
            .unwrap_or(&vec![])
            .iter()
            .cloned(),
    );

    let partial_reliability = options.enable_partial_reliability
        && (parameters.iter().any(|e| matches!(e, Parameter::ForwardTsnSupported(_)))
            || supported.contains(&forward_tsn_chunk::CHUNK_TYPE));

    let message_interleaving = options.enable_message_interleaving
        && supported.contains(&idata_chunk::CHUNK_TYPE)
        && supported.contains(&iforward_tsn_chunk::CHUNK_TYPE);

    let peer_zero_checksum = *parameters
        .iter()
        .find_map(|e| match e {
            Parameter::ZeroChecksumAcceptable(ZeroChecksumAcceptableParameter { method }) => {
                Some(method)
            }
            _ => None,
        })
        .unwrap_or(&ZERO_CHECKSUM_ALTERNATE_ERROR_DETECTION_METHOD_NONE);
    let zero_checksum = (options.zero_checksum_alternate_error_detection_method
        != ZERO_CHECKSUM_ALTERNATE_ERROR_DETECTION_METHOD_NONE)
        && (options.zero_checksum_alternate_error_detection_method == peer_zero_checksum);

    Capabilities {
        partial_reliability,
        message_interleaving,
        reconfig: supported.contains(&re_config_chunk::CHUNK_TYPE),
        zero_checksum,
        negotiated_maximum_incoming_streams: min(
            options.announced_maximum_incoming_streams,
            peer_nbr_outbound_streams,
        ),
        negotiated_maximum_outgoing_streams: min(
            options.announced_maximum_outgoing_streams,
            peer_nbr_inbound_streams,
        ),
    }
}

impl Socket<'_> {
    pub fn new(name: &str, start_time: Instant, options: &Options) -> Self {
        let now = Rc::new(RefCell::new(start_time));
        let events: Rc<RefCell<Events>> = Rc::new(RefCell::new(Events::new()));
        let events: Rc<RefCell<dyn EventSink>> =
            Rc::new(RefCell::new(LoggingEvents::new(events, name.into(), Rc::clone(&now))));
        let sqe = Rc::clone(&events);
        Socket {
            name: name.into(),
            start_time,
            now,
            options: options.clone(),
            state: State::Closed,
            events,
            send_queue: SendQueue::new(options.mtu, options, sqe),
            limit_forward_tsn_until: start_time,
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
            heartbeat_sent_time: start_time,
            rx_packets_count: 0,
            tx_packets_count: 0,
            tx_messages_count: 0,
            peer_implementation: SctpImplementation::Unknown,
            tx_error_counter: TxErrorCounter {
                error_counter: 0,
                limit: options.max_retransmissions,
            },
        }
    }

    fn internal_close(&mut self, error: ErrorKind, message: String) {
        if !matches!(self.state, State::Closed) {
            self.heartbeat_interval.stop();
            self.heartbeat_timeout.stop();
            if error == ErrorKind::NoError {
                self.events.borrow_mut().add(SocketEvent::OnClosed());
            } else {
                self.events.borrow_mut().add(SocketEvent::OnAborted(error, message));
            }
            self.state = State::Closed;
        }
    }

    fn send_buffered_packets(&mut self, now: Instant) {
        if let Some(tcb) = &self.state.tcb_mut() {
            let mut packet = tcb.new_packet();
            self.send_buffered_packets_with(now, &mut packet);
        }
    }

    /// Given a builder that is either empty, or only contains control chunks, add more control
    /// chunks and data chunks to it, and send it and possibly more packets, as is allowed by the
    /// congestion window.
    fn send_buffered_packets_with(&mut self, now: Instant, builder: &mut SctpPacketBuilder) {
        for packet_idx in 0..self.options.max_burst {
            if let Some(tcb) = self.state.tcb_mut() {
                if packet_idx == 0 {
                    if tcb.data_tracker.should_send_ack(now, true) {
                        builder.add(
                            Chunk::Sack(tcb.data_tracker.create_selective_ack(
                                tcb.reassembly_queue.remaining_bytes() as u32,
                            )),
                        );
                    }
                    if now >= self.limit_forward_tsn_until
                        && tcb.retransmission_queue.should_send_forward_tsn(now)
                    {
                        builder.add(tcb.retransmission_queue.create_forward_tsn());
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
                            self.send_queue.discard(*stream_id, *message_id)
                        }
                        self.send_queue.produce(now, max_size)
                    },
                );

                if !chunks.is_empty() {
                    // Sending data means that the path is not idle - restart heartbeat timer.
                    self.heartbeat_interval.start(now);
                }

                for (tsn, data) in chunks {
                    builder.add(tcb.make_data_chunk(tsn, data));
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
            if matches!(self.state, State::CookieEchoed(_)) {
                return;
            }
        }
    }

    fn handle_init(&mut self, chunk: InitChunk) {
        let my_verification_tag: u32;
        let my_initial_tsn: Tsn;
        let tie_tag: u64;

        match &mut self.state {
            State::Closed => {
                my_initial_tsn =
                    Tsn(rand::thread_rng().gen_range(MIN_INITIAL_TSN..MAX_INITIAL_TSN));
                my_verification_tag =
                    rand::thread_rng().gen_range(MIN_VERIFICATION_TAG..MAX_VERIFICATION_TAG);
                tie_tag = 0;
            }
            State::CookieWait(CookieWaitState { verification_tag, initial_tsn, .. })
            | State::CookieEchoed(CookieEchoState { verification_tag, initial_tsn, .. }) => {
                // From <https://datatracker.ietf.org/doc/html/rfc9260#section-5.2.1>:
                //
                //   This usually indicates an initialization collision, i.e., each endpoint is
                //   attempting, at about the same time, to establish an association with the other
                //   endpoint.
                info!("Received Init indicating simultaneous connections");
                my_verification_tag = *verification_tag;
                my_initial_tsn = *initial_tsn;
                tie_tag = 0;
            }
            State::ShutdownAckSent(_) => {
                // From <https://datatracker.ietf.org/doc/html/rfc9260#section-9.2-18>:
                //
                //   If an endpoint is in the SHUTDOWN-ACK-SENT state and receives an INIT chunk
                //   (e.g., if the SHUTDOWN COMPLETE chunk was lost) with source and destination
                //   transport addresses (either in the IP addresses or in the INIT chunk) that
                //   belong to this association, it SHOULD discard the INIT chunk and retransmit
                // the   SHUTDOWN ACK chunk.
                self.send_shutdown_ack();
                return;
            }
            State::Established(tcb)
            | State::ShutdownPending(tcb)
            | State::ShutdownSent(ShutdownSentState { tcb, .. })
            | State::ShutdownReceived(tcb) => {
                // From <https://datatracker.ietf.org/doc/html/rfc9260#section-5.2.2>:
                //
                //   The outbound SCTP packet containing this INIT ACK chunk MUST carry a
                //   Verification Tag value equal to the Initiate Tag found in the unexpected INIT
                //   chunk. And the INIT ACK chunk MUST contain a new Initiate Tag (randomly
                //   generated; see Section 5.3.1). Other parameters for the endpoint SHOULD be
                //   copied from the existing parameters of the association (e.g., number of
                //   outbound streams) into the INIT ACK chunk and cookie.
                //
                // Create a new verification tag, different from the previous one.
                my_verification_tag =
                    rand::thread_rng().gen_range(MIN_VERIFICATION_TAG..MAX_VERIFICATION_TAG);
                my_initial_tsn = tcb.retransmission_queue.next_tsn().add_to(1000000);
                tie_tag = tcb.tie_tag;
            }
        }

        let capabilities = compute_capabilities(
            &self.options,
            chunk.nbr_outbound_streams,
            chunk.nbr_inbound_streams,
            &chunk.parameters,
        );
        let write_checksum = !capabilities.zero_checksum;
        let mut parameters = make_capability_parameters(&self.options, capabilities.zero_checksum);
        parameters.push(Parameter::StateCookie(StateCookieParameter {
            cookie: StateCookie {
                peer_tag: chunk.initiate_tag,
                my_tag: my_verification_tag,
                peer_initial_tsn: chunk.initial_tsn,
                my_initial_tsn,
                a_rwnd: chunk.a_rwnd,
                tie_tag,
                capabilities,
            }
            .serialize(),
        }));
        let init_ack = InitAckChunk {
            initiate_tag: my_verification_tag,
            a_rwnd: self.options.max_receiver_window_buffer_size as u32,
            nbr_outbound_streams: self.options.announced_maximum_outgoing_streams,
            nbr_inbound_streams: self.options.announced_maximum_incoming_streams,
            initial_tsn: my_initial_tsn,
            parameters,
        };

        self.events.borrow_mut().add(SocketEvent::SendPacket(
            SctpPacketBuilder::new(
                chunk.initiate_tag,
                self.options.local_port,
                self.options.remote_port,
                self.options.mtu,
            )
            .write_checksum(write_checksum)
            .add(Chunk::InitAck(init_ack))
            .build(),
        ));
        self.tx_packets_count += 1;
    }

    fn handle_init_ack(&mut self, now: Instant, chunk: InitAckChunk) {
        let State::CookieWait(s) = &mut self.state else {
            // From <https://datatracker.ietf.org/doc/html/rfc9260#section-5.2.3>:
            //
            //   If an INIT ACK chunk is received by an endpoint in any state other than the
            //   COOKIE-WAIT or CLOSED state, the endpoint SHOULD discard the INIT ACK chunk. An
            //   unexpected INIT ACK chunk usually indicates the processing of an old or duplicated
            //   INIT chunk.
            info!("Received INIT_ACK in unexpected state");
            return;
        };

        let capabilities = compute_capabilities(
            &self.options,
            chunk.nbr_outbound_streams,
            chunk.nbr_inbound_streams,
            &chunk.parameters,
        );

        let Some(cookie) = chunk.parameters.into_iter().find_map(|p| match p {
            Parameter::StateCookie(StateCookieParameter { cookie }) => Some(cookie),
            _ => None,
        }) else {
            self.events.borrow_mut().add(SocketEvent::SendPacket(
                SctpPacketBuilder::new(
                    s.verification_tag,
                    self.options.local_port,
                    self.options.remote_port,
                    round_down_to_4!(self.options.mtu),
                )
                .add(Chunk::Abort(AbortChunk {
                    error_causes: vec![ErrorCause::ProtocolViolation(
                        ProtocolViolationErrorCause { information: "INIT-ACK malformed".into() },
                    )],
                }))
                .build(),
            ));
            self.tx_packets_count += 1;
            self.internal_close(
                ErrorKind::ProtocolViolation,
                "InitAck chunk doesn't contain a cookie".into(),
            );
            return;
        };

        self.send_queue.enable_message_interleaving(capabilities.message_interleaving);
        let mut t1_cookie = Timer::new(
            self.options.t1_cookie_timeout,
            BackoffAlgorithm::Exponential,
            self.options.max_init_retransmits,
            None,
        );
        t1_cookie.start(now);
        self.peer_implementation = detemine_sctp_implementation(&cookie);
        self.send_queue.reset();
        let tie_tag = rand::thread_rng().gen::<u64>();
        self.state = State::CookieEchoed(CookieEchoState {
            t1_cookie,
            cookie_echo_chunk: CookieEchoChunk { cookie },
            initial_tsn: s.initial_tsn,
            verification_tag: s.verification_tag,
            tcb: TransmissionControlBlock::new(
                &self.options,
                s.verification_tag,
                s.initial_tsn,
                chunk.initiate_tag,
                chunk.initial_tsn,
                tie_tag,
                chunk.a_rwnd,
                capabilities,
                self.events.clone(),
            ),
        });

        // The connection isn't fully established just yet.
        self.send_cookie_echo(now);
    }

    fn send_cookie_echo(&mut self, now: Instant) {
        let State::CookieEchoed(ref s) = self.state else {
            unreachable!();
        };

        // From <https://datatracker.ietf.org/doc/html/rfc9260.html#section-5.1-2.3.2>:
        //
        //   The COOKIE ECHO chunk MAY be bundled with any pending outbound DATA chunks, but it MUST
        //   be the first chunk in the packet [...]
        let mut builder = SctpPacketBuilder::new(
            s.tcb.peer_verification_tag,
            self.options.local_port,
            self.options.remote_port,
            self.options.mtu,
        );

        builder.add(Chunk::CookieEcho(s.cookie_echo_chunk.clone()));
        self.send_buffered_packets_with(now, &mut builder);
    }

    fn maybe_send_shutdown(&mut self, now: Instant) {
        let State::ShutdownPending(tcb) = &self.state else { unreachable!() };
        if tcb.retransmission_queue.unacked_bytes() != 0 {
            // Not ready to shutdown yet.
            return;
        }

        // From <https://datatracker.ietf.org/doc/html/rfc9260.html#section-9.2-3>:
        //
        //   Once all its outstanding data has been acknowledged, the endpoint sends a SHUTDOWN
        //   chunk to its peer, including in the Cumulative TSN Ack field the last sequential TSN it
        //   has received from the peer. It SHOULD then start the T2-shutdown timer and enter the
        //   SHUTDOWN-SENT state.
        let mut t2_shutdown = Timer::new(
            tcb.rto.rto(),
            BackoffAlgorithm::Exponential,
            self.options.max_retransmissions,
            None,
        );
        t2_shutdown.start(now);

        transition_between!(self.state,
            State::ShutdownPending(tcb) =>
                State::ShutdownSent(ShutdownSentState { tcb, t2_shutdown })
        );

        self.send_shutdown();
    }

    fn maybe_send_shutdown_ack(&mut self) {
        let State::ShutdownReceived(tcb) = &mut self.state else { unreachable!() };
        if tcb.retransmission_queue.unacked_bytes() != 0 {
            // Not ready to shutdown yet.
            return;
        }

        // From <https://datatracker.ietf.org/doc/html/rfc9260#section-9.2-12>:
        //
        //   If the receiver of the SHUTDOWN chunk has no more outstanding DATA chunks, the SHUTDOWN
        //   chunk receiver MUST send a SHUTDOWN ACK chunk and start a T2-shutdown timer of its own,
        //   entering the SHUTDOWN-ACK-SENT state. If the timer expires, the endpoint MUST resend
        //   the SHUTDOWN ACK chunk [...]
        transition_between!(self.state,
            State::ShutdownReceived(tcb) => State::ShutdownAckSent(tcb)
        );

        self.send_shutdown_ack();
    }

    fn send_shutdown(&mut self) {
        let State::ShutdownSent(ShutdownSentState { tcb, .. }) = &mut self.state else {
            unreachable!()
        };
        self.events.borrow_mut().add(SocketEvent::SendPacket(
            tcb.new_packet()
                .add(Chunk::Shutdown(ShutdownChunk {
                    cumulative_tsn_ack: tcb.data_tracker.last_cumulative_acked_tsn(),
                }))
                .build(),
        ));
        self.tx_packets_count += 1;
    }

    fn send_shutdown_ack(&mut self) {
        let State::ShutdownAckSent(tcb) = &mut self.state else { unreachable!() };
        self.events.borrow_mut().add(SocketEvent::SendPacket(
            tcb.new_packet().add(Chunk::ShutdownAck(ShutdownAckChunk {})).build(),
        ));
        self.tx_packets_count += 1;
    }

    fn maybe_send_fast_retransmit(&mut self, now: Instant) {
        let tcb = self.state.tcb_mut().unwrap();
        if !tcb.retransmission_queue.has_data_to_be_fast_retransmitted() {
            return;
        }

        let mut builder = tcb.new_packet();

        let chunks =
            tcb.retransmission_queue.get_chunks_for_fast_retransmit(now, builder.bytes_remaining());
        for (tsn, data) in chunks {
            builder.add(tcb.make_data_chunk(tsn, data));
        }

        debug_assert!(!builder.is_empty());
        self.events.borrow_mut().add(SocketEvent::SendPacket(builder.build()));
        self.tx_packets_count += 1;
    }

    fn handle_sack(&mut self, now: Instant, sack: SackChunk) {
        let Some(tcb) = self.state.tcb_mut() else {
            self.events
                .borrow_mut()
                .add(SocketEvent::OnError(ErrorKind::NotConnected, "No TCB".into()));
            return;
        };

        let sack = clean_sack(sack);
        match tcb.retransmission_queue.handle_sack(now, &sack) {
            HandleSackResult::Invalid => {
                log::debug!("Dropping out-of-order SACK with TSN {}", sack.cumulative_tsn_ack);
                return;
            }
            HandleSackResult::Valid { rtt, reset_error_counter } => {
                if let Some(rtt) = rtt {
                    tcb.rto.observe_rto(rtt);
                    tcb.retransmission_queue.update_rto(tcb.rto.rto());
                    tcb.data_tracker.update_rto(tcb.rto.rto());
                }
                if reset_error_counter {
                    self.tx_error_counter.reset();
                }
            }
        }

        match self.state {
            State::ShutdownPending(_) => self.maybe_send_shutdown(now),
            State::ShutdownReceived(_) => self.maybe_send_shutdown_ack(),
            _ => (),
        }

        // Receiving an ACK may make the socket go into fast recovery mode. From
        // <https://datatracker.ietf.org/doc/html/rfc9260#section-7.2.4>:
        //
        //   If not in Fast Recovery, determine how many of the earliest (i.e., lowest TSN) DATA
        //   chunks marked for retransmission will fit into a single packet, subject to constraint
        //   of the PMTU of the destination transport address to which the packet is being sent.
        //   Call this value K. Retransmit those K DATA chunks in a single packet. When a Fast
        //   Retransmit is being performed, the sender SHOULD ignore the value of cwnd and SHOULD
        //   NOT delay retransmission for this single packet.
        self.maybe_send_fast_retransmit(now);

        // Receiving an ACK will decrease outstanding bytes (maybe now below cwnd?) or indicate
        // packet loss that may result in sending FORWARD-TSN.
        self.send_buffered_packets(now);
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
        self.internal_close(ErrorKind::PeerReported, reason);
    }

    fn handle_error(&mut self, chunk: ErrorChunk) {
        if self.state.tcb().is_none() {
            return;
        }
        let message =
            chunk.error_causes.into_iter().map(|c| c.to_string()).collect::<Vec<_>>().join(",");
        self.events.borrow_mut().add(SocketEvent::OnError(ErrorKind::PeerReported, message));
    }

    fn handle_cookie_echo(&mut self, now: Instant, header: &CommonHeader, chunk: CookieEchoChunk) {
        match StateCookie::from_bytes(&chunk.cookie) {
            Err(s) => {
                self.events
                    .borrow_mut()
                    .add(SocketEvent::OnError(ErrorKind::ParseFailed, s.into()));
            }
            Ok(cookie) => {
                // The init timer can be running on simultaneous connections.
                let mut re_establish_connection = false;
                if let Some(tcb) = self.state.tcb() {
                    // The comments below contains quotes from
                    // <https://datatracker.ietf.org/doc/html/rfc9260#section-5.2.4>.

                    // "Handle a COOKIE ECHO when a TCB Exists"
                    if header.verification_tag != tcb.my_verification_tag
                        && tcb.peer_verification_tag != cookie.peer_tag
                        && cookie.tie_tag == tcb.tie_tag
                    {
                        // "A) In this case, the peer may have restarted."
                        if matches!(self.state, State::ShutdownAckSent(_)) {
                            // "If the endpoint is in the SHUTDOWN-ACK-SENT state and recognizes
                            // that the peer has restarted ... it MUST NOT set up a new association
                            // but instead resend the SHUTDOWN ACK and send an ERROR chunk with a
                            // "Cookie Received While Shutting Down" error cause to its peer."
                            self.events.borrow_mut().add(SocketEvent::SendPacket(
                                tcb.new_packet()
                                    .add(Chunk::ShutdownAck(ShutdownAckChunk {}))
                                    .add(Chunk::Error(ErrorChunk {
                                        error_causes: vec![
                                            ErrorCause::CookieReceivedWhileShuttingDown(
                                                CookieReceivedWhileShuttingDownErrorCause {},
                                            ),
                                        ],
                                    }))
                                    .build(),
                            ));
                            self.events.borrow_mut().add(SocketEvent::OnError(
                                ErrorKind::WrongSequence,
                                "Received COOKIE-ECHO while shutting down".into(),
                            ));

                            self.tx_packets_count += 1;
                            return;
                        } else {
                            self.events.borrow_mut().add(SocketEvent::OnConnectionRestarted());
                            re_establish_connection = true;
                        }
                    } else if header.verification_tag == tcb.my_verification_tag
                        && tcb.peer_verification_tag != cookie.peer_tag
                    {
                        // TODO: Handle the peer_tag == 0?

                        // "B) In this case, both sides may be attempting to start an association at
                        // about the same time, but the peer endpoint started its INIT after
                        // responding to the local endpoint's INIT."
                        re_establish_connection = true;
                    } else if header.verification_tag != tcb.my_verification_tag
                        && tcb.peer_verification_tag == cookie.peer_tag
                        && cookie.tie_tag == 0
                    {
                        // "C) In this case, the local endpoint's cookie has arrived late. Before it
                        // arrived, the local endpoint sent an INIT and received an INIT ACK and
                        // finally sent a COOKIE ECHO with the peer's same tag but a new tag of its
                        // own. The cookie should be silently discarded. The endpoint SHOULD NOT
                        // change states and should leave any timers running."
                        return;
                    } else if header.verification_tag == tcb.my_verification_tag
                        && tcb.peer_verification_tag == cookie.peer_tag
                    {
                        // "D) When both local and remote tags match, the endpoint should enter the
                        // ESTABLISHED state, if it is in the COOKIE-ECHOED state. It should stop
                        // any cookie timer that may be running and send a COOKIE ACK."
                    }
                } else if header.verification_tag != cookie.my_tag {
                    self.events.borrow_mut().add(SocketEvent::OnError(
                        ErrorKind::ParseFailed,
                        "Received CookieEcho with invalid verification tag".into(),
                    ));
                    return;
                }

                if !matches!(self.state, State::Established(_)) || re_establish_connection {
                    self.send_queue
                        .enable_message_interleaving(cookie.capabilities.message_interleaving);

                    // If the connection is re-established (peer restarted, but re-used old
                    // connection), make sure that all message identifiers are reset and any partly
                    // sent message is re-sent in full. The same is true when the socket is closed
                    // and later re-opened, which never happens in WebRTC, but is a valid operation
                    // on the SCTP level. Note that in case of handover, the send queue is already
                    // re-configured, and shouldn't be reset.
                    self.send_queue.reset();

                    let tie_tag = rand::thread_rng().gen::<u64>();
                    self.state = State::Established(TransmissionControlBlock::new(
                        &self.options,
                        cookie.my_tag,
                        cookie.my_initial_tsn,
                        cookie.peer_tag,
                        cookie.peer_initial_tsn,
                        tie_tag,
                        cookie.a_rwnd,
                        cookie.capabilities,
                        self.events.clone(),
                    ));
                    self.heartbeat_interval.start(now);
                    info!("{}: Connection established", self.name);
                    self.events.borrow_mut().add(SocketEvent::OnConnected());
                }

                let State::Established(ref tcb) = self.state else {
                    unreachable!();
                };

                let write_checksum = !tcb.capabilities.zero_checksum;
                let mut b = SctpPacketBuilder::new(
                    cookie.peer_tag,
                    self.options.local_port,
                    self.options.remote_port,
                    self.options.mtu,
                );
                b.write_checksum(write_checksum);
                b.add(Chunk::CookieAck(CookieAckChunk {}));
                self.send_buffered_packets_with(now, &mut b);
            }
        }
    }

    fn handle_cookie_ack(&mut self, now: Instant) {
        if !matches!(self.state, State::CookieEchoed(_)) {
            // From <https://datatracker.ietf.org/doc/html/rfc9260#section-5.2.5>:
            //
            //   At any state other than COOKIE-ECHOED, an endpoint SHOULD silently discard a
            //   received COOKIE ACK chunk.
            warn!("Received COOKIE_ACK not in COOKIE_ECHOED state");
            return;
        }

        transition_between!(self.state,
           State::CookieEchoed(s) => State::Established(s.tcb)
        );

        self.heartbeat_interval.start(now);
        info!("Socket is connected!");
        self.events.borrow_mut().add(SocketEvent::OnConnected());
    }

    fn handle_data(&mut self, now: Instant, tsn: Tsn, data: Data) {
        if data.payload.is_empty() {
            self.events.borrow_mut().add(SocketEvent::OnError(
                ErrorKind::ProtocolViolation,
                "Received DATA chunk with no user data".into(),
            ));
            if let Some(tcb) = self.state.tcb_mut() {
                self.events.borrow_mut().add(SocketEvent::SendPacket(
                    tcb.new_packet()
                        .add(Chunk::Error(ErrorChunk {
                            error_causes: vec![ErrorCause::NoUserData(NoUserDataErrorCause {
                                tsn,
                            })],
                        }))
                        .build(),
                ));
                self.tx_packets_count += 1;
            }
            return;
        }
        let Some(tcb) = self.state.tcb_mut() else {
            self.events.borrow_mut().add(SocketEvent::OnError(
                ErrorKind::NotConnected,
                "Received unexpected commands on socket that is not connected".into(),
            ));
            return;
        };
        if tcb.reassembly_queue.is_full() {
            // If the reassembly queue is full, there is nothing that can be done. The specification
            // only allows dropping gap-ack-blocks, and that's not likely to help as the socket has
            // been trying to fill gaps since the watermark was reached.
            return;
        }
        if tcb.reassembly_queue.is_above_watermark() {
            // TODO: Implement
            return;
        }
        if !tcb.data_tracker.is_tsn_valid(tsn) {
            // TODO: Implement
            return;
        }
        if tcb.data_tracker.observe(now, tsn, false) {
            tcb.reassembly_queue.add(tsn, data);
        }
    }

    fn handle_heartbeat_req(&mut self, chunk: HeartbeatRequestChunk) {
        // From <https://datatracker.ietf.org/doc/html/rfc9260#section-8.3-9>:
        //
        //   The receiver of the HEARTBEAT chunk SHOULD immediately respond with a HEARTBEAT ACK
        //   chunk that contains the Heartbeat Information TLV, together with any other received
        //   TLVs, copied unchanged from the received HEARTBEAT chunk.
        if let Some(tcb) = self.state.tcb_mut() {
            self.events.borrow_mut().add(SocketEvent::SendPacket(
                tcb.new_packet()
                    .add(Chunk::HeartbeatAck(HeartbeatAckChunk { parameters: chunk.parameters }))
                    .build(),
            ));
            self.tx_packets_count += 1;
        }
    }

    fn handle_heartbeat_ack(&mut self, now: Instant, chunk: HeartbeatAckChunk) {
        self.heartbeat_timeout.stop();
        match chunk.parameters.iter().find_map(|p| match p {
            Parameter::HeartbeatInfo(HeartbeatInfoParameter { info }) => Some(info),
            _ => None,
        }) {
            Some(info) if info.len() == 4 => {
                let counter = read_u32_be!(&info);
                if counter == self.heartbeat_counter {
                    let _rtt = now - self.heartbeat_sent_time;
                    // From <https://datatracker.ietf.org/doc/html/rfc9260#section-8.1>:
                    //
                    //   When a HEARTBEAT ACK chunk is received from the peer endpoint, the counter
                    //   SHOULD also be reset.
                    self.tx_error_counter.reset();
                }
            }
            _ => {
                self.events.borrow_mut().add(SocketEvent::OnError(
                    ErrorKind::ParseFailed,
                    "Failed to parse HEARTBEAT-ACK; Invalid info parameter".into(),
                ));
            }
        }
    }

    fn maybe_send_sack(&mut self, now: Instant) {
        if let Some(tcb) = self.state.tcb_mut() {
            tcb.data_tracker.observe_packet_end(now);
            if tcb.data_tracker.should_send_ack(now, false) {
                let mut b = tcb.new_packet();
                let rwnd = tcb.reassembly_queue.remaining_bytes();
                b.add(Chunk::Sack(tcb.data_tracker.create_selective_ack(rwnd as u32)));
                self.send_buffered_packets_with(now, &mut b);
            }
        }
    }

    fn send_init(&mut self) {
        let State::CookieWait(ref s) = self.state else {
            unreachable!();
        };
        let support_zero_checksum = self.options.zero_checksum_alternate_error_detection_method
            != ZERO_CHECKSUM_ALTERNATE_ERROR_DETECTION_METHOD_NONE;
        self.events.borrow_mut().add(SocketEvent::SendPacket(
            SctpPacketBuilder::new(
                0,
                self.options.local_port,
                self.options.remote_port,
                self.options.mtu,
            )
            .add(Chunk::Init(InitChunk {
                initiate_tag: s.verification_tag,
                a_rwnd: self.options.max_receiver_window_buffer_size as u32,
                nbr_outbound_streams: self.options.announced_maximum_outgoing_streams,
                nbr_inbound_streams: self.options.announced_maximum_incoming_streams,
                initial_tsn: s.initial_tsn,
                parameters: make_capability_parameters(&self.options, support_zero_checksum),
            }))
            .build(),
        ));
        self.tx_packets_count += 1;
    }

    fn handle_heartbeat_timeouts(&mut self, now: Instant) {
        if self.heartbeat_interval.expire(now) {
            if let Some(tcb) = self.state.tcb() {
                self.heartbeat_timeout.set_duration(self.options.rto_initial);
                self.heartbeat_timeout.start(now);
                self.heartbeat_counter = self.heartbeat_counter.wrapping_add(1);
                self.heartbeat_sent_time = now;
                let mut info = vec![0; 4];
                write_u32_be!(&mut info, self.heartbeat_counter);
                self.events.borrow_mut().add(SocketEvent::SendPacket(
                    tcb.new_packet()
                        .add(Chunk::HeartbeatRequest(HeartbeatRequestChunk {
                            parameters: vec![Parameter::HeartbeatInfo(HeartbeatInfoParameter {
                                info,
                            })],
                        }))
                        .build(),
                ));
                self.tx_packets_count += 1;
            }
        }
        if self.heartbeat_timeout.expire(now) {
            // Note that the timeout timer is not restarted. It will be started again when the
            // interval timer expires.
            debug_assert!(!self.heartbeat_timeout.is_running());
            self.tx_error_counter.increment();
        }
    }

    pub fn verification_tag(&self) -> u32 {
        self.state.tcb().map_or(0, |tcb| tcb.my_verification_tag)
    }

    fn handle_reconfig_timeout(&mut self, now: Instant) {
        let tcb = self.state.tcb_mut().unwrap();
        if tcb.reconfig_timer.expire(now) {
            match tcb.current_reset_request {
                CurrentResetRequest::None => unreachable!(),
                CurrentResetRequest::Prepared(..) => {
                    // There is no outstanding request, but there is a prepared one. This means that
                    // the receiver has previously responded "in progress", which resulted in
                    // retrying the request (but with a new req_seq_nbr) after a while.
                }
                CurrentResetRequest::Inflight(..) => {
                    // There is an outstanding request, which timed out while waiting for a
                    // response.
                    self.tx_error_counter.increment();
                    if self.tx_error_counter.is_exhausted() {
                        return;
                    }
                }
            }
            tcb.reconfig_timer.set_duration(tcb.rto.rto());
            let mut builder = tcb.new_packet();
            tcb.add_prepared_ssn_reset_request(&mut builder);
            self.events.borrow_mut().add(SocketEvent::SendPacket(builder.build()));
            self.tx_packets_count += 1;
        }
    }

    fn handle_t2_shutdown_timeout(&mut self, now: Instant) {
        let State::ShutdownSent(s) = &mut self.state else {
            return;
        };
        if s.t2_shutdown.expire(now) {
            if s.t2_shutdown.is_running() {
                self.send_shutdown();
                return;
            }

            self.events.borrow_mut().add(SocketEvent::SendPacket(
                s.tcb
                    .new_packet()
                    .add(Chunk::Abort(AbortChunk {
                        error_causes: vec![ErrorCause::UserInitiatedAbort(
                            UserInitiatedAbortErrorCause {
                                reason: "Too many retransmissions".into(),
                            },
                        )],
                    }))
                    .build(),
            ));
            self.tx_packets_count += 1;
            self.internal_close(ErrorKind::TooManyRetries, "Too many retransmissions".into());
        }
    }

    fn validate_req_seq_nbr(
        req_seq_nbr: u32,
        last_processed_req_seq_nbr: u32,
        last_processed_req_result: ReconfigurationResponseResult,
        responses: &mut Vec<Parameter>,
    ) -> bool {
        if req_seq_nbr == last_processed_req_seq_nbr {
            // From <https://datatracker.ietf.org/doc/html/rfc6525#section-5.2.1>:
            //
            //   If the received RE-CONFIG chunk contains at least one request and based on the
            //   analysis of the Re-configuration Request Sequence Numbers this is the last received
            //   RE-CONFIG chunk (i.e., a retransmission), the same RE-CONFIG chunk MUST to be sent
            //   back in response, as it was earlier.
            responses.push(Parameter::ReconfigurationResponse(ReconfigurationResponseParameter {
                response_seq_nbr: req_seq_nbr,
                result: last_processed_req_result,
                sender_next_tsn: None,
                receiver_next_tsn: None,
            }));
            return false;
        } else if req_seq_nbr != last_processed_req_seq_nbr.wrapping_add(1) {
            // Too old, too new, from wrong association etc.
            responses.push(Parameter::ReconfigurationResponse(ReconfigurationResponseParameter {
                response_seq_nbr: req_seq_nbr,
                result: ReconfigurationResponseResult::ErrorBadSequenceNumber,
                sender_next_tsn: None,
                receiver_next_tsn: None,
            }));
            return false;
        }
        true
    }

    fn handle_forward_tsn(
        &mut self,
        now: Instant,
        new_cumulative_tsn: Tsn,
        skipped_streams: Vec<SkippedStream>,
    ) {
        if let Some(tcb) = self.state.tcb_mut() {
            if tcb.data_tracker.handle_forward_tsn(now, new_cumulative_tsn) {
                tcb.reassembly_queue.handle_forward_tsn(new_cumulative_tsn, skipped_streams);
            }
        }
    }

    fn handle_iforward_tsn(&mut self, _now: Instant, _chunk: IForwardTsnChunk) {}

    fn handle_unrecognized_chunk(&mut self, chunk: UnknownChunk) -> bool {
        // From <https://datatracker.ietf.org/doc/html/rfc9260#section-3.2-3.2.5>:
        //
        //   Chunk Types are encoded such that the highest-order 2 bits specify the action that is
        //   taken if the processing endpoint does not recognize the Chunk Type.
        let typ = chunk.typ;
        let report_as_error = (typ & 0x40) != 0;
        let continue_processing = (typ & 0x80) != 0;
        if report_as_error {
            self.events
                .borrow_mut()
                .add(SocketEvent::OnError(ErrorKind::ParseFailed, format!("Received {}, ", chunk)));
            // From <https://datatracker.ietf.org/doc/html/rfc9260#section-3.2-3.2.6.1.2.2.1>:
            //
            //   [...] report the unrecognized chunk in an ERROR chunk using the 'Unrecognized Chunk
            //   Type' error cause.
            if let Some(tcb) = self.state.tcb() {
                let mut serialized = vec![0; chunk.serialized_size()];
                chunk.serialize_to(&mut serialized);
                self.events.borrow_mut().add(SocketEvent::SendPacket(
                    tcb.new_packet()
                        .add(Chunk::Error(ErrorChunk {
                            error_causes: vec![ErrorCause::UnrecognizedChunk(
                                UnrecognizedChunkErrorCause { chunk: serialized },
                            )],
                        }))
                        .build(),
                ));
                self.tx_packets_count += 1;
            }
        }
        continue_processing
    }

    fn handle_reconfig(&mut self, now: Instant, chunk: ReConfigChunk) {
        let Some(tcb) = self.state.tcb_mut() else {
            return;
        };
        let mut responses: Vec<Parameter> = Vec::new();
        for parameter in chunk.parameters {
            match parameter {
                Parameter::OutgoingSsnResetRequest(OutgoingSsnResetRequestParameter {
                    request_seq_nbr,
                    sender_last_assigned_tsn,
                    streams,
                    ..
                }) => {
                    if Self::validate_req_seq_nbr(
                        request_seq_nbr,
                        tcb.last_processed_req_seq_nbr,
                        tcb.last_processed_req_result,
                        &mut responses,
                    ) {
                        tcb.last_processed_req_seq_nbr = request_seq_nbr;
                        tcb.last_processed_req_result = if sender_last_assigned_tsn
                            > tcb.data_tracker.last_cumulative_acked_tsn()
                        {
                            // From <https://datatracker.ietf.org/doc/html/rfc6525#section-5.2.2>:
                            //
                            //   E2: If the Sender's Last Assigned TSN is greater than the
                            //   cumulative acknowledgment point, then the endpoint MUST enter
                            //   "deferred reset processing".
                            //
                            //   [...] If the endpoint enters "deferred reset processing", it MUST
                            //   put a Re-configuration Response Parameter into a RE-CONFIG chunk
                            //   indicating "In progress" and MUST send the RE-CONFIG chunk.
                            tcb.reassembly_queue
                                .enter_deferred_reset(sender_last_assigned_tsn, &streams);
                            ReconfigurationResponseResult::InProgress
                        } else {
                            // From <https://datatracker.ietf.org/doc/html/rfc6525#section-5.2.2>:
                            //
                            //   E3: If no stream numbers are listed in the parameter, then all
                            //   incoming streams MUST be reset to 0 as the next expected SSN. If
                            //   specific stream numbers are listed, then only these specific
                            //   streams MUST be reset to 0, and all other non-listed SSNs remain
                            //   unchanged.
                            //
                            //   E4: Any queued TSNs (queued at step E2) MUST now be released and
                            //   processed normally."
                            tcb.reassembly_queue.reset_streams_and_leave_deferred_reset(&streams);
                            self.events
                                .borrow_mut()
                                .add(SocketEvent::OnIncomingStreamReset(streams));
                            ReconfigurationResponseResult::SuccessPerformed
                        };
                        responses.push(Parameter::ReconfigurationResponse(
                            ReconfigurationResponseParameter {
                                response_seq_nbr: request_seq_nbr,
                                result: tcb.last_processed_req_result,
                                sender_next_tsn: None,
                                receiver_next_tsn: None,
                            },
                        ));
                    }
                }
                Parameter::IncomingSsnResetRequest(IncomingSsnResetRequestParameter {
                    request_seq_nbr,
                    ..
                }) => {
                    if Self::validate_req_seq_nbr(
                        request_seq_nbr,
                        tcb.last_processed_req_seq_nbr,
                        tcb.last_processed_req_result,
                        &mut responses,
                    ) {
                        responses.push(Parameter::ReconfigurationResponse(
                            ReconfigurationResponseParameter {
                                response_seq_nbr: request_seq_nbr,
                                result: ReconfigurationResponseResult::SuccessNothingToDo,
                                sender_next_tsn: None,
                                receiver_next_tsn: None,
                            },
                        ));
                        tcb.last_processed_req_seq_nbr = request_seq_nbr;
                    }
                }
                Parameter::ReconfigurationResponse(ReconfigurationResponseParameter {
                    response_seq_nbr,
                    result,
                    ..
                }) => {
                    if let CurrentResetRequest::Inflight(InflightResetRequest {
                        request_sequence_number,
                        request,
                    }) = &tcb.current_reset_request
                    {
                        if response_seq_nbr == *request_sequence_number {
                            tcb.reconfig_timer.stop();

                            tcb.current_reset_request = match result {
                                ReconfigurationResponseResult::SuccessNothingToDo
                                | ReconfigurationResponseResult::SuccessPerformed => {
                                    self.events.borrow_mut().add(
                                        SocketEvent::OnStreamsResetPerformed(
                                            request.streams.clone(),
                                        ),
                                    );
                                    self.send_queue.commit_reset_streams();

                                    CurrentResetRequest::None
                                }
                                ReconfigurationResponseResult::InProgress => {
                                    tcb.reconfig_timer.set_duration(tcb.rto.rto());
                                    tcb.reconfig_timer.start(now);

                                    CurrentResetRequest::Prepared(request.clone())
                                }
                                ReconfigurationResponseResult::Denied
                                | ReconfigurationResponseResult::ErrorWrongSSN
                                | ReconfigurationResponseResult::ErrorRequestAlreadyInProgress
                                | ReconfigurationResponseResult::ErrorBadSequenceNumber => {
                                    self.events.borrow_mut().add(
                                        SocketEvent::OnStreamsResetFailed(request.streams.clone()),
                                    );
                                    self.send_queue.rollback_reset_streams();

                                    CurrentResetRequest::None
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        if !responses.is_empty() {
            self.events.borrow_mut().add(SocketEvent::SendPacket(
                tcb.new_packet()
                    .add(Chunk::ReConfig(ReConfigChunk { parameters: responses }))
                    .build(),
            ));
            self.tx_packets_count += 1;
        }

        // Note: Handling this response may result in outgoing stream resets finishing (either
        // successfully or with failure). If there still are pending streams that were waiting for
        // this request to finish, continue resetting them. Also, if a response was processed,
        // pending to-be-reset streams may now have become unpaused. Try to send more DATA chunks.
        self.send_buffered_packets(now);
    }

    fn handle_t1init_timeout(&mut self, now: Instant) {
        let State::CookieWait(s) = &mut self.state else { unreachable!() };
        if s.t1_init.expire(now) {
            if s.t1_init.is_running() {
                self.send_init();
            } else {
                self.internal_close(ErrorKind::TooManyRetries, "No INIT_ACK received".into());
            }
        }
    }

    fn handle_t1cookie_timeout(&mut self, now: Instant) {
        let State::CookieEchoed(s) = &mut self.state else { unreachable!() };
        if s.t1_cookie.expire(now) {
            if !s.t1_cookie.is_running() {
                self.internal_close(ErrorKind::TooManyRetries, "No COOKIE_ACK received".into());
            } else {
                self.send_cookie_echo(now);
            }
        }
    }

    fn handle_shutdown(&mut self) {
        match self.state {
            State::Closed | State::ShutdownReceived(_) | State::ShutdownAckSent(_) => {
                // Nothing to do.
            }
            State::CookieWait(_) | State::CookieEchoed(_) => {
                // From <https://datatracker.ietf.org/doc/html/rfc9260#section-9.2-21>:
                //
                //   If a SHUTDOWN chunk is received in the COOKIE-WAIT or COOKIE ECHOED state, the
                //   SHUTDOWN chunk SHOULD be silently discarded.
            }
            State::Established(_) | State::ShutdownPending(_) => {
                // From <https://datatracker.ietf.org/doc/html/rfc9260#section-9.2-6>:
                //
                //   Upon reception of the SHUTDOWN chunk, the peer endpoint does the following:
                //   enter the SHUTDOWN-RECEIVED state, stop accepting new data from its SCTP user,
                //   and verify, by checking the Cumulative TSN Ack field of the chunk, that all its
                //   outstanding DATA chunks have been received by the SHUTDOWN chunk sender.
                transition_between!(self.state,
                    State::Established(tcb), State::ShutdownPending(tcb) =>
                        State::ShutdownReceived(tcb)
                );

                self.maybe_send_shutdown_ack();
            }
            State::ShutdownSent(_) => {
                // From <https://datatracker.ietf.org/doc/html/rfc9260#section-9.2-22>:
                //
                //   If an endpoint is in the SHUTDOWN-SENT state and receives a SHUTDOWN chunk from
                //   its peer, the endpoint SHOULD respond immediately with a SHUTDOWN ACK chunk to
                //   its peer and move into the SHUTDOWN-ACK-SENT state, restarting its T2-shutdown
                //   timer.
                transition_between!(self.state,
                    State::ShutdownSent(ShutdownSentState { tcb, .. }) =>
                        State::ShutdownAckSent(tcb)
                );

                self.send_shutdown_ack();
            }
        }
    }

    fn handle_shutdown_ack(&mut self, header: &CommonHeader) {
        match &self.state {
            State::ShutdownSent(ShutdownSentState { tcb, .. }) | State::ShutdownAckSent(tcb) => {
                // From <https://datatracker.ietf.org/doc/html/rfc9260#section-9.2-14>:
                //
                //   Upon the receipt of the SHUTDOWN ACK chunk, the sender of the SHUTDOWN chunk
                //   MUST stop the T2-shutdown timer, send a SHUTDOWN COMPLETE chunk to its peer,
                //   and remove all record of the association.
                //
                // From <https://datatracker.ietf.org/doc/html/rfc9260#section-9.2-23>:
                //
                //   If an endpoint is in the SHUTDOWN-ACK-SENT state and receives a SHUTDOWN ACK,
                //   it MUST stop the T2-shutdown timer, send a SHUTDOWN COMPLETE chunk to its peer,
                //   and remove all record of the association.
                self.events.borrow_mut().add(SocketEvent::SendPacket(
                    tcb.new_packet()
                        .add(Chunk::ShutdownComplete(ShutdownCompleteChunk {
                            tag_reflected: false,
                        }))
                        .build(),
                ));
                self.tx_packets_count += 1;
                self.internal_close(ErrorKind::NoError, "".to_string());
            }
            _ => {
                // From <https://datatracker.ietf.org/doc/html/rfc9260#section-8.5.1-1.10.1.1>:
                //
                //   If the receiver is in COOKIE-ECHOED or COOKIE-WAIT state, the procedures in
                //   Section 8.4 SHOULD be followed; in other words, it is treated as an OOTB
                //   packet.
                //
                // From <https://datatracker.ietf.org/doc/html/rfc9260#section-8.4-3.5.1>:
                //
                //   If the packet contains a SHUTDOWN ACK chunk, the receiver SHOULD respond to the
                //   sender of the OOTB packet with a SHUTDOWN COMPLETE chunk. When sending the
                //   SHUTDOWN COMPLETE chunk, the receiver of the OOTB packet MUST fill in the
                //   Verification Tag field of the outbound packet with the Verification Tag
                //   received in the SHUTDOWN ACK chunk and set the T bit in the Chunk Flags to
                //   indicate that the Verification Tag is reflected.
                self.events.borrow_mut().add(SocketEvent::SendPacket(
                    SctpPacketBuilder::new(
                        header.verification_tag,
                        self.options.local_port,
                        self.options.remote_port,
                        self.options.mtu,
                    )
                    .add(Chunk::ShutdownComplete(ShutdownCompleteChunk { tag_reflected: true }))
                    .build(),
                ));
                self.tx_packets_count += 1;
            }
        }
    }

    fn handle_shutdown_complete(&mut self, _chunk: ShutdownCompleteChunk) {
        if let State::ShutdownAckSent(_) = self.state {
            // From <https://datatracker.ietf.org/doc/html/rfc9260#section-9.2-15>:
            //
            //   Upon reception of the SHUTDOWN COMPLETE chunk, the endpoint verifies that it is in
            //   the SHUTDOWN-ACK-SENT state; if it is not, the chunk SHOULD be discarded. If the
            //   endpoint is in the SHUTDOWN-ACK-SENT state, the endpoint SHOULD stop the
            //   T2-shutdown timer and remove all knowledge of the association (and thus the
            //   association enters the CLOSED state).
            self.internal_close(ErrorKind::NoError, "".to_string());
        }
    }

    fn maybe_send_shutdown_on_packet_received(&mut self, now: Instant, chunks: &[Chunk]) {
        if let State::ShutdownSent(s) = &mut self.state {
            if chunks.iter().any(|c| matches!(c, Chunk::Data(_))) {
                // From <https://datatracker.ietf.org/doc/html/rfc9260#section-9.2-10>:
                //
                //   While in the SHUTDOWN-SENT state, the SHUTDOWN chunk sender MUST immediately
                //   respond to each received packet containing one or more DATA chunks with a
                //   SHUTDOWN chunk and restart the T2-shutdown timer.
                s.t2_shutdown.set_duration(s.tcb.rto.rto());
                s.t2_shutdown.start(now);
                self.send_shutdown();
            }
        }
    }
}

impl DcSctpSocket for Socket<'_> {
    fn poll_event(&mut self) -> Option<SocketEvent> {
        self.events.borrow_mut().next_event()
    }

    fn connect(&mut self) {
        let State::Closed = self.state else {
            warn!("Called connect on a socket that is not closed");
            return;
        };
        let now = *self.now.borrow();
        let mut t1_init = Timer::new(
            self.options.t1_init_timeout,
            BackoffAlgorithm::Exponential,
            self.options.max_init_retransmits,
            None,
        );
        t1_init.start(now);
        let initial_tsn = Tsn(rand::thread_rng().gen_range(MIN_INITIAL_TSN..MAX_INITIAL_TSN));
        let verification_tag =
            rand::thread_rng().gen_range(MIN_VERIFICATION_TAG..MAX_VERIFICATION_TAG);
        self.state = State::CookieWait(CookieWaitState { t1_init, initial_tsn, verification_tag });
        self.send_init();
    }

    fn handle_input(&mut self, packet: &[u8]) {
        self.rx_packets_count += 1;
        let now = *self.now.borrow();
        log_packet(&self.name, now - self.start_time, false, packet);

        match SctpPacket::from_bytes(packet, &self.options) {
            Err(_e) => {
                self.events.borrow_mut().add(SocketEvent::OnError(
                    ErrorKind::ParseFailed,
                    "Failed to parse SCTP packet".into(),
                ));
            }
            Ok(packet) => {
                self.maybe_send_shutdown_on_packet_received(now, &packet.chunks);
                for chunk in packet.chunks {
                    match chunk {
                        Chunk::Data(DataChunk { tsn, data }) => self.handle_data(now, tsn, data),
                        Chunk::Init(c) => self.handle_init(c),
                        Chunk::InitAck(c) => self.handle_init_ack(now, c),
                        Chunk::Sack(c) => self.handle_sack(now, c),
                        Chunk::Abort(c) => self.handle_abort(c),
                        Chunk::Shutdown(_) => self.handle_shutdown(),
                        Chunk::ShutdownAck(_) => self.handle_shutdown_ack(&packet.common_header),
                        Chunk::Error(c) => self.handle_error(c),
                        Chunk::CookieEcho(c) => {
                            self.handle_cookie_echo(now, &packet.common_header, c)
                        }
                        Chunk::CookieAck(_) => self.handle_cookie_ack(now),
                        Chunk::HeartbeatRequest(c) => self.handle_heartbeat_req(c),
                        Chunk::HeartbeatAck(c) => self.handle_heartbeat_ack(now, c),
                        Chunk::ShutdownComplete(c) => self.handle_shutdown_complete(c),
                        Chunk::ReConfig(c) => self.handle_reconfig(now, c),
                        Chunk::ForwardTsn(ForwardTsnChunk {
                            new_cumulative_tsn,
                            skipped_streams,
                        }) => self.handle_forward_tsn(now, new_cumulative_tsn, skipped_streams),
                        Chunk::IData(IDataChunk { tsn, data }) => self.handle_data(now, tsn, data),
                        Chunk::IForwardTsn(IForwardTsnChunk {
                            new_cumulative_tsn,
                            skipped_streams,
                        }) => self.handle_forward_tsn(now, new_cumulative_tsn, skipped_streams),
                        Chunk::Unknown(c) => {
                            if !self.handle_unrecognized_chunk(c) {
                                break;
                            }
                        }
                    }
                }
                self.maybe_send_sack(now);
            }
        }
    }

    fn advance_time(&mut self, now: Instant) {
        self.now.replace(now);
        match &mut self.state {
            State::Closed => {}
            State::CookieWait(ref s) => {
                debug_assert!(s.t1_init.is_running());
                self.handle_t1init_timeout(now);
            }
            State::CookieEchoed(s) => {
                // NOTE: Only let the t1-cookie timer drive retransmissions.
                debug_assert!(s.t1_cookie.is_running());
                s.tcb.data_tracker.handle_timeout(now);
                self.handle_t1cookie_timeout(now);
            }
            State::Established(tcb)
            | State::ShutdownPending(tcb)
            | State::ShutdownSent(ShutdownSentState { tcb, .. })
            | State::ShutdownReceived(tcb)
            | State::ShutdownAckSent(tcb) => {
                tcb.data_tracker.handle_timeout(now);
                if tcb.retransmission_queue.handle_timeout(now) {
                    self.tx_error_counter.increment();
                }
                self.handle_heartbeat_timeouts(now);
                self.handle_reconfig_timeout(now);
                self.handle_t2_shutdown_timeout(now);
            }
        }
        if let Some(tcb) = self.state.tcb_mut() {
            if self.tx_error_counter.is_exhausted() {
                self.events.borrow_mut().add(SocketEvent::SendPacket(
                    tcb.new_packet()
                        .add(Chunk::Abort(AbortChunk {
                            error_causes: vec![ErrorCause::UserInitiatedAbort(
                                UserInitiatedAbortErrorCause {
                                    reason: "Too many retransmissions".into(),
                                },
                            )],
                        }))
                        .build(),
                ));
                self.tx_packets_count += 1;
                self.internal_close(ErrorKind::TooManyRetries, "Too many retransmissions".into());
                return;
            }

            // From <https://datatracker.ietf.org/doc/html/rfc9260#section-5.1-2.3.2>:
            //
            //   [...] until the COOKIE ACK chunk is returned, the sender MUST NOT send any other
            //   packets to the peer.
            if !matches!(self.state, State::CookieEchoed(_)) {
                self.send_buffered_packets(now);
            }
        }
    }

    fn poll_timeout(&self) -> Option<Instant> {
        match self.state {
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
                timeout = closest_timeout(timeout, self.heartbeat_interval.next_expiry());
                timeout = closest_timeout(timeout, self.heartbeat_timeout.next_expiry());
                if let State::ShutdownSent(ref s) = self.state {
                    timeout = closest_timeout(timeout, s.t2_shutdown.next_expiry());
                };
                timeout
            }
        }
    }

    fn shutdown(&mut self) {
        let now = *self.now.borrow();

        // From <https://datatracker.ietf.org/doc/html/rfc9260#section-9.2-2>:
        //
        //   Upon receipt of the SHUTDOWN primitive from its upper layer, the endpoint enters the
        //   SHUTDOWN-PENDING state and remains there until all outstanding data has been
        //   acknowledged by its peer.
        match self.state {
            State::Closed => {
                // Already closed.
            }
            State::CookieWait(_) => {
                // Connection closed during the initial connection phase. There is no outstanding
                // data, so the socket can just be closed (stopping any connection timers, if any),
                // as this is the client's intention, by calling [shutdown()].
                self.internal_close(ErrorKind::NoError, "".to_string());
            }
            State::ShutdownPending(_)
            | State::ShutdownSent(_)
            | State::ShutdownAckSent(_)
            | State::ShutdownReceived(_) => {
                // Already shutting down.
            }
            State::CookieEchoed(_) | State::Established(_) => {
                transition_between!(self.state,
                    State::CookieEchoed(CookieEchoState { tcb, .. }) | State::Established(tcb) =>
                        State::ShutdownPending(tcb)
                );

                self.maybe_send_shutdown(now);
            }
        }
    }

    fn close(&mut self) {
        if !matches!(self.state, State::Closed) {
            if let Some(tcb) = self.state.tcb() {
                self.events.borrow_mut().add(SocketEvent::SendPacket(
                    tcb.new_packet()
                        .add(Chunk::Abort(AbortChunk {
                            error_causes: vec![ErrorCause::UserInitiatedAbort(
                                UserInitiatedAbortErrorCause { reason: "Close called".into() },
                            )],
                        }))
                        .build(),
                ));
                self.tx_packets_count += 1;
            }
            self.internal_close(ErrorKind::NoError, String::new());
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

    fn options(&self) -> Options {
        self.options.clone()
    }

    fn set_max_message_size(&mut self, max_message_size: usize) {
        self.options.max_message_size = max_message_size;
    }

    fn set_stream_priority(&mut self, stream_id: StreamId, priority: u16) {
        self.send_queue.set_priority(stream_id, priority);
    }

    fn get_stream_priority(&self, stream_id: StreamId) -> u16 {
        self.send_queue.get_priority(stream_id)
    }

    fn send(&mut self, message: Message, send_options: &SendOptions) -> SendStatus {
        let add_error_events = |kind, msg| {
            if let Some(ref lifecycle_id) = send_options.lifecycle_id {
                self.events.borrow_mut().add(SocketEvent::OnLifecycleEnd(lifecycle_id.clone()));
            }
            self.events.borrow_mut().add(SocketEvent::OnError(kind, String::from(msg)));
        };

        if message.payload.is_empty() {
            add_error_events(ErrorKind::ProtocolViolation, "Unable to send empty message");
            return SendStatus::ErrorMessageEmpty;
        }
        if message.payload.len() > self.options.max_message_size {
            add_error_events(ErrorKind::ProtocolViolation, "Unable to send too large message");
            return SendStatus::ErrorMessageTooLarge;
        }

        if self.send_queue.total_buffered_amount() >= self.options.max_send_buffer_size
            || self.send_queue.buffered_amount(message.stream_id)
                >= self.options.per_stream_send_queue_limit
        {
            add_error_events(
                ErrorKind::ResourceExhaustion,
                "Unable to send message as the send queue is full",
            );
            return SendStatus::ErrorResourceExhaustion;
        }

        let now = *self.now.borrow();
        self.tx_messages_count += 1;
        self.send_queue.add(now, message, send_options);
        self.send_buffered_packets(now);
        SendStatus::Success
    }

    fn send_many(
        &mut self,
        _messages: &mut [crate::api::Message],
        _send_options: &crate::api::SendOptions,
    ) -> Vec<SendStatus> {
        todo!()
    }

    fn reset_streams(&mut self, outgoing_streams: &[StreamId]) -> ResetStreamsStatus {
        let Some(tcb) = self.state.tcb_mut() else {
            return ResetStreamsStatus::NotConnected;
        };
        if !tcb.capabilities.reconfig {
            return ResetStreamsStatus::NotSupported;
        }
        let now = *self.now.borrow();
        for stream_id in outgoing_streams {
            self.send_queue.prepare_reset_stream(*stream_id);
        }

        // This will send the SSN reset request control messagae.
        self.send_buffered_packets(now);

        ResetStreamsStatus::Performed
    }

    fn buffered_amount(&self, stream_id: StreamId) -> usize {
        self.send_queue.buffered_amount(stream_id)
    }

    fn buffered_amount_low_threshold(&self, stream_id: StreamId) -> usize {
        self.send_queue.buffered_amount_low_threshold(stream_id)
    }

    fn set_buffered_amount_low_threshold(&mut self, stream_id: StreamId, bytes: usize) {
        self.send_queue.set_buffered_amount_low_threshold(stream_id, bytes);
    }

    fn get_metrics(&self) -> Option<Metrics> {
        let tcb = self.state.tcb()?;

        let packet_payload_size =
            self.options.mtu - sctp_packet::COMMON_HEADER_SIZE - data_chunk::HEADER_SIZE;
        Some(Metrics {
            tx_packets_count: self.tx_packets_count,
            tx_messages_count: self.tx_messages_count,
            rtx_packets_count: tcb.retransmission_queue.rtx_packets_count(),
            rtx_bytes_count: tcb.retransmission_queue.rtx_bytes_count(),
            cwnd_bytes: tcb.retransmission_queue.cwnd(),
            srtt: tcb.rto.srtt(),
            unack_data_count: tcb.retransmission_queue.unacked_items()
                + self.send_queue.total_buffered_amount().div_ceil(packet_payload_size),
            rx_packets_count: self.rx_packets_count,
            rx_messages_count: tcb.reassembly_queue.rx_messages_count(),
            peer_rwnd_bytes: tcb.retransmission_queue.rwnd() as u32,
            peer_implementation: self.peer_implementation,
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
                self.send_queue.get_handover_readiness() | tcb.get_handover_readiness()
            }
            _ => HandoverReadiness::WRONG_CONNECTION_STATE,
        }
    }

    fn restore_from_state(&mut self, state: &SocketHandoverState) {
        if !matches!(self.state, State::Closed) {
            self.events.borrow_mut().add(SocketEvent::OnError(
                ErrorKind::NotConnected,
                "Only closed socket can be restored from state".into(),
            ));
            return;
        } else if matches!(state.socket_state, HandoverSocketState::Closed) {
            // Nothing to do.
            return;
        }

        self.send_queue.restore_from_state(state);

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
            &self.options,
            state.my_verification_tag,
            Tsn(state.my_initial_tsn),
            state.peer_verification_tag,
            Tsn(state.peer_initial_tsn),
            state.tie_tag,
            /* rwnd */ 0,
            capabilities,
            Rc::clone(&self.events),
        );
        tcb.restore_from_state(state);

        self.state = State::Established(tcb);
        self.events.borrow_mut().add(SocketEvent::OnConnected());
    }

    fn get_handover_state_and_close(&mut self) -> Option<SocketHandoverState> {
        if !self.get_handover_readiness().is_ready() {
            return None;
        }

        let mut handover_state = SocketHandoverState::default();

        if let State::Established(tcb) = &self.state {
            handover_state.socket_state = HandoverSocketState::Connected;
            self.send_queue.add_to_handover_state(&mut handover_state);
            tcb.add_to_handover_state(&mut handover_state);
            self.events.borrow_mut().add(SocketEvent::OnClosed());
            self.state = State::Closed;
        }
        Some(handover_state)
    }
}
