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

use crate::api::ErrorKind;
use crate::api::ResetStreamsError;
use crate::api::SocketEvent;
use crate::api::SocketTime;
use crate::api::StreamId;
use crate::packet::chunk::Chunk;
use crate::packet::incoming_ssn_reset_request_parameter::IncomingSsnResetRequestParameter;
use crate::packet::outgoing_ssn_reset_request_parameter::OutgoingSsnResetRequestParameter;
use crate::packet::parameter::Parameter;
use crate::packet::re_config_chunk::ReConfigChunk;
use crate::packet::reconfiguration_response_parameter::ReconfigurationResponseParameter;
use crate::packet::reconfiguration_response_parameter::ReconfigurationResponseResult;
use crate::socket::context::Context;
use crate::socket::state::State;
use crate::socket::transmission_control_block::CurrentResetRequest;
use crate::socket::transmission_control_block::InflightResetRequest;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReqSeqNbrValidationResult {
    Valid,
    Retransmission,
    BadSequenceNumber,
}

pub(crate) fn do_reset_streams(
    state: &mut State,
    ctx: &mut Context,
    now: SocketTime,
    outgoing_streams: &[StreamId],
) -> Result<(), ResetStreamsError> {
    let Some(tcb) = state.tcb_mut() else {
        return Err(ResetStreamsError::NotConnected);
    };
    if !tcb.capabilities.reconfig {
        return Err(ResetStreamsError::NotSupported);
    }
    for stream_id in outgoing_streams {
        ctx.send_queue.prepare_reset_stream(*stream_id);
    }

    // This will send the SSN reset request control messagae.
    ctx.send_buffered_packets(state, now);

    Ok(())
}

pub(crate) fn handle_reconfig(
    state: &mut State,
    ctx: &mut Context,
    now: SocketTime,
    chunk: ReConfigChunk,
) {
    let Some(tcb) = state.tcb_mut() else {
        return;
    };

    if chunk.parameters.is_empty() {
        ctx.events.borrow_mut().add(SocketEvent::OnError(
            ErrorKind::ProtocolViolation,
            "RE-CONFIG chunk must have at least one parameter".into(),
        ));
        return;
    }

    let mut responses: Vec<Parameter> = Vec::new();
    let mut has_seen_outgoing_reset_request = false;

    for parameter in chunk.parameters {
        match parameter {
            Parameter::OutgoingSsnResetRequest(OutgoingSsnResetRequestParameter {
                request_seq_nbr,
                sender_last_assigned_tsn,
                streams,
                ..
            }) => {
                if has_seen_outgoing_reset_request {
                    ctx.events.borrow_mut().add(SocketEvent::OnError(
                        ErrorKind::ProtocolViolation,
                        "RE-CONFIG chunk must not have multiple Outgoing SSN Reset Request parameters"
                            .into(),
                    ));
                    return;
                }
                has_seen_outgoing_reset_request = true;

                let validation_result =
                    validate_req_seq_nbr(request_seq_nbr, tcb.last_processed_req_seq_nbr);

                if validation_result == ReqSeqNbrValidationResult::BadSequenceNumber {
                    responses.push(Parameter::ReconfigurationResponse(
                        ReconfigurationResponseParameter {
                            response_seq_nbr: request_seq_nbr,
                            result: ReconfigurationResponseResult::ErrorBadSequenceNumber,
                            sender_next_tsn: None,
                            receiver_next_tsn: None,
                        },
                    ));
                    continue;
                }

                if validation_result == ReqSeqNbrValidationResult::Retransmission
                    && tcb.last_processed_req_result != ReconfigurationResponseResult::InProgress
                {
                    responses.push(Parameter::ReconfigurationResponse(
                        ReconfigurationResponseParameter {
                            response_seq_nbr: request_seq_nbr,
                            result: tcb.last_processed_req_result,
                            sender_next_tsn: None,
                            receiver_next_tsn: None,
                        },
                    ));
                    continue;
                }

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
                    tcb.reassembly_queue.enter_deferred_reset(sender_last_assigned_tsn, &streams);
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
                    ctx.events.borrow_mut().add(SocketEvent::OnIncomingStreamReset(streams));
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
            Parameter::IncomingSsnResetRequest(IncomingSsnResetRequestParameter {
                request_seq_nbr,
                ..
            }) => {
                let validation_result =
                    validate_req_seq_nbr(request_seq_nbr, tcb.last_processed_req_seq_nbr);
                if validation_result == ReqSeqNbrValidationResult::Valid
                    || validation_result == ReqSeqNbrValidationResult::Retransmission
                {
                    responses.push(Parameter::ReconfigurationResponse(
                        ReconfigurationResponseParameter {
                            response_seq_nbr: request_seq_nbr,
                            result: ReconfigurationResponseResult::SuccessNothingToDo,
                            sender_next_tsn: None,
                            receiver_next_tsn: None,
                        },
                    ));
                    tcb.last_processed_req_seq_nbr = request_seq_nbr;
                    tcb.last_processed_req_result =
                        ReconfigurationResponseResult::SuccessNothingToDo;
                } else {
                    responses.push(Parameter::ReconfigurationResponse(
                        ReconfigurationResponseParameter {
                            response_seq_nbr: request_seq_nbr,
                            result: ReconfigurationResponseResult::ErrorBadSequenceNumber,
                            sender_next_tsn: None,
                            receiver_next_tsn: None,
                        },
                    ));
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
                                ctx.events.borrow_mut().add(SocketEvent::OnStreamsResetPerformed(
                                    request.streams.clone(),
                                ));
                                ctx.send_queue.commit_reset_streams();

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
                                ctx.events.borrow_mut().add(SocketEvent::OnStreamsResetFailed(
                                    request.streams.clone(),
                                ));
                                ctx.send_queue.rollback_reset_streams();

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
        ctx.events.borrow_mut().add(SocketEvent::SendPacket(
            tcb.new_packet().add(&Chunk::ReConfig(ReConfigChunk { parameters: responses })).build(),
        ));
        ctx.tx_packets_count += 1;
    }

    // Note: Handling this response may result in outgoing stream resets finishing (either
    // successfully or with failure). If there still are pending streams that were waiting for
    // this request to finish, continue resetting them. Also, if a response was processed,
    // pending to-be-reset streams may now have become unpaused. Try to send more DATA chunks.
    ctx.send_buffered_packets(state, now);
}

/// Handles the stream reconfiguration timers.
///
/// Returns `true` if any timer expired.
pub(crate) fn handle_reconfig_timeout(
    state: &mut State,
    ctx: &mut Context,
    now: SocketTime,
) -> bool {
    let tcb = state.tcb_mut().unwrap();
    if !tcb.reconfig_timer.expire(now) {
        return false;
    }

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
            ctx.tx_error_counter.increment();
        }
    }
    if !ctx.tx_error_counter.is_exhausted() {
        tcb.reconfig_timer.set_duration(tcb.rto.rto());
        let mut builder = tcb.new_packet();
        tcb.add_prepared_ssn_reset_request(&mut builder);
        ctx.events.borrow_mut().add(SocketEvent::SendPacket(builder.build()));
        ctx.tx_packets_count += 1;
    }
    true
}

fn validate_req_seq_nbr(
    req_seq_nbr: u32,
    last_processed_req_seq_nbr: u32,
) -> ReqSeqNbrValidationResult {
    if req_seq_nbr == last_processed_req_seq_nbr {
        // From <https://datatracker.ietf.org/doc/html/rfc6525#section-5.2.1>:
        //
        //   If the received RE-CONFIG chunk contains at least one request and based on the
        //   analysis of the Re-configuration Request Sequence Numbers this is the last received
        //   RE-CONFIG chunk (i.e., a retransmission), the same RE-CONFIG chunk MUST to be sent
        //   back in response, as it was earlier.
        ReqSeqNbrValidationResult::Retransmission
    } else if req_seq_nbr != last_processed_req_seq_nbr.wrapping_add(1) {
        // Too old, too new, from wrong association etc.
        ReqSeqNbrValidationResult::BadSequenceNumber
    } else {
        ReqSeqNbrValidationResult::Valid
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EventSink;
    use crate::api::Message;
    use crate::api::Options;
    use crate::api::PpId;
    use crate::api::SctpImplementation;
    use crate::api::SendOptions;
    use crate::events::Events;
    use crate::packet::SkippedStream;
    use crate::packet::sctp_packet::SctpPacket;
    use crate::socket::capabilities::Capabilities;
    use crate::socket::context::TxErrorCounter;
    use crate::socket::transmission_control_block::TransmissionControlBlock;
    use crate::testing::data_sequencer::DataSequencer;
    use crate::timer::BackoffAlgorithm;
    use crate::timer::Timer;
    use crate::tx::send_queue::SendQueue;
    use crate::types::Ssn;
    use crate::types::Tsn;
    use std::cell::RefCell;
    use std::rc::Rc;
    use std::time::Duration;

    fn create_test_objects(
        my_initial_tsn: Tsn,
        peer_initial_tsn: Tsn,
    ) -> (State, Context, Rc<RefCell<Events>>) {
        let options = Options::default();
        let capabilities = Capabilities { reconfig: true, ..Default::default() };

        let events = Rc::new(RefCell::new(Events::new()));

        let tcb = TransmissionControlBlock::new(
            &options,
            0, // my_verification_tag
            my_initial_tsn,
            0, // peer_verification_tag
            peer_initial_tsn,
            0,      // tie_tag
            131072, // a_rwnd
            capabilities,
            Rc::clone(&events) as Rc<RefCell<dyn EventSink>>,
        );

        let state = State::Established(tcb);

        let send_queue =
            SendQueue::new(options.mtu, &options, Rc::clone(&events) as Rc<RefCell<dyn EventSink>>);
        let context = Context {
            options,
            events: Rc::clone(&events) as Rc<RefCell<dyn EventSink>>,
            send_queue,
            limit_forward_tsn_until: SocketTime::zero(),
            heartbeat_interval: Timer::new(
                Duration::from_secs(30),
                BackoffAlgorithm::Fixed,
                None,
                None,
            ),
            heartbeat_timeout: Timer::new(
                Duration::from_secs(1),
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
            tx_error_counter: TxErrorCounter::new(Some(10)),
        };

        (state, context, events)
    }

    fn expect_sent_packet(events: &Rc<RefCell<Events>>, options: &Options) -> SctpPacket {
        loop {
            let event = events.borrow_mut().next_event().expect("expected event");
            match event {
                SocketEvent::SendPacket(packet) => {
                    return SctpPacket::from_bytes(&packet, options).expect("valid packet");
                }
                SocketEvent::OnBufferedAmountLow(_) => {
                    // Ignore these - handling them explicitly in the tests just create noise.
                    continue;
                }
                _ => {
                    panic!("Expected SendPacket, got {:?}", event);
                }
            }
        }
    }

    fn expect_sent_reconfig_chunk(
        events: &Rc<RefCell<Events>>,
        options: &Options,
    ) -> ReConfigChunk {
        let packet = expect_sent_packet(events, options);
        packet
            .chunks
            .into_iter()
            .find_map(|c| match c {
                Chunk::ReConfig(r) => Some(r),
                _ => None,
            })
            .expect("Expected ReConfig chunk")
    }

    fn expect_sent_reconfig_response(
        events: &Rc<RefCell<Events>>,
        options: &Options,
    ) -> ReconfigurationResponseParameter {
        let chunk = expect_sent_reconfig_chunk(events, options);
        chunk
            .parameters
            .into_iter()
            .find_map(|p| match p {
                Parameter::ReconfigurationResponse(r) => Some(r),
                _ => None,
            })
            .expect("Expected ReconfigurationResponse")
    }

    fn expect_sent_reset_request(
        events: &Rc<RefCell<Events>>,
        options: &Options,
    ) -> OutgoingSsnResetRequestParameter {
        let chunk = expect_sent_reconfig_chunk(events, options);
        chunk
            .parameters
            .into_iter()
            .find_map(|p| match p {
                Parameter::OutgoingSsnResetRequest(r) => Some(r),
                _ => None,
            })
            .expect("Expected OutgoingSsnResetRequest")
    }

    fn expect_incoming_stream_reset_event(
        events: &Rc<RefCell<Events>>,
        expected_streams: Vec<StreamId>,
    ) {
        let event = events.borrow_mut().next_event().expect("expected event");
        let SocketEvent::OnIncomingStreamReset(streams) = event else {
            panic!("Expected OnIncomingStreamReset, got {:?}", event);
        };
        assert_eq!(streams, expected_streams);
    }

    #[test]
    fn chunk_with_no_parameters_returns_error() {
        let my_initial_tsn = Tsn(0);
        let peer_initial_tsn = Tsn(10);
        let (mut state, mut ctx, events) = create_test_objects(my_initial_tsn, peer_initial_tsn);

        handle_reconfig(
            &mut state,
            &mut ctx,
            SocketTime::zero(),
            ReConfigChunk { parameters: vec![] },
        );

        let event = events.borrow_mut().next_event().expect("expected event");
        let SocketEvent::OnError(kind, msg) = event else {
            panic!("Expected OnError, got {:?}", event);
        };

        assert_eq!(kind, ErrorKind::ProtocolViolation);
        assert_eq!(msg, "RE-CONFIG chunk must have at least one parameter");
    }

    #[test]
    fn chunk_with_invalid_parameters_returns_error() {
        let my_initial_tsn = Tsn(0);
        let peer_initial_tsn = Tsn(10);
        let (mut state, mut ctx, events) = create_test_objects(my_initial_tsn, peer_initial_tsn);

        // Two OutgoingSSNResetRequestParameter in a RE-CONFIG is not valid.
        let param1 = Parameter::OutgoingSsnResetRequest(OutgoingSsnResetRequestParameter {
            request_seq_nbr: 1,
            response_seq_nbr: 10,
            sender_last_assigned_tsn: Tsn(10),
            streams: vec![StreamId(1)],
        });
        let param2 = Parameter::OutgoingSsnResetRequest(OutgoingSsnResetRequestParameter {
            request_seq_nbr: 2,
            response_seq_nbr: 10,
            sender_last_assigned_tsn: Tsn(10),
            streams: vec![StreamId(2)],
        });

        handle_reconfig(
            &mut state,
            &mut ctx,
            SocketTime::zero(),
            ReConfigChunk { parameters: vec![param1, param2] },
        );

        let event = events.borrow_mut().next_event().expect("expected event");
        let SocketEvent::OnError(kind, msg) = event else {
            panic!("Expected OnError, got {:?}", event);
        };

        assert_eq!(kind, ErrorKind::ProtocolViolation);
        assert_eq!(
            msg,
            "RE-CONFIG chunk must not have multiple Outgoing SSN Reset Request parameters"
        );
    }

    #[test]
    fn fail_to_deliver_without_resetting_stream() {
        let my_initial_tsn = Tsn(0);
        let peer_initial_tsn = Tsn(10);
        let (mut state, _, _) = create_test_objects(my_initial_tsn, peer_initial_tsn);
        let mut seq = DataSequencer::new(StreamId(1));

        // Receive two messages (moves next expected SSN from 0 to 2).
        let tcb = state.tcb_mut().unwrap();
        tcb.data_tracker.observe(SocketTime::zero(), Tsn(10), false);
        tcb.reassembly_queue.add(Tsn(10), seq.ordered("1234", "BE"));
        tcb.data_tracker.observe(SocketTime::zero(), Tsn(11), false);
        tcb.reassembly_queue.add(Tsn(11), seq.ordered("2345", "BE"));

        assert_eq!(tcb.reassembly_queue.get_next_message().unwrap().payload, b"1234");
        assert_eq!(tcb.reassembly_queue.get_next_message().unwrap().payload, b"2345");
        assert!(tcb.reassembly_queue.get_next_message().is_none());

        // Simulate sender resetting the stream (SSN reset to 0) but receiver NOT processing it.
        // DataSequencer::new WILL reset SSN to 0.
        let mut seq = DataSequencer::new(StreamId(1));
        tcb.data_tracker.observe(SocketTime::zero(), Tsn(12), false);
        tcb.reassembly_queue.add(Tsn(12), seq.ordered("3456", "BE"));

        // Should NOT be delivered because ReassemblyQueue expects SSN=2, but got SSN=0.
        assert!(tcb.reassembly_queue.get_next_message().is_none());
    }

    #[test]
    fn reset_streams_not_deferred() {
        let my_initial_tsn = Tsn(0);
        let peer_initial_tsn = Tsn(10);
        let (mut state, mut ctx, events) = create_test_objects(my_initial_tsn, peer_initial_tsn);
        let mut seq = DataSequencer::new(StreamId(1));

        // Receive two messages (moves next expected SSN from 0 to 2).
        let tcb = state.tcb_mut().unwrap();
        tcb.data_tracker.observe(SocketTime::zero(), Tsn(10), false);
        tcb.reassembly_queue.add(Tsn(10), seq.ordered("1234", "BE"));
        tcb.data_tracker.observe(SocketTime::zero(), Tsn(11), false);
        tcb.reassembly_queue.add(Tsn(11), seq.ordered("2345", "BE"));

        assert_eq!(tcb.reassembly_queue.get_next_message().unwrap().payload, b"1234");
        assert_eq!(tcb.reassembly_queue.get_next_message().unwrap().payload, b"2345");
        assert!(tcb.reassembly_queue.get_next_message().is_none());

        // Reset, SID=1, TSN=11 (fulfilled).
        handle_reconfig(
            &mut state,
            &mut ctx,
            SocketTime::zero(),
            ReConfigChunk {
                parameters: vec![Parameter::OutgoingSsnResetRequest(
                    OutgoingSsnResetRequestParameter {
                        request_seq_nbr: 10,
                        response_seq_nbr: 3,
                        sender_last_assigned_tsn: Tsn(11),
                        streams: vec![StreamId(1)],
                    },
                )],
            },
        );

        expect_incoming_stream_reset_event(&events, vec![StreamId(1)]);

        let response = expect_sent_reconfig_response(&events, &ctx.options);
        assert_eq!(response.result, ReconfigurationResponseResult::SuccessPerformed);

        // Reset data sequencer for Stream 1 (simulating sender reset)
        let mut seq = DataSequencer::new(StreamId(1));

        let tcb = state.tcb_mut().unwrap();
        tcb.data_tracker.observe(SocketTime::zero(), Tsn(12), false);
        tcb.reassembly_queue.add(Tsn(12), seq.ordered("3456", "BE"));

        assert_eq!(tcb.reassembly_queue.get_next_message().unwrap().payload, b"3456");
    }

    #[test]
    fn reset_streams_deferred() {
        let my_initial_tsn = Tsn(0);
        let peer_initial_tsn = Tsn(10);
        let (mut state, mut ctx, events) = create_test_objects(my_initial_tsn, peer_initial_tsn);
        let mut seq = DataSequencer::new(StreamId(1));

        // TSN 10 is received and acked.
        let tcb = state.tcb_mut().unwrap();
        tcb.data_tracker.observe(SocketTime::zero(), Tsn(10), false);
        tcb.reassembly_queue.add(Tsn(10), seq.ordered("1234", "BE"));

        // Send reset request saying last assigned TSN is 11 (which is missing).
        handle_reconfig(
            &mut state,
            &mut ctx,
            SocketTime::zero(),
            ReConfigChunk {
                parameters: vec![Parameter::OutgoingSsnResetRequest(
                    OutgoingSsnResetRequestParameter {
                        request_seq_nbr: 10,
                        response_seq_nbr: 3,
                        sender_last_assigned_tsn: Tsn(11),
                        streams: vec![StreamId(1)],
                    },
                )],
            },
        );

        // Expect InProgress response (and no OnIncomingStreamReset yet)
        let response = expect_sent_reconfig_response(&events, &ctx.options);
        assert_eq!(response.result, ReconfigurationResponseResult::InProgress);

        while let Some(event) = events.borrow_mut().next_event() {
            if let SocketEvent::OnIncomingStreamReset(_) = event {
                panic!("Unexpected OnIncomingStreamReset event: {:?}", event);
            }
        }

        // Receive the missing TSN 11.
        let tcb = state.tcb_mut().unwrap();
        tcb.data_tracker.observe(SocketTime::zero(), Tsn(11), false);
        tcb.reassembly_queue.add(Tsn(11), seq.ordered("2345", "BE"));

        // Process the same request again.
        handle_reconfig(
            &mut state,
            &mut ctx,
            SocketTime::zero(),
            ReConfigChunk {
                parameters: vec![Parameter::OutgoingSsnResetRequest(
                    OutgoingSsnResetRequestParameter {
                        request_seq_nbr: 11,
                        response_seq_nbr: 3,
                        sender_last_assigned_tsn: Tsn(11),
                        streams: vec![StreamId(1)],
                    },
                )],
            },
        );

        // Expect OnIncomingStreamReset first
        expect_incoming_stream_reset_event(&events, vec![StreamId(1)]);

        // Expect SuccessPerformed response
        let response = expect_sent_reconfig_response(&events, &ctx.options);
        assert_eq!(response.result, ReconfigurationResponseResult::SuccessPerformed);

        // Verify that stream was reset by resetting the sender and expect the message (SSN=0) to be
        // delivered.
        let mut seq = DataSequencer::new(StreamId(1));

        let tcb = state.tcb_mut().unwrap();
        tcb.data_tracker.observe(SocketTime::zero(), Tsn(12), false);
        tcb.reassembly_queue.add(Tsn(12), seq.ordered("3456", "BE"));

        assert_eq!(tcb.reassembly_queue.get_next_message().unwrap().payload, b"1234"); // TSN=10
        assert_eq!(tcb.reassembly_queue.get_next_message().unwrap().payload, b"2345"); // TSN=11
        assert_eq!(tcb.reassembly_queue.get_next_message().unwrap().payload, b"3456");
    }

    #[test]
    fn reset_streams_deferred_only_selected_streams() {
        // This test verifies the receiving behavior of receiving messages on
        // streams 1, 2 and 3, and receiving a reset request on stream 1, 2, causing
        // deferred reset processing.

        let my_initial_tsn = Tsn(0);
        let peer_initial_tsn = Tsn(10);
        let (mut state, mut ctx, events) = create_test_objects(my_initial_tsn, peer_initial_tsn);
        let mut seq1 = DataSequencer::new(StreamId(1));
        let mut seq2 = DataSequencer::new(StreamId(2));
        let mut seq3 = DataSequencer::new(StreamId(3));

        // Reset stream 1,2 with "last assigned TSN=12" (current TSN=10).
        handle_reconfig(
            &mut state,
            &mut ctx,
            SocketTime::zero(),
            ReConfigChunk {
                parameters: vec![Parameter::OutgoingSsnResetRequest(
                    OutgoingSsnResetRequestParameter {
                        request_seq_nbr: 10,
                        response_seq_nbr: 3,
                        sender_last_assigned_tsn: Tsn(12),
                        streams: vec![StreamId(1), StreamId(2)],
                    },
                )],
            },
        );
        // Expect InProgress
        let response = expect_sent_reconfig_response(&events, &ctx.options);
        assert_eq!(response.result, ReconfigurationResponseResult::InProgress);

        let tcb = state.tcb_mut().unwrap();
        // TSN 10, SID 1 - before TSN 12 -> deliver
        tcb.data_tracker.observe(SocketTime::zero(), Tsn(10), false);
        tcb.reassembly_queue.add(Tsn(10), seq1.ordered("1111", "BE"));
        assert_eq!(tcb.reassembly_queue.get_next_message().unwrap().payload, b"1111");

        // TSN 11, SID 2 - before TSN 12 -> deliver
        tcb.data_tracker.observe(SocketTime::zero(), Tsn(11), false);
        tcb.reassembly_queue.add(Tsn(11), seq2.ordered("2222", "BE"));
        assert_eq!(tcb.reassembly_queue.get_next_message().unwrap().payload, b"2222");

        // TSN 12, SID 3 - at TSN 12 -> deliver
        tcb.data_tracker.observe(SocketTime::zero(), Tsn(12), false);
        tcb.reassembly_queue.add(Tsn(12), seq3.ordered("3333", "BE"));
        assert_eq!(tcb.reassembly_queue.get_next_message().unwrap().payload, b"3333");

        // TSN 13, SID 1 - after TSN 12 and SID=1 -> defer
        let mut seq1 = DataSequencer::new(StreamId(1));
        tcb.data_tracker.observe(SocketTime::zero(), Tsn(13), false);
        tcb.reassembly_queue.add(Tsn(13), seq1.ordered("1-new", "BE"));
        assert!(tcb.reassembly_queue.get_next_message().is_none());

        // TSN 14, SID 2 - after TSN 12 and SID=2 -> defer
        let mut seq2 = DataSequencer::new(StreamId(2));
        tcb.data_tracker.observe(SocketTime::zero(), Tsn(14), false);
        tcb.reassembly_queue.add(Tsn(14), seq2.ordered("2-new", "BE"));
        assert!(tcb.reassembly_queue.get_next_message().is_none());

        // TSN 15, SID 3 - after TSN 12, but SID 3 is not reset -> deliver
        tcb.data_tracker.observe(SocketTime::zero(), Tsn(15), false);
        tcb.reassembly_queue.add(Tsn(15), seq3.ordered("4444", "BE"));
        assert_eq!(tcb.reassembly_queue.get_next_message().unwrap().payload, b"4444");

        // Process request again (TSN=12 is received, this can be performed.)
        handle_reconfig(
            &mut state,
            &mut ctx,
            SocketTime::zero(),
            ReConfigChunk {
                parameters: vec![Parameter::OutgoingSsnResetRequest(
                    OutgoingSsnResetRequestParameter {
                        request_seq_nbr: 11,
                        response_seq_nbr: 3,
                        sender_last_assigned_tsn: Tsn(12),
                        streams: vec![StreamId(1), StreamId(2)],
                    },
                )],
            },
        );

        expect_incoming_stream_reset_event(&events, vec![StreamId(1), StreamId(2)]);

        let response = expect_sent_reconfig_response(&events, &ctx.options);
        assert_eq!(response.result, ReconfigurationResponseResult::SuccessPerformed);

        // The deferred messages from SID=1 and SID=2 can now be delivered.
        let tcb = state.tcb_mut().unwrap();
        assert_eq!(tcb.reassembly_queue.get_next_message().unwrap().payload, b"1-new");
        assert_eq!(tcb.reassembly_queue.get_next_message().unwrap().payload, b"2-new");
        assert!(tcb.reassembly_queue.get_next_message().is_none());
    }

    #[test]
    fn reset_streams_defers_forward_tsn() {
        // This test verifies that FORWARD-TSNs are deferred if they want to move
        // the cumulative ack TSN point past sender's last assigned TSN.
        let my_initial_tsn = Tsn(0);
        let peer_initial_tsn = Tsn(10);
        let (mut state, mut ctx, events) = create_test_objects(my_initial_tsn, peer_initial_tsn);
        let mut seq = DataSequencer::new(StreamId(42));

        // Simulate sender sends:
        // * TSN 10 (SSN=0, BE, lost),
        // * TSN 11 (SSN=1, BE, lost),
        // * TSN 12 (SSN=2, BE, lost)
        // * RESET THE STREAM
        // * TSN 13 (SSN=0, B, received)
        // * TSN 14 (SSN=0, E, lost),
        // * TSN 15 (SSN=1, BE, received)

        let _tsn10 = seq.ordered("1234", "BE");
        let _tsn11 = seq.ordered("2345", "BE");
        let _tsn12 = seq.ordered("3456", "BE");

        // Request reset. Sender's last assigned TSN is 12, which is not seen -> defer.
        handle_reconfig(
            &mut state,
            &mut ctx,
            SocketTime::zero(),
            ReConfigChunk {
                parameters: vec![Parameter::OutgoingSsnResetRequest(
                    OutgoingSsnResetRequestParameter {
                        request_seq_nbr: 10,
                        response_seq_nbr: 3,
                        sender_last_assigned_tsn: Tsn(12),
                        streams: vec![StreamId(42)],
                    },
                )],
            },
        );
        assert_eq!(
            expect_sent_reconfig_response(&events, &ctx.options).result,
            ReconfigurationResponseResult::InProgress
        );

        // Reset data sequencer, making it set SSN=0.
        let mut seq = DataSequencer::new(StreamId(42));

        let tcb = state.tcb_mut().unwrap();
        // TSN 13, B, after TSN=12 -> defer
        let tsn13 = seq.ordered("part1", "B");
        tcb.data_tracker.observe(SocketTime::zero(), Tsn(13), false);
        tcb.reassembly_queue.add(Tsn(13), tsn13);
        assert!(tcb.reassembly_queue.get_next_message().is_none());

        // TSN 14 (lost), TSN 15, BE, after TSN=12 -> defer
        let _tsn14 = seq.ordered("part2", "E");

        let tsn15 = seq.ordered("next", "BE");
        tcb.data_tracker.observe(SocketTime::zero(), Tsn(15), false);
        tcb.reassembly_queue.add(Tsn(15), tsn15);
        assert!(tcb.reassembly_queue.get_next_message().is_none());

        // Time passes, sender decides to send FORWARD-TSN up to the RESET.
        // Forward TSN 12.
        tcb.data_tracker.handle_forward_tsn(SocketTime::zero(), Tsn(12));
        tcb.reassembly_queue
            .handle_forward_tsn(Tsn(12), vec![SkippedStream::ForwardTsn(StreamId(42), Ssn(2))]);

        // The receiver sends a SACK in response to that.
        // The stream hasn't been reset yet, but the sender now decides that TSN=13-14 is to be
        // skipped. As this has a TSN 14, after TSN=12 -> defer it.
        tcb.data_tracker.handle_forward_tsn(SocketTime::zero(), Tsn(14));
        tcb.reassembly_queue
            .handle_forward_tsn(Tsn(14), vec![SkippedStream::ForwardTsn(StreamId(42), Ssn(0))]);

        // Reset the stream -> deferred TSNs should be delivered.
        handle_reconfig(
            &mut state,
            &mut ctx,
            SocketTime::zero(),
            ReConfigChunk {
                parameters: vec![Parameter::OutgoingSsnResetRequest(
                    OutgoingSsnResetRequestParameter {
                        request_seq_nbr: 11,
                        response_seq_nbr: 3,
                        sender_last_assigned_tsn: Tsn(12),
                        streams: vec![StreamId(42)],
                    },
                )],
            },
        );

        expect_incoming_stream_reset_event(&events, vec![StreamId(42)]);

        assert_eq!(
            expect_sent_reconfig_response(&events, &ctx.options).result,
            ReconfigurationResponseResult::SuccessPerformed
        );

        let tcb = state.tcb_mut().unwrap();
        // Expect TSN 15 (SSN 1) to be delivered.
        // TSN 13+14 (SSN 0) was skipped via ForwardTSN.
        assert_eq!(tcb.reassembly_queue.get_next_message().unwrap().payload, b"next");
        assert!(tcb.reassembly_queue.get_next_message().is_none());
    }

    #[test]
    fn send_outgoing_request_directly() {
        let my_initial_tsn = Tsn(0);
        let peer_initial_tsn = Tsn(10);
        let (mut state, mut ctx, events) = create_test_objects(my_initial_tsn, peer_initial_tsn);

        do_reset_streams(&mut state, &mut ctx, SocketTime::zero(), &[StreamId(1)]).unwrap();

        let req = expect_sent_reset_request(&events, &ctx.options);
        assert_eq!(req.streams, vec![StreamId(1)]);
        assert_eq!(req.request_seq_nbr, 0); // Initial req seq nbr starts at 0 (my_initial_tsn)
    }

    #[test]
    fn reset_multiple_streams_in_one_request() {
        let my_initial_tsn = Tsn(0);
        let peer_initial_tsn = Tsn(10);
        let (mut state, mut ctx, events) = create_test_objects(my_initial_tsn, peer_initial_tsn);

        do_reset_streams(&mut state, &mut ctx, SocketTime::zero(), &[StreamId(1), StreamId(3)])
            .unwrap();

        let req = expect_sent_reset_request(&events, &ctx.options);
        let mut streams = req.streams.clone();
        streams.sort();
        assert_eq!(streams, vec![StreamId(1), StreamId(3)]);
    }

    #[test]
    fn send_outgoing_request_deferred() {
        let my_initial_tsn = Tsn(0);
        let peer_initial_tsn = Tsn(10);
        let (mut state, mut ctx, events) = create_test_objects(my_initial_tsn, peer_initial_tsn);

        // Add a message large enough to be fragmented and produce some of it to make it "partially
        // sent".
        let large_payload = vec![0u8; 2000];
        ctx.send_queue.add(
            SocketTime::zero(),
            Message::new(StreamId(42), PpId(53), large_payload),
            &SendOptions::default(),
        );

        // Produce a chunk (partial send).
        // Produce 1000 bytes.
        let chunk = ctx.send_queue.produce(SocketTime::zero(), 1000);
        assert!(chunk.is_some());

        // Request reset.
        do_reset_streams(&mut state, &mut ctx, SocketTime::zero(), &[StreamId(42)]).unwrap();

        // Should NOT send a request yet because stream is pending (has partially sent data).
        while let Some(event) = events.borrow_mut().next_event() {
            if let SocketEvent::SendPacket(packet) = event {
                let packet = SctpPacket::from_bytes(&packet, &ctx.options).unwrap();
                if packet.chunks.iter().any(|c| matches!(c, Chunk::ReConfig(_))) {
                    panic!("Unexpected ReConfig chunk - should be deferred");
                }
            }
        }

        // Now drain the send queue (simulating sending the pending data).
        while ctx.send_queue.produce(SocketTime::zero(), 1000).is_some() {}

        // Trigger check again.
        ctx.send_buffered_packets(&mut state, SocketTime::zero());

        // NOW it should send the request.
        let req = expect_sent_reset_request(&events, &ctx.options);
        assert_eq!(req.streams, vec![StreamId(42)]);
    }

    #[test]
    fn send_outgoing_resetting_on_positive_response() {
        let my_initial_tsn = Tsn(0);
        let peer_initial_tsn = Tsn(10);
        let (mut state, mut ctx, events) = create_test_objects(my_initial_tsn, peer_initial_tsn);

        do_reset_streams(&mut state, &mut ctx, SocketTime::zero(), &[StreamId(1)]).unwrap();

        let req = expect_sent_reset_request(&events, &ctx.options);
        let req_seq_nbr = req.request_seq_nbr;

        // Receive Success response
        handle_reconfig(
            &mut state,
            &mut ctx,
            SocketTime::zero(),
            ReConfigChunk {
                parameters: vec![Parameter::ReconfigurationResponse(
                    ReconfigurationResponseParameter {
                        response_seq_nbr: req_seq_nbr,
                        result: ReconfigurationResponseResult::SuccessPerformed,
                        sender_next_tsn: None,
                        receiver_next_tsn: None,
                    },
                )],
            },
        );

        // Should NOT trigger any new packet (no response to a response)
        // But SHOULD trigger OnStreamsResetPerformed
        let event = events.borrow_mut().next_event().expect("expected event");
        let SocketEvent::OnStreamsResetPerformed(streams) = event else {
            panic!("Unexpected event: {:?}", event);
        };

        assert_eq!(streams, vec![StreamId(1)]);
    }

    #[test]
    fn send_outgoing_reset_rollback_on_error() {
        let my_initial_tsn = Tsn(0);
        let peer_initial_tsn = Tsn(10);
        let (mut state, mut ctx, events) = create_test_objects(my_initial_tsn, peer_initial_tsn);

        do_reset_streams(&mut state, &mut ctx, SocketTime::zero(), &[StreamId(1)]).unwrap();

        let req = expect_sent_reset_request(&events, &ctx.options);
        let req_seq_nbr = req.request_seq_nbr;

        // Receive Error response
        handle_reconfig(
            &mut state,
            &mut ctx,
            SocketTime::zero(),
            ReConfigChunk {
                parameters: vec![Parameter::ReconfigurationResponse(
                    ReconfigurationResponseParameter {
                        response_seq_nbr: req_seq_nbr,
                        result: ReconfigurationResponseResult::ErrorBadSequenceNumber,
                        sender_next_tsn: None,
                        receiver_next_tsn: None,
                    },
                )],
            },
        );

        let event = events.borrow_mut().next_event().expect("expected event");
        let SocketEvent::OnStreamsResetFailed(streams) = event else {
            panic!("Unexpected event: {:?}", event);
        };

        assert_eq!(streams, vec![StreamId(1)]);
    }

    #[test]
    fn send_outgoing_reset_retransmit_on_in_progress() {
        let my_initial_tsn = Tsn(0);
        let peer_initial_tsn = Tsn(10);
        let (mut state, mut ctx, events) = create_test_objects(my_initial_tsn, peer_initial_tsn);

        do_reset_streams(&mut state, &mut ctx, SocketTime::zero(), &[StreamId(1)]).unwrap();

        let req = expect_sent_reset_request(&events, &ctx.options);
        let req_seq_nbr = req.request_seq_nbr;

        // Receive InProgress response
        handle_reconfig(
            &mut state,
            &mut ctx,
            SocketTime::zero(),
            ReConfigChunk {
                parameters: vec![Parameter::ReconfigurationResponse(
                    ReconfigurationResponseParameter {
                        response_seq_nbr: req_seq_nbr,
                        result: ReconfigurationResponseResult::InProgress,
                        sender_next_tsn: None,
                        receiver_next_tsn: None,
                    },
                )],
            },
        );

        // Should NOT trigger any new reconfig packet immediately. Drain events to be sure.
        while let Some(event) = events.borrow_mut().next_event() {
            if let SocketEvent::SendPacket(packet) = event {
                let packet = SctpPacket::from_bytes(&packet, &ctx.options).unwrap();
                if packet.chunks.iter().any(|c| matches!(c, Chunk::ReConfig(_))) {
                    panic!("Unexpected ReConfig chunk");
                }
            }
        }

        // Advance time by RTO to trigger timeout
        let rto = state.tcb().unwrap().rto.rto();
        let now = SocketTime::zero() + rto;

        handle_reconfig_timeout(&mut state, &mut ctx, now);

        // Should trigger retransmission
        assert_eq!(expect_sent_reset_request(&events, &ctx.options).streams, vec![StreamId(1)]);
    }

    #[test]
    fn reset_while_request_is_sent_will_queue() {
        let my_initial_tsn = Tsn(0);
        let peer_initial_tsn = Tsn(10);
        let (mut state, mut ctx, events) = create_test_objects(my_initial_tsn, peer_initial_tsn);

        // Reset stream 1.
        do_reset_streams(&mut state, &mut ctx, SocketTime::zero(), &[StreamId(1)]).unwrap();

        // Expect packet (reset request).
        let req = expect_sent_reset_request(&events, &ctx.options);
        assert_eq!(req.streams, vec![StreamId(1)]);
        let req_seq_nbr = req.request_seq_nbr;

        // Reset streams 2 and 3 while request is in-flight.
        do_reset_streams(&mut state, &mut ctx, SocketTime::zero(), &[StreamId(2), StreamId(3)])
            .unwrap();

        // Try to send packets. Should NOT produce new ReConfig (because one is in flight).
        ctx.send_buffered_packets(&mut state, SocketTime::zero());
        while let Some(event) = events.borrow_mut().next_event() {
            if let SocketEvent::SendPacket(packet) = event {
                let packet = SctpPacket::from_bytes(&packet, &ctx.options).unwrap();
                if packet.chunks.iter().any(|c| matches!(c, Chunk::ReConfig(_))) {
                    panic!("Unexpected ReConfig chunk");
                }
            }
        }

        // Receive response for first request.
        handle_reconfig(
            &mut state,
            &mut ctx,
            SocketTime::zero(),
            ReConfigChunk {
                parameters: vec![Parameter::ReconfigurationResponse(
                    ReconfigurationResponseParameter {
                        response_seq_nbr: req_seq_nbr,
                        result: ReconfigurationResponseResult::SuccessPerformed,
                        sender_next_tsn: None,
                        receiver_next_tsn: None,
                    },
                )],
            },
        );

        // Expect OnStreamsResetPerformed for the first request
        let event = events.borrow_mut().next_event().expect("expected event");
        let SocketEvent::OnStreamsResetPerformed(streams) = event else {
            panic!("Unexpected event: {:?}", event);
        };

        assert_eq!(streams, vec![StreamId(1)]);

        // NOW the second request should be sent.
        let req = expect_sent_reset_request(&events, &ctx.options);
        let mut streams = req.streams.clone();
        streams.sort();
        assert_eq!(streams, vec![StreamId(2), StreamId(3)]);
        assert_eq!(req.request_seq_nbr, req_seq_nbr.wrapping_add(1));
    }

    #[test]
    fn send_incoming_reset_just_returns_nothing_performed() {
        let my_initial_tsn = Tsn(0);
        let peer_initial_tsn = Tsn(10);
        let (mut state, mut ctx, events) = create_test_objects(my_initial_tsn, peer_initial_tsn);

        handle_reconfig(
            &mut state,
            &mut ctx,
            SocketTime::zero(),
            ReConfigChunk {
                parameters: vec![Parameter::IncomingSsnResetRequest(
                    IncomingSsnResetRequestParameter {
                        request_seq_nbr: 10,
                        streams: vec![StreamId(1)],
                    },
                )],
            },
        );

        let resp = expect_sent_reconfig_response(&events, &ctx.options);
        assert_eq!(resp.response_seq_nbr, 10);
        assert_eq!(resp.result, ReconfigurationResponseResult::SuccessNothingToDo);
    }

    #[test]
    fn send_same_request_twice_is_idempotent() {
        // Simulate that receiving the same chunk twice (due to network issues,
        // or retransmissions, causing a RECONFIG to be re-received) is idempotent.
        let my_initial_tsn = Tsn(0);
        let peer_initial_tsn = Tsn(10);
        let (mut state, mut ctx, events) = create_test_objects(my_initial_tsn, peer_initial_tsn);

        for _ in 0..2 {
            handle_reconfig(
                &mut state,
                &mut ctx,
                SocketTime::zero(),
                ReConfigChunk {
                    parameters: vec![Parameter::OutgoingSsnResetRequest(
                        OutgoingSsnResetRequestParameter {
                            request_seq_nbr: 10,
                            response_seq_nbr: 3,
                            sender_last_assigned_tsn: Tsn(11),
                            streams: vec![StreamId(1)],
                        },
                    )],
                },
            );

            assert_eq!(
                expect_sent_reconfig_response(&events, &ctx.options).result,
                ReconfigurationResponseResult::InProgress
            );
        }
    }

    #[test]
    fn perform_close_after_one_first_failing() {
        // Inject a stream reset on the first expected TSN (which hasn't been seen).
        let my_initial_tsn = Tsn(0);
        let peer_initial_tsn = Tsn(10);
        let (mut state, mut ctx, events) = create_test_objects(my_initial_tsn, peer_initial_tsn);

        // Peer Initial TSN is 10.
        handle_reconfig(
            &mut state,
            &mut ctx,
            SocketTime::zero(),
            ReConfigChunk {
                parameters: vec![Parameter::OutgoingSsnResetRequest(
                    OutgoingSsnResetRequestParameter {
                        request_seq_nbr: 10,
                        response_seq_nbr: 3,
                        sender_last_assigned_tsn: Tsn(10), // Missing (current is before 10)
                        streams: vec![StreamId(1)],
                    },
                )],
            },
        );

        // The socket is expected to say "in progress" as that TSN hasn't been seen.
        let response = expect_sent_reconfig_response(&events, &ctx.options);
        assert_eq!(response.result, ReconfigurationResponseResult::InProgress);

        let mut seq = DataSequencer::new(StreamId(1));

        // Let the socket receive the TSN.
        let tcb = state.tcb_mut().unwrap();
        tcb.reassembly_queue.add(Tsn(10), seq.ordered("1234", "BE"));
        tcb.data_tracker.observe(SocketTime::zero(), Tsn(10), false);

        // And emulate that time has passed, and the peer retries the stream reset,
        // but now with an incremented request sequence number.
        handle_reconfig(
            &mut state,
            &mut ctx,
            SocketTime::zero(),
            ReConfigChunk {
                parameters: vec![Parameter::OutgoingSsnResetRequest(
                    OutgoingSsnResetRequestParameter {
                        request_seq_nbr: 11,
                        response_seq_nbr: 3,
                        sender_last_assigned_tsn: Tsn(10),
                        streams: vec![StreamId(1)],
                    },
                )],
            },
        );

        // This is supposed to be handled well.
        expect_incoming_stream_reset_event(&events, vec![StreamId(1)]);
        assert_eq!(
            expect_sent_reconfig_response(&events, &ctx.options).result,
            ReconfigurationResponseResult::SuccessPerformed
        );
    }

    #[test]
    fn reset_streams_deferred_retransmission_with_same_seq_num_success() {
        let my_initial_tsn = Tsn(0);
        let peer_initial_tsn = Tsn(10);
        let (mut state, mut ctx, events) = create_test_objects(my_initial_tsn, peer_initial_tsn);
        let mut seq = DataSequencer::new(StreamId(1));

        // 1. Receive request N -> conditions not met -> respond "In Progress"
        // 2. Conditions met (TSN received)
        // 3. Receive request N (retransmission) -> re-evaluate -> respond "Success"

        let tcb = state.tcb_mut().unwrap();
        tcb.data_tracker.observe(SocketTime::zero(), Tsn(10), false);
        tcb.reassembly_queue.add(Tsn(10), seq.ordered("10", "BE"));

        // Request reset 10, waiting for 12.
        handle_reconfig(
            &mut state,
            &mut ctx,
            SocketTime::zero(),
            ReConfigChunk {
                parameters: vec![Parameter::OutgoingSsnResetRequest(
                    OutgoingSsnResetRequestParameter {
                        request_seq_nbr: 10,
                        response_seq_nbr: 3,
                        sender_last_assigned_tsn: Tsn(12),
                        streams: vec![StreamId(1)],
                    },
                )],
            },
        );

        let response = expect_sent_reconfig_response(&events, &ctx.options);
        assert_eq!(response.result, ReconfigurationResponseResult::InProgress);

        // Receive 11, 12.
        let tcb = state.tcb_mut().unwrap();
        tcb.data_tracker.observe(SocketTime::zero(), Tsn(11), false);
        tcb.reassembly_queue.add(Tsn(11), seq.ordered("11", "BE"));
        tcb.data_tracker.observe(SocketTime::zero(), Tsn(12), false);
        tcb.reassembly_queue.add(Tsn(12), seq.ordered("12", "BE"));

        // Drain SACKs
        while events.borrow_mut().next_event().is_some() {}

        // Retransmit SAME request (10).
        handle_reconfig(
            &mut state,
            &mut ctx,
            SocketTime::zero(),
            ReConfigChunk {
                parameters: vec![Parameter::OutgoingSsnResetRequest(
                    OutgoingSsnResetRequestParameter {
                        request_seq_nbr: 10,
                        response_seq_nbr: 3,
                        sender_last_assigned_tsn: Tsn(12),
                        streams: vec![StreamId(1)],
                    },
                )],
            },
        );

        // Expect reset performed event first
        expect_incoming_stream_reset_event(&events, vec![StreamId(1)]);

        let response = expect_sent_reconfig_response(&events, &ctx.options);
        assert_eq!(response.result, ReconfigurationResponseResult::SuccessPerformed);
    }

    #[test]
    fn reset_streams_deferred_with_new_seq_num_success() {
        // Backward compatibility (old behavior):
        // 1. Receive request N -> conditions not met -> respond "In Progress"
        // 2. Conditions met
        // 3. Receive request N+1 -> rreat as new -> respond "Success"

        let my_initial_tsn = Tsn(0);
        let peer_initial_tsn = Tsn(10);
        let (mut state, mut ctx, events) = create_test_objects(my_initial_tsn, peer_initial_tsn);
        let mut seq = DataSequencer::new(StreamId(1));

        // Request reset 10, waiting for 11.
        handle_reconfig(
            &mut state,
            &mut ctx,
            SocketTime::zero(),
            ReConfigChunk {
                parameters: vec![Parameter::OutgoingSsnResetRequest(
                    OutgoingSsnResetRequestParameter {
                        request_seq_nbr: 10,
                        response_seq_nbr: 3,
                        sender_last_assigned_tsn: Tsn(11),
                        streams: vec![StreamId(1)],
                    },
                )],
            },
        );

        assert_eq!(
            expect_sent_reconfig_response(&events, &ctx.options).result,
            ReconfigurationResponseResult::InProgress
        );

        // Receive 10, 11
        let tcb = state.tcb_mut().unwrap();
        tcb.data_tracker.observe(SocketTime::zero(), Tsn(10), false);
        tcb.reassembly_queue.add(Tsn(10), seq.ordered("10", "BE"));
        tcb.data_tracker.observe(SocketTime::zero(), Tsn(11), false);
        tcb.reassembly_queue.add(Tsn(11), seq.ordered("11", "BE"));

        // Drain SACKs
        while events.borrow_mut().next_event().is_some() {}

        // New request 11.
        handle_reconfig(
            &mut state,
            &mut ctx,
            SocketTime::zero(),
            ReConfigChunk {
                parameters: vec![Parameter::OutgoingSsnResetRequest(
                    OutgoingSsnResetRequestParameter {
                        request_seq_nbr: 11,
                        response_seq_nbr: 3,
                        sender_last_assigned_tsn: Tsn(11),
                        streams: vec![StreamId(1)],
                    },
                )],
            },
        );

        // Expect reset performed event first
        expect_incoming_stream_reset_event(&events, vec![StreamId(1)]);

        assert_eq!(
            expect_sent_reconfig_response(&events, &ctx.options).result,
            ReconfigurationResponseResult::SuccessPerformed
        );
    }

    #[test]
    fn reset_streams_deferred_retransmission_still_in_progress() {
        let my_initial_tsn = Tsn(0);
        let peer_initial_tsn = Tsn(10);
        let (mut state, mut ctx, events) = create_test_objects(my_initial_tsn, peer_initial_tsn);

        // Request reset 10, waiting for 11.
        handle_reconfig(
            &mut state,
            &mut ctx,
            SocketTime::zero(),
            ReConfigChunk {
                parameters: vec![Parameter::OutgoingSsnResetRequest(
                    OutgoingSsnResetRequestParameter {
                        request_seq_nbr: 10,
                        response_seq_nbr: 3,
                        sender_last_assigned_tsn: Tsn(11),
                        streams: vec![StreamId(1)],
                    },
                )],
            },
        );

        assert_eq!(
            expect_sent_reconfig_response(&events, &ctx.options).result,
            ReconfigurationResponseResult::InProgress
        );

        // Retransmit same request 10. Condition still not met.
        handle_reconfig(
            &mut state,
            &mut ctx,
            SocketTime::zero(),
            ReConfigChunk {
                parameters: vec![Parameter::OutgoingSsnResetRequest(
                    OutgoingSsnResetRequestParameter {
                        request_seq_nbr: 10,
                        response_seq_nbr: 3,
                        sender_last_assigned_tsn: Tsn(11),
                        streams: vec![StreamId(1)],
                    },
                )],
            },
        );

        assert_eq!(
            expect_sent_reconfig_response(&events, &ctx.options).result,
            ReconfigurationResponseResult::InProgress
        );
    }

    #[test]
    fn reset_streams_success_idempotency() {
        let my_initial_tsn = Tsn(0);
        let peer_initial_tsn = Tsn(10);
        let (mut state, mut ctx, events) = create_test_objects(my_initial_tsn, peer_initial_tsn);
        let mut seq = DataSequencer::new(StreamId(1));

        let tcb = state.tcb_mut().unwrap();
        tcb.data_tracker.observe(SocketTime::zero(), Tsn(10), false);
        tcb.reassembly_queue.add(Tsn(10), seq.ordered("10", "BE"));
        tcb.data_tracker.observe(SocketTime::zero(), Tsn(11), false);
        tcb.reassembly_queue.add(Tsn(11), seq.ordered("11", "BE"));

        // Request reset 10, waiting for 11. Conditions met.
        handle_reconfig(
            &mut state,
            &mut ctx,
            SocketTime::zero(),
            ReConfigChunk {
                parameters: vec![Parameter::OutgoingSsnResetRequest(
                    OutgoingSsnResetRequestParameter {
                        request_seq_nbr: 10,
                        response_seq_nbr: 3,
                        sender_last_assigned_tsn: Tsn(11),
                        streams: vec![StreamId(1)],
                    },
                )],
            },
        );

        // Expect reset performed event first
        expect_incoming_stream_reset_event(&events, vec![StreamId(1)]);

        assert_eq!(
            expect_sent_reconfig_response(&events, &ctx.options).result,
            ReconfigurationResponseResult::SuccessPerformed
        );

        // Retransmit same request 10.
        // Drain any pending events (SACKs)
        while events.borrow_mut().next_event().is_some() {}

        handle_reconfig(
            &mut state,
            &mut ctx,
            SocketTime::zero(),
            ReConfigChunk {
                parameters: vec![Parameter::OutgoingSsnResetRequest(
                    OutgoingSsnResetRequestParameter {
                        request_seq_nbr: 10,
                        response_seq_nbr: 3,
                        sender_last_assigned_tsn: Tsn(11),
                        streams: vec![StreamId(1)],
                    },
                )],
            },
        );

        // Should return cached success.
        assert_eq!(
            expect_sent_reconfig_response(&events, &ctx.options).result,
            ReconfigurationResponseResult::SuccessPerformed
        );
        // Should NOT trigger event again.
        while let Some(event) = events.borrow_mut().next_event() {
            if let SocketEvent::OnIncomingStreamReset(_) = event {
                panic!("Unexpected OnIncomingStreamReset event: {:?}", event);
            }
        }
    }
}
