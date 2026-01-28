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

                if validate_req_seq_nbr(
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
            }
            Parameter::IncomingSsnResetRequest(IncomingSsnResetRequestParameter {
                request_seq_nbr,
                ..
            }) => {
                if validate_req_seq_nbr(
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

pub(crate) fn handle_reconfig_timeout(state: &mut State, ctx: &mut Context, now: SocketTime) {
    let tcb = state.tcb_mut().unwrap();
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
                ctx.tx_error_counter.increment();
                if ctx.tx_error_counter.is_exhausted() {
                    return;
                }
            }
        }
        tcb.reconfig_timer.set_duration(tcb.rto.rto());
        let mut builder = tcb.new_packet();
        tcb.add_prepared_ssn_reset_request(&mut builder);
        ctx.events.borrow_mut().add(SocketEvent::SendPacket(builder.build()));
        ctx.tx_packets_count += 1;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EventSink;
    use crate::api::Message;
    use crate::api::Options;
    use crate::api::PpId;
    use crate::api::SctpImplementation;
    use crate::api::SendOptions;
    use crate::packet::SkippedStream;
    use crate::packet::data::Data;
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
    use std::collections::VecDeque;
    use std::rc::Rc;
    use std::time::Duration;

    struct TestFixture {
        state: State,
        ctx: Context,
        events: Rc<RefCell<TestEventSink>>,
    }

    impl TestFixture {
        fn new() -> Self {
            let options = Options::default();
            let events = Rc::new(RefCell::new(TestEventSink::new()));

            let mut tcb = TransmissionControlBlock::new(
                &options,
                0,       // my_verification_tag
                Tsn(0),  // my_initial_tsn
                0,       // peer_verification_tag
                Tsn(10), // peer_initial_tsn (Matching C++ test kPeerInitialTsn)
                0,       // tie_tag
                131072,  // a_rwnd
                Capabilities::default(),
                Rc::clone(&events) as Rc<RefCell<dyn EventSink>>,
            );
            // Enable reconfig capability
            tcb.capabilities.reconfig = true;
            tcb.capabilities.negotiated_maximum_incoming_streams = 65535;
            tcb.capabilities.negotiated_maximum_outgoing_streams = 65535;

            let state = State::Established(tcb);

            let context = Context {
                options: options.clone(),
                events: Rc::clone(&events) as Rc<RefCell<dyn EventSink>>,
                send_queue: SendQueue::new(
                    options.mtu,
                    &options,
                    Rc::clone(&events) as Rc<RefCell<dyn EventSink>>,
                ),
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

            Self { state, ctx: context, events }
        }

        fn tcb(&mut self) -> &mut TransmissionControlBlock {
            self.state.tcb_mut().unwrap()
        }

        fn handle_reconfig(&mut self, chunk: ReConfigChunk) {
            handle_reconfig(&mut self.state, &mut self.ctx, SocketTime::zero(), chunk);
        }

        fn pop_event(&mut self) -> SocketEvent {
            self.events.borrow_mut().pop().expect("Expected event")
        }

        fn try_pop_event(&mut self) -> Option<SocketEvent> {
            self.events.borrow_mut().pop()
        }

        fn expect_no_incoming_stream_reset_event(&mut self) {
            while let Some(event) = self.try_pop_event() {
                if let SocketEvent::OnIncomingStreamReset(_) = event {
                    panic!("Unexpected OnIncomingStreamReset event: {:?}", event);
                }
            }
        }

        fn expect_sent_packet(&mut self) -> SctpPacket {
            loop {
                // If we run out of events, pop_event will panic, which is what we want.
                let event = self.pop_event();
                match event {
                    SocketEvent::SendPacket(packet) => {
                        return SctpPacket::from_bytes(&packet, &self.ctx.options)
                            .expect("valid packet");
                    }
                    SocketEvent::OnBufferedAmountLow(_) => {
                        // Ignore
                        continue;
                    }
                    _ => {
                        panic!("Expected SendPacket, got {:?}", event);
                    }
                }
            }
        }

        fn expect_sent_reconfig_chunk(&mut self) -> ReConfigChunk {
            let packet = self.expect_sent_packet();
            packet
                .chunks
                .into_iter()
                .find_map(|c| match c {
                    Chunk::ReConfig(r) => Some(r),
                    _ => None,
                })
                .expect("Expected ReConfig chunk")
        }

        fn expect_sent_reconfig_response(&mut self) -> ReconfigurationResponseParameter {
            let chunk = self.expect_sent_reconfig_chunk();
            chunk
                .parameters
                .into_iter()
                .find_map(|p| match p {
                    Parameter::ReconfigurationResponse(r) => Some(r),
                    _ => None,
                })
                .expect("Expected ReconfigurationResponse")
        }

        fn expect_sent_reset_request(&mut self) -> OutgoingSsnResetRequestParameter {
            let chunk = self.expect_sent_reconfig_chunk();
            chunk
                .parameters
                .into_iter()
                .find_map(|p| match p {
                    Parameter::OutgoingSsnResetRequest(r) => Some(r),
                    _ => None,
                })
                .expect("Expected OutgoingSsnResetRequest")
        }

        fn do_reset_streams(&mut self, streams: &[StreamId]) {
            do_reset_streams(&mut self.state, &mut self.ctx, SocketTime::zero(), streams)
                .expect("do_reset_streams failed");
        }

        fn handle_reconfig_timeout(&mut self, now: SocketTime) {
            handle_reconfig_timeout(&mut self.state, &mut self.ctx, now);
        }

        fn prepare_outgoing_reset(
            &self,
            request_seq_nbr: u32,
            response_seq_nbr: u32,
            sender_last_assigned_tsn: Tsn,
            streams: Vec<StreamId>,
        ) -> ReConfigChunk {
            let param = Parameter::OutgoingSsnResetRequest(OutgoingSsnResetRequestParameter {
                request_seq_nbr,
                response_seq_nbr,
                sender_last_assigned_tsn,
                streams,
            });
            ReConfigChunk { parameters: vec![param] }
        }

        fn prepare_reconfig_response(
            &self,
            response_seq_nbr: u32,
            result: ReconfigurationResponseResult,
        ) -> ReConfigChunk {
            let param = Parameter::ReconfigurationResponse(ReconfigurationResponseParameter {
                response_seq_nbr,
                result,
                sender_next_tsn: None,
                receiver_next_tsn: None,
            });
            ReConfigChunk { parameters: vec![param] }
        }

        fn expect_incoming_stream_reset_event(&mut self, expected_streams: Vec<StreamId>) {
            let event = self.pop_event();
            if let SocketEvent::OnIncomingStreamReset(streams) = event {
                assert_eq!(streams, expected_streams);
            } else {
                panic!("Expected OnIncomingStreamReset, got {:?}", event);
            }
        }

        fn receive(&mut self, tsn: Tsn, data: Data) {
            self.tcb().reassembly_queue.add(tsn, data);
            self.tcb().data_tracker.observe(SocketTime::zero(), tsn, false);
        }

        fn expect_delivered_message(&mut self) -> Message {
            self.tcb().reassembly_queue.get_next_message().unwrap()
        }

        fn expect_no_message(&mut self) -> bool {
            self.tcb().reassembly_queue.get_next_message().is_none()
        }
    }

    struct TestEventSink {
        events: VecDeque<SocketEvent>,
    }

    impl TestEventSink {
        fn new() -> Self {
            Self { events: VecDeque::new() }
        }

        fn pop(&mut self) -> Option<SocketEvent> {
            self.events.pop_front()
        }
    }

    impl EventSink for TestEventSink {
        fn add(&mut self, event: SocketEvent) {
            self.events.push_back(event);
        }
        fn next_event(&mut self) -> Option<SocketEvent> {
            self.events.pop_front()
        }
    }

    #[test]
    fn chunk_with_no_parameters_returns_error() {
        let mut fixture = TestFixture::new();

        fixture.handle_reconfig(ReConfigChunk { parameters: vec![] });

        let event = fixture.pop_event();
        if let SocketEvent::OnError(kind, msg) = event {
            assert_eq!(kind, ErrorKind::ProtocolViolation);
            assert_eq!(msg, "RE-CONFIG chunk must have at least one parameter");
        } else {
            panic!("Expected OnError, got {:?}", event);
        }
    }

    #[test]
    fn chunk_with_invalid_parameters_returns_error() {
        let mut fixture = TestFixture::new();

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

        fixture.handle_reconfig(ReConfigChunk { parameters: vec![param1, param2] });

        let event = fixture.pop_event();
        if let SocketEvent::OnError(kind, msg) = event {
            assert_eq!(kind, ErrorKind::ProtocolViolation);
            assert_eq!(
                msg,
                "RE-CONFIG chunk must not have multiple Outgoing SSN Reset Request parameters"
            );
        } else {
            panic!("Expected OnError, got {:?}", event);
        }
    }

    #[test]
    fn fail_to_deliver_without_resetting_stream() {
        let mut fixture = TestFixture::new();
        let mut seq = DataSequencer::new(StreamId(1));

        fixture.receive(Tsn(10), seq.ordered("1234", "BE"));
        fixture.receive(Tsn(11), seq.ordered("2345", "BE"));

        fixture.expect_delivered_message();
        fixture.expect_delivered_message();
        assert!(fixture.expect_no_message());

        // Simulate sender resetting the stream (SSN reset to 0) but receiver NOT processing it.
        // DataSequencer::new WILL reset SSN to 0.
        let mut seq = DataSequencer::new(StreamId(1));
        fixture.receive(Tsn(12), seq.ordered("3456", "BE"));

        // Should NOT be delivered because ReassemblyQueue expects SSN=2, but got SSN=0.
        assert!(fixture.expect_no_message());
    }

    #[test]
    fn reset_streams_not_deferred() {
        let mut fixture = TestFixture::new();
        let mut seq = DataSequencer::new(StreamId(1));

        fixture.receive(Tsn(10), seq.ordered("1234", "BE"));
        fixture.receive(Tsn(11), seq.ordered("2345", "BE"));

        // Verify messages are ready
        assert_eq!(fixture.expect_delivered_message().payload, b"1234");
        assert_eq!(fixture.expect_delivered_message().payload, b"2345");
        assert!(fixture.expect_no_message());

        // Reset, SID=1, TSN=11 (fulfilled).
        fixture.handle_reconfig(fixture.prepare_outgoing_reset(10, 3, Tsn(11), vec![StreamId(1)]));

        fixture.expect_incoming_stream_reset_event(vec![StreamId(1)]);

        let response = fixture.expect_sent_reconfig_response();
        assert_eq!(response.result, ReconfigurationResponseResult::SuccessPerformed);

        // Reset data sequencer for Stream 1 (simulating sender reset)
        let mut seq = DataSequencer::new(StreamId(1));
        fixture.receive(Tsn(12), seq.ordered("3456", "BE"));

        assert_eq!(fixture.expect_delivered_message().payload, b"3456");
    }

    #[test]
    fn reset_streams_deferred() {
        let mut fixture = TestFixture::new();
        let mut seq = DataSequencer::new(StreamId(1));

        // TSN 10 is received and acked.
        fixture.receive(Tsn(10), seq.ordered("1234", "BE"));

        // Send reset request saying last assigned TSN is 11 (which is missing).
        fixture.handle_reconfig(fixture.prepare_outgoing_reset(10, 3, Tsn(11), vec![StreamId(1)]));

        // Expect InProgress response (and no OnIncomingStreamReset yet)
        let response = fixture.expect_sent_reconfig_response();
        assert_eq!(response.result, ReconfigurationResponseResult::InProgress);

        fixture.expect_no_incoming_stream_reset_event();

        // Receive the missing TSN 11.
        fixture.receive(Tsn(11), seq.ordered("2345", "BE"));

        // Process the same request again.
        fixture.handle_reconfig(fixture.prepare_outgoing_reset(11, 3, Tsn(11), vec![StreamId(1)]));

        // Expect OnIncomingStreamReset first
        fixture.expect_incoming_stream_reset_event(vec![StreamId(1)]);

        // Expect SuccessPerformed response
        let response = fixture.expect_sent_reconfig_response();
        assert_eq!(response.result, ReconfigurationResponseResult::SuccessPerformed);

        // Verify that stream was reset by resetting the sender and expect the message (SSN=0) to be
        // delivered.
        let mut seq = DataSequencer::new(StreamId(1));
        fixture.receive(Tsn(12), seq.ordered("3456", "BE"));

        assert_eq!(fixture.expect_delivered_message().payload, b"1234"); // TSN=10
        assert_eq!(fixture.expect_delivered_message().payload, b"2345"); // TSN=11
        assert_eq!(fixture.expect_delivered_message().payload, b"3456");
    }

    #[test]
    fn reset_streams_deferred_only_selected_streams() {
        // This test verifies the receiving behavior of receiving messages on
        // streams 1, 2 and 3, and receiving a reset request on stream 1, 2, causing
        // deferred reset processing.

        let mut fixture = TestFixture::new();
        let mut seq1 = DataSequencer::new(StreamId(1));
        let mut seq2 = DataSequencer::new(StreamId(2));
        let mut seq3 = DataSequencer::new(StreamId(3));

        // Reset stream 1,2 with "last assigned TSN=12" (current TSN=10).
        fixture.handle_reconfig(fixture.prepare_outgoing_reset(
            10,
            3,
            Tsn(12),
            vec![StreamId(1), StreamId(2)],
        ));
        // Expect InProgress
        let response = fixture.expect_sent_reconfig_response();
        assert_eq!(response.result, ReconfigurationResponseResult::InProgress);

        // TSN 10, SID 1 - before TSN 12 -> deliver
        fixture.receive(Tsn(10), seq1.ordered("1111", "BE"));
        assert_eq!(fixture.expect_delivered_message().payload, b"1111");

        // TSN 11, SID 2 - before TSN 12 -> deliver
        fixture.receive(Tsn(11), seq2.ordered("2222", "BE"));
        assert_eq!(fixture.expect_delivered_message().payload, b"2222");

        // TSN 12, SID 3 - at TSN 12 -> deliver
        fixture.receive(Tsn(12), seq3.ordered("3333", "BE"));
        assert_eq!(fixture.expect_delivered_message().payload, b"3333");

        // TSN 13, SID 1 - after TSN 12 and SID=1 -> defer
        let mut seq1 = DataSequencer::new(StreamId(1));
        fixture.receive(Tsn(13), seq1.ordered("1-new", "BE"));
        assert!(fixture.expect_no_message());

        // TSN 14, SID 2 - after TSN 12 and SID=2 -> defer
        let mut seq2 = DataSequencer::new(StreamId(2));
        fixture.receive(Tsn(14), seq2.ordered("2-new", "BE"));
        assert!(fixture.expect_no_message());

        // TSN 15, SID 3 - after TSN 12, but SID 3 is not reset -> deliver
        fixture.receive(Tsn(15), seq3.ordered("4444", "BE"));
        assert_eq!(fixture.expect_delivered_message().payload, b"4444");

        // Process request again (TSN=12 is received, this can be performed.)
        fixture.handle_reconfig(fixture.prepare_outgoing_reset(
            11,
            3,
            Tsn(12),
            vec![StreamId(1), StreamId(2)],
        ));

        fixture.expect_incoming_stream_reset_event(vec![StreamId(1), StreamId(2)]);

        let response = fixture.expect_sent_reconfig_response();
        assert_eq!(response.result, ReconfigurationResponseResult::SuccessPerformed);

        // The deferred messages from SID=1 and SID=2 can now be delivered.
        assert_eq!(fixture.expect_delivered_message().payload, b"1-new");
        assert_eq!(fixture.expect_delivered_message().payload, b"2-new");
        assert!(fixture.expect_no_message());
    }

    #[test]
    fn reset_streams_defers_forward_tsn() {
        // This test verifies that FORWARD-TSNs are deferred if they want to move
        // the cumulative ack TSN point past sender's last assigned TSN.
        let mut fixture = TestFixture::new();
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
        fixture.handle_reconfig(fixture.prepare_outgoing_reset(10, 3, Tsn(12), vec![StreamId(42)]));
        assert_eq!(
            fixture.expect_sent_reconfig_response().result,
            ReconfigurationResponseResult::InProgress
        );

        // TSN 13, B, after TSN=12 -> defer
        let mut seq = DataSequencer::new(StreamId(42));
        let tsn13 = seq.ordered("part1", "B");
        fixture.receive(Tsn(13), tsn13);
        assert!(fixture.expect_no_message());

        // TSN 14 (lost), TSN 15, BE, after TSN=12 -> defer
        let _tsn14 = seq.ordered("part2", "E");
        let tsn15 = seq.ordered("next", "BE");
        fixture.receive(Tsn(15), tsn15);
        assert!(fixture.expect_no_message());

        // Time passes, sender decides to send FORWARD-TSN up to the RESET.
        // Forward TSN 12.
        fixture.tcb().data_tracker.handle_forward_tsn(SocketTime::zero(), Tsn(12));
        fixture
            .tcb()
            .reassembly_queue
            .handle_forward_tsn(Tsn(12), vec![SkippedStream::ForwardTsn(StreamId(42), Ssn(2))]);

        // The receiver sends a SACK in response to that.
        // The stream hasn't been reset yet, but the sender now decides that TSN=13-14 is to be
        // skipped. As this has a TSN 14, after TSN=12 -> defer it.
        fixture.tcb().data_tracker.handle_forward_tsn(SocketTime::zero(), Tsn(14));
        fixture
            .tcb()
            .reassembly_queue
            .handle_forward_tsn(Tsn(14), vec![SkippedStream::ForwardTsn(StreamId(42), Ssn(0))]);

        // Reset the stream -> deferred TSNs should be delivered.
        fixture.handle_reconfig(fixture.prepare_outgoing_reset(11, 3, Tsn(12), vec![StreamId(42)]));

        fixture.expect_incoming_stream_reset_event(vec![StreamId(42)]);

        assert_eq!(
            fixture.expect_sent_reconfig_response().result,
            ReconfigurationResponseResult::SuccessPerformed
        );

        // Expect TSN 15 (SSN 1) to be delivered.
        // TSN 13+14 (SSN 0) was skipped via ForwardTSN.
        assert_eq!(fixture.expect_delivered_message().payload, b"next");
        assert!(fixture.expect_no_message());
    }

    #[test]
    fn send_outgoing_request_directly() {
        let mut fixture = TestFixture::new();

        fixture.do_reset_streams(&[StreamId(1)]);

        let req = fixture.expect_sent_reset_request();
        assert_eq!(req.streams, vec![StreamId(1)]);
        assert_eq!(req.request_seq_nbr, 0); // Initial req seq nbr starts at 0 (my_initial_tsn)
    }

    #[test]
    fn reset_multiple_streams_in_one_request() {
        let mut fixture = TestFixture::new();

        fixture.do_reset_streams(&[StreamId(1), StreamId(3)]);

        let req = fixture.expect_sent_reset_request();
        let mut streams = req.streams.clone();
        streams.sort();
        assert_eq!(streams, vec![StreamId(1), StreamId(3)]);
    }

    #[test]
    fn send_outgoing_request_deferred() {
        let mut fixture = TestFixture::new();

        // Add a message large enough to be fragmented and produce some of it to make it "partially
        // sent".
        let large_payload = vec![0u8; 2000];
        fixture.ctx.send_queue.add(
            SocketTime::zero(),
            Message::new(StreamId(42), PpId(53), large_payload),
            &SendOptions::default(),
        );

        // Produce a chunk (partial send).
        // Produce 1000 bytes.
        let chunk = fixture.ctx.send_queue.produce(SocketTime::zero(), 1000);
        assert!(chunk.is_some());

        // Request reset.
        fixture.do_reset_streams(&[StreamId(42)]);

        // Should NOT send a request yet because stream is pending (has partially sent data).
        while let Some(event) = fixture.try_pop_event() {
            if let SocketEvent::SendPacket(packet) = event {
                let packet = SctpPacket::from_bytes(&packet, &fixture.ctx.options).unwrap();
                if packet.chunks.iter().any(|c| matches!(c, Chunk::ReConfig(_))) {
                    panic!("Unexpected ReConfig chunk - should be deferred");
                }
            }
        }

        // Now drain the send queue (simulating sending the pending data).
        while fixture.ctx.send_queue.produce(SocketTime::zero(), 1000).is_some() {}

        // Trigger check again.
        fixture.ctx.send_buffered_packets(&mut fixture.state, SocketTime::zero());

        // NOW it should send the request.
        let req = fixture.expect_sent_reset_request();
        assert_eq!(req.streams, vec![StreamId(42)]);
    }

    #[test]
    fn send_outgoing_resetting_on_positive_response() {
        let mut fixture = TestFixture::new();

        fixture.do_reset_streams(&[StreamId(1)]);

        let req = fixture.expect_sent_reset_request();
        let req_seq_nbr = req.request_seq_nbr;

        // Receive Success response
        fixture.handle_reconfig(fixture.prepare_reconfig_response(
            req_seq_nbr,
            ReconfigurationResponseResult::SuccessPerformed,
        ));

        // Should NOT trigger any new packet (no response to a response)
        // But SHOULD trigger OnStreamsResetPerformed
        let event = fixture.pop_event();
        if let SocketEvent::OnStreamsResetPerformed(streams) = event {
            assert_eq!(streams, vec![StreamId(1)]);
        } else {
            panic!("Unexpected event: {:?}", event);
        }
    }

    #[test]
    fn send_outgoing_reset_rollback_on_error() {
        let mut fixture = TestFixture::new();

        fixture.do_reset_streams(&[StreamId(1)]);

        let req = fixture.expect_sent_reset_request();
        let req_seq_nbr = req.request_seq_nbr;

        // Receive Error response
        fixture.handle_reconfig(fixture.prepare_reconfig_response(
            req_seq_nbr,
            ReconfigurationResponseResult::ErrorBadSequenceNumber,
        ));

        let event = fixture.pop_event();
        if let SocketEvent::OnStreamsResetFailed(streams) = event {
            assert_eq!(streams, vec![StreamId(1)]);
        } else {
            panic!("Unexpected event: {:?}", event);
        }
    }

    #[test]
    fn send_outgoing_reset_retransmit_on_in_progress() {
        let mut fixture = TestFixture::new();

        fixture.do_reset_streams(&[StreamId(1)]);

        let req = fixture.expect_sent_reset_request();
        let req_seq_nbr = req.request_seq_nbr;

        // Receive InProgress response
        fixture.handle_reconfig(
            fixture
                .prepare_reconfig_response(req_seq_nbr, ReconfigurationResponseResult::InProgress),
        );

        // Should NOT trigger any new reconfig packet immediately. Drain events to be sure.
        while let Some(event) = fixture.try_pop_event() {
            if let SocketEvent::SendPacket(packet) = event {
                let packet = SctpPacket::from_bytes(&packet, &fixture.ctx.options).unwrap();
                if packet.chunks.iter().any(|c| matches!(c, Chunk::ReConfig(_))) {
                    panic!("Unexpected ReConfig chunk");
                }
            }
        }

        // Advance time by RTO to trigger timeout
        let rto = fixture.tcb().rto.rto();
        let now = SocketTime::zero() + rto;

        fixture.handle_reconfig_timeout(now);

        // Should trigger retransmission
        assert_eq!(fixture.expect_sent_reset_request().streams, vec![StreamId(1)]);
    }

    #[test]
    fn reset_while_request_is_sent_will_queue() {
        let mut fixture = TestFixture::new();

        // Reset stream 1.
        fixture.do_reset_streams(&[StreamId(1)]);

        // Expect packet (reset request).
        let req = fixture.expect_sent_reset_request();
        assert_eq!(req.streams, vec![StreamId(1)]);
        let req_seq_nbr = req.request_seq_nbr;

        // Reset streams 2 and 3 while request is in-flight.
        fixture.do_reset_streams(&[StreamId(2), StreamId(3)]);

        // Try to send packets. Should NOT produce new ReConfig (because one is in flight).
        fixture.ctx.send_buffered_packets(&mut fixture.state, SocketTime::zero());
        while let Some(event) = fixture.try_pop_event() {
            if let SocketEvent::SendPacket(packet) = event {
                let packet = SctpPacket::from_bytes(&packet, &fixture.ctx.options).unwrap();
                if packet.chunks.iter().any(|c| matches!(c, Chunk::ReConfig(_))) {
                    panic!("Unexpected ReConfig chunk");
                }
            }
        }

        // Receive response for first request.
        fixture.handle_reconfig(fixture.prepare_reconfig_response(
            req_seq_nbr,
            ReconfigurationResponseResult::SuccessPerformed,
        ));

        // Expect OnStreamsResetPerformed for the first request
        let event = fixture.pop_event();
        if let SocketEvent::OnStreamsResetPerformed(streams) = event {
            assert_eq!(streams, vec![StreamId(1)]);
        } else {
            panic!("Unexpected event: {:?}", event);
        }

        // NOW the second request should be sent.
        let req = fixture.expect_sent_reset_request();
        let mut streams = req.streams.clone();
        streams.sort();
        assert_eq!(streams, vec![StreamId(2), StreamId(3)]);
        assert_eq!(req.request_seq_nbr, req_seq_nbr.wrapping_add(1));
    }

    #[test]
    fn send_incoming_reset_just_returns_nothing_performed() {
        let mut fixture = TestFixture::new();

        fixture.handle_reconfig(ReConfigChunk {
            parameters: vec![Parameter::IncomingSsnResetRequest(
                IncomingSsnResetRequestParameter {
                    request_seq_nbr: 10,
                    streams: vec![StreamId(1)],
                },
            )],
        });

        let resp = fixture.expect_sent_reconfig_response();
        assert_eq!(resp.response_seq_nbr, 10);
        assert_eq!(resp.result, ReconfigurationResponseResult::SuccessNothingToDo);
    }

    #[test]
    fn send_same_request_twice_is_idempotent() {
        // Simulate that receiving the same chunk twice (due to network issues,
        // or retransmissions, causing a RECONFIG to be re-received) is idempotent.
        let mut fixture = TestFixture::new();

        for _ in 0..2 {
            fixture.handle_reconfig(fixture.prepare_outgoing_reset(
                10,
                3,
                Tsn(11),
                vec![StreamId(1)],
            ));

            assert_eq!(
                fixture.expect_sent_reconfig_response().result,
                ReconfigurationResponseResult::InProgress
            );
        }
    }

    #[test]
    fn perform_close_after_one_first_failing() {
        // Inject a stream reset on the first expected TSN (which hasn't been seen).
        let mut fixture = TestFixture::new();

        // Peer Initial TSN is 10.
        fixture.handle_reconfig(fixture.prepare_outgoing_reset(
            10,
            3,
            Tsn(10), // Missing (current is before 10)
            vec![StreamId(1)],
        ));

        // The socket is expected to say "in progress" as that TSN hasn't been seen.
        let response = fixture.expect_sent_reconfig_response();
        assert_eq!(response.result, ReconfigurationResponseResult::InProgress);

        // Let the socket receive the TSN.
        let mut seq = DataSequencer::new(StreamId(1));
        fixture.receive(Tsn(10), seq.ordered("1234", "BE"));

        // And emulate that time has passed, and the peer retries the stream reset,
        // but now with an incremented request sequence number.
        fixture.handle_reconfig(fixture.prepare_outgoing_reset(11, 3, Tsn(10), vec![StreamId(1)]));

        // This is supposed to be handled well.
        fixture.expect_incoming_stream_reset_event(vec![StreamId(1)]);
        assert_eq!(
            fixture.expect_sent_reconfig_response().result,
            ReconfigurationResponseResult::SuccessPerformed
        );
    }
}
