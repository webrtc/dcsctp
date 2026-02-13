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
    let mut responses: Vec<Parameter> = Vec::new();
    for parameter in chunk.parameters {
        match parameter {
            Parameter::OutgoingSsnResetRequest(OutgoingSsnResetRequestParameter {
                request_seq_nbr,
                sender_last_assigned_tsn,
                streams,
                ..
            }) => {
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
