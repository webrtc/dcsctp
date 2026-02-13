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
use crate::api::SocketEvent;
use crate::api::SocketTime;
use crate::packet::abort_chunk::AbortChunk;
use crate::packet::chunk::Chunk;
use crate::packet::error_causes::ErrorCause;
use crate::packet::sctp_packet::CommonHeader;
use crate::packet::sctp_packet::SctpPacketBuilder;
use crate::packet::shutdown_ack_chunk::ShutdownAckChunk;
use crate::packet::shutdown_chunk::ShutdownChunk;
use crate::packet::shutdown_complete_chunk::ShutdownCompleteChunk;
use crate::packet::user_initiated_abort_error_cause::UserInitiatedAbortErrorCause;
use crate::socket::context::Context;
use crate::socket::state::CookieEchoState;
use crate::socket::state::ShutdownSentState;
use crate::socket::state::State;
use crate::timer::BackoffAlgorithm;
use crate::timer::Timer;
use crate::transition_between;

pub(crate) fn do_shutdown(state: &mut State, ctx: &mut Context, now: SocketTime) {
    // From <https://datatracker.ietf.org/doc/html/rfc9260#section-9.2-2>:
    //
    //   Upon receipt of the SHUTDOWN primitive from its upper layer, the endpoint enters the
    //   SHUTDOWN-PENDING state and remains there until all outstanding data has been
    //   acknowledged by its peer.
    match state {
        State::Closed
        | State::ShutdownPending(_)
        | State::ShutdownSent(_)
        | State::ShutdownAckSent(_)
        | State::ShutdownReceived(_) => {
            // Already closed or shutting down.
        }
        State::CookieWait(_) => {
            // Connection closed during the initial connection phase. There is no outstanding
            // data, so the socket can just be closed (stopping any connection timers, if any),
            // as this is the client's intention, by calling [shutdown()].
            ctx.internal_close(state, ErrorKind::NoError, "".to_string());
        }
        State::CookieEchoed(_) | State::Established(_) => {
            transition_between!(*state,
                State::CookieEchoed(CookieEchoState { tcb, .. }) | State::Established(tcb) =>
                    State::ShutdownPending(tcb)
            );

            maybe_send_shutdown(state, ctx, now);
        }
    }
}

pub(crate) fn handle_shutdown(state: &mut State, ctx: &mut Context) {
    match state {
        State::Closed
        | State::ShutdownReceived(_)
        | State::ShutdownAckSent(_)
        | State::CookieWait(_)
        | State::CookieEchoed(_) => {
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
            transition_between!(*state,
                State::Established(tcb), State::ShutdownPending(tcb) =>
                    State::ShutdownReceived(tcb)
            );

            maybe_send_shutdown_ack(state, ctx);
        }
        State::ShutdownSent(_) => {
            // From <https://datatracker.ietf.org/doc/html/rfc9260#section-9.2-22>:
            //
            //   If an endpoint is in the SHUTDOWN-SENT state and receives a SHUTDOWN chunk from
            //   its peer, the endpoint SHOULD respond immediately with a SHUTDOWN ACK chunk to
            //   its peer and move into the SHUTDOWN-ACK-SENT state, restarting its T2-shutdown
            //   timer.
            transition_between!(*state,
                State::ShutdownSent(ShutdownSentState { tcb, .. }) =>
                    State::ShutdownAckSent(tcb)
            );

            send_shutdown_ack(state, ctx);
        }
    }
}

pub(crate) fn handle_shutdown_ack(state: &mut State, ctx: &mut Context, header: &CommonHeader) {
    match &state {
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
            ctx.events.borrow_mut().add(SocketEvent::SendPacket(
                tcb.new_packet()
                    .add(&Chunk::ShutdownComplete(ShutdownCompleteChunk { tag_reflected: false }))
                    .build(),
            ));
            ctx.tx_packets_count += 1;
            ctx.internal_close(state, ErrorKind::NoError, "".to_string());
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
            ctx.events.borrow_mut().add(SocketEvent::SendPacket(
                SctpPacketBuilder::new(
                    header.verification_tag,
                    ctx.options.local_port,
                    ctx.options.remote_port,
                    ctx.options.mtu,
                )
                .add(&Chunk::ShutdownComplete(ShutdownCompleteChunk { tag_reflected: true }))
                .build(),
            ));
            ctx.tx_packets_count += 1;
        }
    }
}

pub(crate) fn handle_shutdown_complete(
    state: &mut State,
    ctx: &mut Context,
    _chunk: ShutdownCompleteChunk,
) {
    if let State::ShutdownAckSent(_) = state {
        // From <https://datatracker.ietf.org/doc/html/rfc9260#section-9.2-15>:
        //
        //   Upon reception of the SHUTDOWN COMPLETE chunk, the endpoint verifies that it is in
        //   the SHUTDOWN-ACK-SENT state; if it is not, the chunk SHOULD be discarded. If the
        //   endpoint is in the SHUTDOWN-ACK-SENT state, the endpoint SHOULD stop the
        //   T2-shutdown timer and remove all knowledge of the association (and thus the
        //   association enters the CLOSED state).
        ctx.internal_close(state, ErrorKind::NoError, "".to_string());
    }
}

/// Handles the T2-shutdown timer.
///
/// Returns `true` if the timer expired.
pub(crate) fn handle_t2_shutdown_timeout(
    state: &mut State,
    ctx: &mut Context,
    now: SocketTime,
) -> bool {
    let State::ShutdownSent(s) = state else {
        return false;
    };
    if !s.t2_shutdown.expire(now) {
        return false;
    }

    if s.t2_shutdown.is_running() {
        send_shutdown(state, ctx);
        return true;
    }

    ctx.events.borrow_mut().add(SocketEvent::SendPacket(
        s.tcb
            .new_packet()
            .add(&Chunk::Abort(AbortChunk {
                error_causes: vec![ErrorCause::UserInitiatedAbort(UserInitiatedAbortErrorCause {
                    reason: "Too many retransmissions".into(),
                })],
            }))
            .build(),
    ));
    ctx.tx_packets_count += 1;
    ctx.internal_close(state, ErrorKind::TooManyRetries, "Too many retransmissions".into());
    true
}

pub(crate) fn maybe_send_shutdown_on_packet_received(
    state: &mut State,
    ctx: &mut Context,
    now: SocketTime,
    chunks: &[Chunk],
) {
    if let State::ShutdownSent(s) = state {
        if chunks.iter().any(|c| matches!(c, Chunk::Data(_))) {
            // From <https://datatracker.ietf.org/doc/html/rfc9260#section-9.2-10>:
            //
            //   While in the SHUTDOWN-SENT state, the SHUTDOWN chunk sender MUST immediately
            //   respond to each received packet containing one or more DATA chunks with a
            //   SHUTDOWN chunk and restart the T2-shutdown timer.
            s.t2_shutdown.set_duration(s.tcb.rto.rto());
            s.t2_shutdown.start(now);
            send_shutdown(state, ctx);
        }
    }
}

pub(crate) fn maybe_send_shutdown(state: &mut State, ctx: &mut Context, now: SocketTime) {
    let State::ShutdownPending(tcb) = state else { unreachable!() };
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
        ctx.options.max_retransmissions,
        None,
    );
    t2_shutdown.start(now);

    transition_between!(*state,
        State::ShutdownPending(tcb) =>
            State::ShutdownSent(ShutdownSentState { tcb, t2_shutdown })
    );

    send_shutdown(state, ctx);
}

pub(crate) fn maybe_send_shutdown_ack(state: &mut State, ctx: &mut Context) {
    let State::ShutdownReceived(tcb) = &state else { unreachable!() };
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
    transition_between!(*state,
        State::ShutdownReceived(tcb) => State::ShutdownAckSent(tcb)
    );

    send_shutdown_ack(state, ctx);
}

pub(crate) fn send_shutdown(state: &mut State, ctx: &mut Context) {
    let State::ShutdownSent(ShutdownSentState { tcb, .. }) = &state else { unreachable!() };
    ctx.events.borrow_mut().add(SocketEvent::SendPacket(
        tcb.new_packet()
            .add(&Chunk::Shutdown(ShutdownChunk {
                cumulative_tsn_ack: tcb.data_tracker.last_cumulative_acked_tsn(),
            }))
            .build(),
    ));
    ctx.tx_packets_count += 1;
}

pub(crate) fn send_shutdown_ack(state: &mut State, ctx: &mut Context) {
    let State::ShutdownAckSent(tcb) = &state else { unreachable!() };
    ctx.events.borrow_mut().add(SocketEvent::SendPacket(
        tcb.new_packet().add(&Chunk::ShutdownAck(ShutdownAckChunk {})).build(),
    ));
    ctx.tx_packets_count += 1;
}
