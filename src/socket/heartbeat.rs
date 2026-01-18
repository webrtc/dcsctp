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
use crate::packet::chunk::Chunk;
use crate::packet::heartbeat_ack_chunk::HeartbeatAckChunk;
use crate::packet::heartbeat_info_parameter::HeartbeatInfoParameter;
use crate::packet::heartbeat_request_chunk::HeartbeatRequestChunk;
use crate::packet::parameter::Parameter;
use crate::packet::read_u32_be;
use crate::packet::write_u32_be;
use crate::socket::context::Context;
use crate::socket::state::State;

pub(crate) fn handle_heartbeat_req(
    state: &mut State,
    ctx: &mut Context,
    chunk: HeartbeatRequestChunk,
) {
    // From <https://datatracker.ietf.org/doc/html/rfc9260#section-8.3-9>:
    //
    //   The receiver of the HEARTBEAT chunk SHOULD immediately respond with a HEARTBEAT ACK
    //   chunk that contains the Heartbeat Information TLV, together with any other received
    //   TLVs, copied unchanged from the received HEARTBEAT chunk.
    if let Some(tcb) = state.tcb_mut() {
        ctx.events.borrow_mut().add(SocketEvent::SendPacket(
            tcb.new_packet()
                .add(&Chunk::HeartbeatAck(HeartbeatAckChunk { parameters: chunk.parameters }))
                .build(),
        ));
        ctx.tx_packets_count += 1;
    }
}

pub(crate) fn handle_heartbeat_ack(ctx: &mut Context, now: SocketTime, chunk: HeartbeatAckChunk) {
    ctx.heartbeat_timeout.stop();
    match chunk.parameters.iter().find_map(|p| match p {
        Parameter::HeartbeatInfo(HeartbeatInfoParameter { info }) => Some(info),
        _ => None,
    }) {
        Some(info) if info.len() == 4 => {
            let counter = read_u32_be!(&info);
            if counter == ctx.heartbeat_counter {
                let _rtt = now - ctx.heartbeat_sent_time;
                // From <https://datatracker.ietf.org/doc/html/rfc9260#section-8.1>:
                //
                //   When a HEARTBEAT ACK chunk is received from the peer endpoint, the counter
                //   SHOULD also be reset.
                ctx.tx_error_counter.reset();
            }
        }
        _ => {
            ctx.events.borrow_mut().add(SocketEvent::OnError(
                ErrorKind::ParseFailed,
                "Failed to parse HEARTBEAT-ACK; Invalid info parameter".into(),
            ));
        }
    }
}

pub(crate) fn handle_heartbeat_timeouts(state: &mut State, ctx: &mut Context, now: SocketTime) {
    if ctx.heartbeat_interval.expire(now) {
        if let Some(tcb) = state.tcb() {
            ctx.heartbeat_timeout.set_duration(ctx.options.rto_initial);
            ctx.heartbeat_timeout.start(now);
            ctx.heartbeat_counter = ctx.heartbeat_counter.wrapping_add(1);
            ctx.heartbeat_sent_time = now;
            let mut info = vec![0; 4];
            write_u32_be!(&mut info, ctx.heartbeat_counter);
            ctx.events.borrow_mut().add(SocketEvent::SendPacket(
                tcb.new_packet()
                    .add(&Chunk::HeartbeatRequest(HeartbeatRequestChunk {
                        parameters: vec![Parameter::HeartbeatInfo(HeartbeatInfoParameter { info })],
                    }))
                    .build(),
            ));
            ctx.tx_packets_count += 1;
        }
    }
    if ctx.heartbeat_timeout.expire(now) {
        // Note that the timeout timer is not restarted. It will be started again when the
        // interval timer expires.
        debug_assert!(!ctx.heartbeat_timeout.is_running());
        ctx.tx_error_counter.increment();
    }
}
