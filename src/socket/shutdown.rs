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

use crate::api::SocketEvent;
use crate::packet::chunk::Chunk;
use crate::packet::shutdown_ack_chunk::ShutdownAckChunk;
use crate::socket::context::Context;
use crate::socket::state::State;

pub(crate) fn send_shutdown_ack(state: &mut State, ctx: &mut Context) {
    let State::ShutdownAckSent(tcb) = &state else { unreachable!() };
    ctx.events.borrow_mut().add(SocketEvent::SendPacket(
        tcb.new_packet().add(&Chunk::ShutdownAck(ShutdownAckChunk {})).build(),
    ));
    ctx.tx_packets_count += 1;
}
