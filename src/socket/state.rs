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

use crate::packet::cookie_echo_chunk::CookieEchoChunk;
use crate::socket::transmission_control_block::TransmissionControlBlock;
use crate::timer::Timer;
use crate::types::Tsn;

pub(crate) struct CookieWaitState {
    pub t1_init: Timer,
    pub initial_tsn: Tsn,
    pub verification_tag: u32,
}

pub(crate) struct CookieEchoState {
    pub t1_cookie: Timer,
    pub cookie_echo_chunk: CookieEchoChunk,
    pub initial_tsn: Tsn,
    pub verification_tag: u32,
    pub tcb: TransmissionControlBlock,
}

pub(crate) struct ShutdownSentState {
    pub t2_shutdown: Timer,
    pub tcb: TransmissionControlBlock,
}

pub(crate) enum State {
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
    pub fn tcb_mut(&mut self) -> Option<&mut TransmissionControlBlock> {
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

    pub fn tcb(&self) -> Option<&TransmissionControlBlock> {
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

/// Facilitates state transitions within a `State` enum, allowing the state enum variant arguments
/// to be moved to the new state, improving code readability.
#[macro_export]
macro_rules! transition_between {
  ($state:expr, $($from_pat:pat),+ => $to_expr:expr) => {
      $state = match std::mem::replace(&mut $state, State::Closed) {
          $($from_pat => $to_expr,)+
          _ => unreachable!(),
      };
  };
}
