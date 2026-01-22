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

use core::fmt;

pub enum HandoverSocketState {
    Closed,
    Connected,
}

pub struct HandoverCapabilities {
    pub partial_reliability: bool,
    pub message_interleaving: bool,
    pub reconfig: bool,
    pub zero_checksum: bool,
    pub negotiated_maximum_incoming_streams: u16,
    pub negotiated_maximum_outgoing_streams: u16,
}

pub struct HandoverOutgoingStream {
    pub id: u16,
    pub next_ssn: u16,
    pub next_unordered_mid: u32,
    pub next_ordered_mid: u32,
    pub priority: u16,
}

pub struct HandoverTransmission {
    pub next_tsn: u32,
    pub next_reset_req_sn: u32,
    pub cwnd: u32,
    pub a_rwnd: u32,
    pub ssthresh: u32,
    pub partial_bytes_acked: u32,
    pub streams: Vec<HandoverOutgoingStream>,
}

pub struct HandoverOrderedStream {
    pub id: u16,
    pub next_ssn: u32,
}

pub struct HandoverUnorderedStream {
    pub id: u16,
}

pub struct HandoverReceive {
    pub seen_packet: bool,
    pub last_cumulative_acked_tsn: u32,
    pub last_assembled_tsn: u32,
    pub last_completed_deferred_reset_req_sn: u32,
    pub last_completed_reset_req_sn: u32,
    pub ordered_streams: Vec<HandoverOrderedStream>,
    pub unordered_streams: Vec<HandoverUnorderedStream>,
}

// Stores state snapshot of a dcSCTP socket. The snapshot can be used to recreate the socket -
// possibly in another process. This state should be treaded as opaque - the calling client should
// not inspect or alter it except for serialization. Serialization is not provided by dcSCTP. If
// needed it has to be implemented in the calling client.
pub struct SocketHandoverState {
    pub socket_state: HandoverSocketState,

    pub my_verification_tag: u32,
    pub my_initial_tsn: u32,
    pub peer_verification_tag: u32,
    pub peer_initial_tsn: u32,
    pub tie_tag: u64,

    pub capabilities: HandoverCapabilities,
    pub tx: HandoverTransmission,
    pub rx: HandoverReceive,
}

impl Default for SocketHandoverState {
    fn default() -> Self {
        Self {
            socket_state: HandoverSocketState::Closed,
            my_verification_tag: 0,
            my_initial_tsn: 0,
            peer_verification_tag: 0,
            peer_initial_tsn: 0,
            tie_tag: 0,
            capabilities: HandoverCapabilities {
                partial_reliability: false,
                message_interleaving: false,
                reconfig: false,
                zero_checksum: false,
                negotiated_maximum_incoming_streams: 0,
                negotiated_maximum_outgoing_streams: 0,
            },
            tx: HandoverTransmission {
                next_tsn: 0,
                next_reset_req_sn: 0,
                cwnd: 0,
                a_rwnd: 0,
                ssthresh: 0,
                partial_bytes_acked: 0,
                streams: vec![],
            },
            rx: HandoverReceive {
                seen_packet: false,
                last_cumulative_acked_tsn: 0,
                last_assembled_tsn: 0,
                last_completed_deferred_reset_req_sn: 0,
                last_completed_reset_req_sn: 0,
                ordered_streams: vec![],
                unordered_streams: vec![],
            },
        }
    }
}

#[derive(Clone, PartialEq)]
pub struct HandoverReadiness(pub u32);

impl HandoverReadiness {
    // A list of possible reasons for a socket to be not ready for handover.
    pub const READY: HandoverReadiness = HandoverReadiness(0);
    pub const WRONG_CONNECTION_STATE: HandoverReadiness = HandoverReadiness(1);
    pub const SEND_QUEUE_NOT_EMPTY: HandoverReadiness = HandoverReadiness(2);
    pub const PENDING_STREAM_RESET_REQUEST: HandoverReadiness = HandoverReadiness(4);
    pub const DATA_TRACKER_TSN_BLOCKS_PENDING: HandoverReadiness = HandoverReadiness(8);
    pub const PENDING_STREAM_RESET: HandoverReadiness = HandoverReadiness(16);
    pub const STREAM_RESET_DEFERRED: HandoverReadiness = HandoverReadiness(64);
    pub const STREAM_HAS_UNASSEMBLED_CHUNKS: HandoverReadiness = HandoverReadiness(128);
    pub const RETRANSMISSION_QUEUE_OUTSTANDING_DATA: HandoverReadiness = HandoverReadiness(512);
    pub const RETRANSMISSION_QUEUE_FAST_RECOVERY: HandoverReadiness = HandoverReadiness(1024);
    pub const RETRANSMISSION_QUEUE_NOT_EMPTY: HandoverReadiness = HandoverReadiness(2048);

    pub fn is_ready(&self) -> bool {
        self.0 == Self::READY.0
    }

    pub fn contains(&self, reason: HandoverReadiness) -> bool {
        self.0 & reason.0 != 0
    }
}

impl fmt::Display for HandoverReadiness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const REASONS: &[(HandoverReadiness, &str)] = &[
            (HandoverReadiness::WRONG_CONNECTION_STATE, "wrong_connection_state"),
            (HandoverReadiness::SEND_QUEUE_NOT_EMPTY, "send_queue_not_empty"),
            (HandoverReadiness::PENDING_STREAM_RESET_REQUEST, "pending_stream_reset_request"),
            (HandoverReadiness::DATA_TRACKER_TSN_BLOCKS_PENDING, "data_tracker_tsn_blocks_pending"),
            (HandoverReadiness::PENDING_STREAM_RESET, "pending_stream_reset"),
            (HandoverReadiness::STREAM_RESET_DEFERRED, "stream_reset_deferred"),
            (HandoverReadiness::STREAM_HAS_UNASSEMBLED_CHUNKS, "stream_has_unassembled_chunks"),
            (
                HandoverReadiness::RETRANSMISSION_QUEUE_OUTSTANDING_DATA,
                "retransmission_queue_outstanding_data",
            ),
            (
                HandoverReadiness::RETRANSMISSION_QUEUE_FAST_RECOVERY,
                "retransmission_queue_fast_recovery",
            ),
            (HandoverReadiness::RETRANSMISSION_QUEUE_NOT_EMPTY, "retransmission_queue_not_empty"),
        ];

        let reasons: Vec<_> = REASONS
            .iter()
            .filter(|(bit, _)| self.0 & bit.0 != 0)
            .map(|(_, reason)| *reason)
            .collect();

        write!(f, "{}", reasons.join(","))
    }
}

impl fmt::Debug for HandoverReadiness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl std::ops::BitOr for HandoverReadiness {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitAnd<bool> for HandoverReadiness {
    type Output = Self;

    fn bitand(self, rhs: bool) -> Self::Output {
        if rhs { self } else { HandoverReadiness::READY }
    }
}
