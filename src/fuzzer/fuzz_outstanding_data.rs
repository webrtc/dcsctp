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

use crate::api::LifecycleId;
use crate::api::SocketTime;
use crate::api::StreamId;
use crate::packet::data::Data;
use crate::packet::sack_chunk::GapAckBlock;
use crate::tx::outstanding_data::OutstandingData;
use crate::types::Mid;
use crate::types::OutgoingMessageId;
use crate::types::Ssn;
use crate::types::StreamKey;
use crate::types::Tsn;
use arbitrary::Arbitrary;
use arbitrary::Unstructured;
use std::time::Duration;

#[derive(Arbitrary, Debug)]
enum Command {
    AdvanceTime {
        delta_ms: u16,
    },
    Insert {
        max_retransmissions: u16,
        lifetime_ms: u32,
        lifecycle_id: Option<u64>,
        stream_id: u16,
        ssn: u16,
        mid: u32,
        is_unordered: bool,
        payload_len: u16,
    },
    HandleSack {
        cumulative_tsn_ack: u32,
        gap_ack_blocks: Vec<(u16, u16)>,
        is_in_fast_recovery: bool,
    },
    ExpireOutstandingChunks,
    NackAll,
    GetChunksToBeFastRetransmitted {
        max_size: usize,
    },
    GetChunksToBeRetransmitted {
        max_size: usize,
    },
}

pub fn fuzz_outstanding_data(data: &[u8]) {
    let mut unstructured = Unstructured::new(data);
    let commands = match unstructured.arbitrary::<Vec<Command>>() {
        Ok(c) => c,
        Err(_) => return,
    };

    let data_chunk_header_size = 16;
    let last_tsn = match u32::arbitrary(&mut unstructured) {
        Ok(tsn) => Tsn(tsn),
        Err(_) => return,
    };
    let mut outstanding_data = OutstandingData::new(data_chunk_header_size, last_tsn);
    let mut next_message_id: u32 = 42;
    let mut current_time = SocketTime::zero();

    for command in commands {
        match command {
            Command::AdvanceTime { delta_ms } => {
                current_time = current_time + Duration::from_millis(delta_ms as u64);
            }
            Command::Insert {
                max_retransmissions,
                lifetime_ms,
                lifecycle_id,
                stream_id,
                ssn,
                mid,
                is_unordered,
                payload_len,
            } => {
                // get_unsent_messages_to_discard must be called prior to calling insert, as
                // documented.
                outstanding_data.get_unsent_messages_to_discard();

                let message_id = OutgoingMessageId(next_message_id);
                next_message_id += 1;

                let data = Data {
                    stream_key: StreamKey::new(is_unordered, StreamId(stream_id)),
                    ssn: Ssn(ssn),
                    mid: Mid(mid),
                    is_beginning: true,
                    is_end: true,
                    payload: vec![0; (payload_len % 1500) as usize + 1],
                    ..Default::default()
                };

                let expires_at = current_time + Duration::from_millis(lifetime_ms as u64);

                outstanding_data.insert(
                    message_id,
                    &data,
                    current_time,
                    max_retransmissions,
                    expires_at,
                    lifecycle_id.and_then(LifecycleId::new),
                );
            }
            Command::HandleSack { cumulative_tsn_ack, gap_ack_blocks, is_in_fast_recovery } => {
                let gap_blocks: Vec<GapAckBlock> =
                    gap_ack_blocks.into_iter().map(|(s, e)| GapAckBlock::new(s, e)).collect();
                outstanding_data.handle_sack(
                    Tsn(cumulative_tsn_ack),
                    &gap_blocks,
                    is_in_fast_recovery,
                );
            }
            Command::ExpireOutstandingChunks => {
                outstanding_data.expire_outstanding_chunks(current_time);
            }
            Command::NackAll => {
                outstanding_data.nack_all();
            }
            Command::GetChunksToBeFastRetransmitted { max_size } => {
                outstanding_data.get_chunks_to_be_fast_retransmitted(current_time, max_size);
            }
            Command::GetChunksToBeRetransmitted { max_size } => {
                outstanding_data.get_chunks_to_be_retransmitted(current_time, max_size);
            }
        }
    }
}
