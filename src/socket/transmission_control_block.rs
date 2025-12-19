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

use crate::api::handover::HandoverCapabilities;
use crate::api::handover::HandoverReadiness;
use crate::api::handover::SocketHandoverState;
use crate::api::Options;
use crate::api::SocketTime;
use crate::api::StreamId;
use crate::math::round_down_to_4;
use crate::packet::chunk::Chunk;
use crate::packet::data::Data;
use crate::packet::data_chunk::DataChunk;
use crate::packet::idata_chunk::IDataChunk;
use crate::packet::outgoing_ssn_reset_request_parameter::OutgoingSsnResetRequestParameter;
use crate::packet::parameter::Parameter;
use crate::packet::re_config_chunk::ReConfigChunk;
use crate::packet::reconfiguration_response_parameter::ReconfigurationResponseResult;
use crate::packet::sctp_packet::SctpPacketBuilder;
use crate::rx::data_tracker::DataTracker;
use crate::rx::reassembly_queue::ReassemblyQueue;
use crate::socket::capabilities::Capabilities;
use crate::timer::BackoffAlgorithm;
use crate::timer::Timer;
use crate::tx::retransmission_queue::RetransmissionQueue;
use crate::tx::retransmission_timeout::RetransmissionTimeout;
use crate::types::Tsn;
use crate::EventSink;
use std::cell::RefCell;
use std::rc::Rc;

#[derive(Clone)]
pub(crate) struct PreparedResetRequest {
    pub sender_last_assigned_tsn: Tsn,
    pub streams: Vec<StreamId>,
}

pub(crate) struct InflightResetRequest {
    pub request_sequence_number: u32,
    pub request: PreparedResetRequest,
}

pub(crate) enum CurrentResetRequest {
    /// There is no intention to reset outgoing streams.
    None,

    /// There is a prepared, but not yet sent outgoing stream reset request.
    Prepared(PreparedResetRequest),

    /// Like [`Self::Prepared`], but it has been allocated a request sequence number and is
    /// in-flight.
    Inflight(InflightResetRequest),
}

pub struct TransmissionControlBlock {
    pub my_verification_tag: u32,
    pub my_initial_tsn: Tsn,
    pub peer_verification_tag: u32,
    pub peer_initial_tsn: Tsn,
    pub tie_tag: u64,
    pub data_tracker: DataTracker,
    pub reassembly_queue: ReassemblyQueue,
    pub retransmission_queue: RetransmissionQueue,
    pub rto: RetransmissionTimeout,
    pub capabilities: Capabilities,

    /// The next sequence number for outgoing stream requests.
    next_outgoing_reset_req_seq_nbr: u32,

    pub reconfig_timer: Timer,

    /// The current stream request operation.
    pub current_reset_request: CurrentResetRequest,

    /// For incoming requests - last processed request sequence number.
    pub last_processed_req_seq_nbr: u32,

    pub last_processed_req_result: ReconfigurationResponseResult,

    local_port: u16,
    remote_port: u16,
    max_packet_size: usize,
}

impl TransmissionControlBlock {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        options: &Options,
        my_verification_tag: u32,
        my_initial_tsn: Tsn,
        peer_verification_tag: u32,
        peer_initial_tsn: Tsn,
        tie_tag: u64,
        a_rwnd: u32,
        capabilities: Capabilities,
        events: Rc<RefCell<dyn EventSink>>,
    ) -> Self {
        TransmissionControlBlock {
            my_verification_tag,
            my_initial_tsn,
            peer_verification_tag,
            peer_initial_tsn,
            tie_tag,
            data_tracker: DataTracker::new(peer_initial_tsn, options),
            reassembly_queue: ReassemblyQueue::new(
                options.max_receiver_window_buffer_size,
                capabilities.message_interleaving,
            ),
            retransmission_queue: RetransmissionQueue::new(
                Rc::clone(&events),
                my_initial_tsn,
                a_rwnd,
                options,
                capabilities.partial_reliability,
                capabilities.message_interleaving,
            ),
            rto: RetransmissionTimeout::new(options),
            capabilities,
            next_outgoing_reset_req_seq_nbr: my_initial_tsn.0,
            reconfig_timer: Timer::new(
                options.rto_initial,
                BackoffAlgorithm::Exponential,
                None,
                None,
            ),
            current_reset_request: CurrentResetRequest::None,
            last_processed_req_seq_nbr: peer_initial_tsn.0.wrapping_sub(1),
            last_processed_req_result: ReconfigurationResponseResult::SuccessNothingToDo,
            local_port: options.local_port,
            remote_port: options.remote_port,
            max_packet_size: round_down_to_4!(options.mtu),
        }
    }

    pub fn make_data_chunk(&self, tsn: Tsn, data: Data) -> Chunk {
        if self.capabilities.message_interleaving {
            Chunk::IData(IDataChunk { data, tsn })
        } else {
            Chunk::Data(DataChunk { data, tsn })
        }
    }

    pub fn add_prepared_ssn_reset_request(&mut self, builder: &mut SctpPacketBuilder) {
        debug_assert!(matches!(
            self.current_reset_request,
            CurrentResetRequest::Prepared(_) | CurrentResetRequest::Inflight(_)
        ));

        if let CurrentResetRequest::Prepared(request) = &self.current_reset_request {
            self.current_reset_request = CurrentResetRequest::Inflight(InflightResetRequest {
                request_sequence_number: self.next_outgoing_reset_req_seq_nbr,
                request: request.clone(),
            });
            self.next_outgoing_reset_req_seq_nbr =
                self.next_outgoing_reset_req_seq_nbr.wrapping_add(1);
        }

        let CurrentResetRequest::Inflight(InflightResetRequest {
            request_sequence_number,
            request,
        }) = &self.current_reset_request
        else {
            unreachable!()
        };

        builder.add(Chunk::ReConfig(ReConfigChunk {
            parameters: vec![Parameter::OutgoingSsnResetRequest(
                OutgoingSsnResetRequestParameter {
                    request_seq_nbr: *request_sequence_number,
                    response_seq_nbr: *request_sequence_number,
                    sender_last_assigned_tsn: request.sender_last_assigned_tsn,
                    streams: request.streams.clone(),
                },
            )],
        }));
    }

    pub fn start_ssn_reset_request(
        &mut self,
        now: SocketTime,
        streams: Vec<StreamId>,
        builder: &mut SctpPacketBuilder,
    ) {
        debug_assert!(!streams.is_empty());
        self.retransmission_queue.begin_reset_streams();
        self.current_reset_request = CurrentResetRequest::Prepared(PreparedResetRequest {
            sender_last_assigned_tsn: self.retransmission_queue.last_assigned_tsn(),
            streams,
        });
        self.reconfig_timer.set_duration(self.rto.rto());
        self.reconfig_timer.start(now);
        self.add_prepared_ssn_reset_request(builder);
    }

    pub fn new_packet(&self) -> SctpPacketBuilder {
        let mut b = SctpPacketBuilder::new(
            self.peer_verification_tag,
            self.local_port,
            self.remote_port,
            self.max_packet_size,
        );
        b.write_checksum(!self.capabilities.zero_checksum);
        b
    }

    pub fn get_handover_readiness(&self) -> HandoverReadiness {
        let stream_reset_readiness = match self.current_reset_request {
            CurrentResetRequest::None => HandoverReadiness::READY,
            _ => HandoverReadiness::PENDING_STREAM_RESET_REQUEST,
        };

        stream_reset_readiness
            | self.data_tracker.get_handover_readiness()
            | self.reassembly_queue.get_handover_readiness()
            | self.retransmission_queue.get_handover_readiness()
    }

    pub(crate) fn add_to_handover_state(&self, state: &mut SocketHandoverState) {
        state.capabilities = HandoverCapabilities {
            partial_reliability: self.capabilities.partial_reliability,
            message_interleaving: self.capabilities.message_interleaving,
            reconfig: self.capabilities.reconfig,
            zero_checksum: self.capabilities.zero_checksum,
            negotiated_maximum_incoming_streams: self
                .capabilities
                .negotiated_maximum_incoming_streams,
            negotiated_maximum_outgoing_streams: self
                .capabilities
                .negotiated_maximum_outgoing_streams,
        };

        state.my_verification_tag = self.my_verification_tag;
        state.peer_verification_tag = self.peer_verification_tag;
        state.my_initial_tsn = self.my_initial_tsn.0;
        state.peer_initial_tsn = self.peer_initial_tsn.0;
        state.tie_tag = self.tie_tag;

        self.data_tracker.add_to_handover_state(state);
        self.reassembly_queue.add_to_handover_state(state);
        self.retransmission_queue.add_to_handover_state(state);
    }

    pub(crate) fn restore_from_state(&mut self, state: &SocketHandoverState) {
        self.data_tracker.restore_from_state(state);
        self.reassembly_queue.restore_from_state(state);
        self.retransmission_queue.restore_from_state(state);
    }
}
