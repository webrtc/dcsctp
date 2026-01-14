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

#![allow(unsafe_code)]

use crate::api::DcSctpSocket as DcSctpSocketTrait;
use crate::api::ErrorKind as DcSctpErrorKind;
use crate::api::LifecycleId;
use crate::api::Message as DcSctpMessage;
use crate::api::Metrics as DcSctpMetrics;
use crate::api::Options as DcSctpOptions;
use crate::api::PpId;
use crate::api::ResetStreamsStatus as DcSctpResetStreamsStatus;
use crate::api::SctpImplementation as DcSctpSctpImplementation;
use crate::api::SendOptions as DcSctpSendOptions;
use crate::api::SendStatus as DcSctpSendStatus;
use crate::api::SocketEvent as DcSctpSocketEvent;
use crate::api::SocketState as DcSctpSocketState;
use crate::api::StreamId;
use crate::api::handover::HandoverCapabilities as DcSctpHandoverCapabilities;
use crate::api::handover::HandoverOrderedStream as DcSctpHandoverOrderedStream;
use crate::api::handover::HandoverOutgoingStream as DcSctpHandoverOutgoingStream;
use crate::api::handover::HandoverReceive as DcSctpHandoverReceive;
use crate::api::handover::HandoverSocketState as DcSctpHandoverSocketState;
use crate::api::handover::HandoverTransmission as DcSctpHandoverTransmission;
use crate::api::handover::HandoverUnorderedStream as DcSctpHandoverUnorderedStream;
use crate::api::handover::SocketHandoverState as DcSctpSocketHandoverState;
use std::time::Duration;

const MAX_LIFETIME_MS: u64 = 3600 * 1000;

#[cxx::bridge(namespace = "dcsctp_cxx")]
mod bridge {
    #[derive(Debug, Default)]
    struct Message {
        stream_id: u16,
        ppid: u32,
        payload: Vec<u8>,
    }

    #[derive(Debug)]
    struct SendOptions {
        unordered: bool,
        lifetime_ms: u64,
        max_retransmissions: u16,
        lifecycle_id: u64,
    }

    #[derive(Debug)]
    enum SocketState {
        Closed,
        Connecting,
        Connected,
        ShuttingDown,
    }

    #[derive(Debug)]
    pub enum ErrorKind {
        NoError,
        TooManyRetries,
        NotConnected,
        ParseFailed,
        WrongSequence,
        PeerReported,
        ProtocolViolation,
        ResourceExhaustion,
        UnsupportedOperation,
    }

    #[derive(Debug)]
    enum EventType {
        Nothing,
        // Valid fields in Event: packet.
        SendPacket,
        OnConnected,
        OnClosed,
        OnConnectionRestarted,
        // Valid fields in Event: error_kind, error_reason.
        OnAborted,
        // Valid fields in Event: error_kind, error_reason.
        OnError,
        // Valid fields in Event: stream_id.
        OnBufferedAmountLow,
        OnTotalBufferedAmountLow,
        // Valid fields in Event: stream_ids.
        OnStreamsResetFailed,
        // Valid fields in Event: stream_ids.
        OnStreamsResetPerformed,
        // Valid fields in Event: stream_ids.
        OnIncomingStreamReset,
        // Valid fields in Event: lifecycle_id.
        OnLifecycleMessageFullySent,
        // Valid fields in Event: lifecycle_id.
        OnLifecycleMessageMaybeExpired,
        // Valid fields in Event: lifecycle_id.
        OnLifecycleMessageExpired,
        // Valid fields in Event: lifecycle_id.
        OnLifecycleMessageDelivered,
        // Valid fields in Event: lifecycle_id.
        OnLifecycleEnd,
    }

    #[derive(Debug, PartialEq)]
    enum SendStatus {
        Success,
        ErrorMessageEmpty,
        ErrorMessageTooLarge,
        ErrorResourceExhaustion,
        ErrorShuttingDown,
    }

    #[derive(Debug, PartialEq)]
    enum ResetStreamsStatus {
        NotConnected,
        Performed,
        NotSupported,
    }

    #[derive(Debug)]
    enum SctpImplementation {
        Unknown,
        DcsctpRs,
        DcsctpCc,
        UsrSctp,
        Other,
    }

    #[derive(Debug)]
    struct Metrics {
        has_value: bool,
        tx_packets_count: usize,
        tx_messages_count: usize,
        rtx_packets_count: usize,
        rtx_bytes_count: u64,
        cwnd_bytes: usize,
        srtt_ms: u64,
        unack_data_count: usize,
        rx_packets_count: usize,
        rx_messages_count: usize,
        peer_rwnd_bytes: u32,
        peer_implementation: SctpImplementation,
        uses_message_interleaving: bool,
        uses_zero_checksum: bool,
        negotiated_maximum_incoming_streams: u16,
        negotiated_maximum_outgoing_streams: u16,
    }

    struct Event {
        event_type: EventType,
        error_kind: ErrorKind,
        stream_id: u16,
        lifecycle_id: u64,
        error_reason: String,
        packet: Vec<u8>,
        stream_ids: Vec<u16>,
    }

    #[derive(Debug)]
    enum HandoverSocketState {
        Closed,
        Connected,
    }

    #[derive(Debug, Default)]
    struct HandoverCapabilities {
        partial_reliability: bool,
        message_interleaving: bool,
        reconfig: bool,
        zero_checksum: bool,
        negotiated_maximum_incoming_streams: u16,
        negotiated_maximum_outgoing_streams: u16,
    }

    #[derive(Debug, Default)]
    struct HandoverOutgoingStream {
        id: u16,
        next_ssn: u16,
        next_unordered_mid: u32,
        next_ordered_mid: u32,
        priority: u16,
    }

    #[derive(Debug, Default)]
    struct HandoverTransmission {
        next_tsn: u32,
        next_reset_req_sn: u32,
        cwnd: u32,
        rwnd: u32,
        ssthresh: u32,
        partial_bytes_acked: u32,
        streams: Vec<HandoverOutgoingStream>,
    }

    #[derive(Debug, Default)]
    struct HandoverOrderedStream {
        id: u16,
        next_ssn: u32,
    }

    #[derive(Debug, Default)]
    struct HandoverUnorderedStream {
        id: u16,
    }

    #[derive(Debug, Default)]
    struct HandoverReceive {
        seen_packet: bool,
        last_cumulative_acked_tsn: u32,
        last_assembled_tsn: u32,
        last_completed_deferred_reset_req_sn: u32,
        last_completed_reset_req_sn: u32,
        ordered_streams: Vec<HandoverOrderedStream>,
        unordered_streams: Vec<HandoverUnorderedStream>,
    }

    #[derive(Debug, Default)]
    struct SocketHandoverState {
        has_value: bool,
        socket_state: HandoverSocketState,
        my_verification_tag: u32,
        my_initial_tsn: u32,
        peer_verification_tag: u32,
        peer_initial_tsn: u32,
        tie_tag: u64,
        capabilities: HandoverCapabilities,
        tx: HandoverTransmission,
        rx: HandoverReceive,
    }

    // Mirrors the Rust Options struct, where all optional primitive values (u32, u64) encoded as
    // their maximum value.
    struct Options {
        local_port: u16,
        remote_port: u16,
        announced_maximum_incoming_streams: u16,
        announced_maximum_outgoing_streams: u16,
        mtu: usize,
        max_message_size: usize,
        default_stream_priority: u16,
        max_receiver_window_buffer_size: usize,
        max_send_buffer_size: usize,
        per_stream_send_queue_limit: usize,
        total_buffered_amount_low_threshold: usize,
        default_stream_buffered_amount_low_threshold: usize,
        rtt_max: u64,
        rto_initial: u64,
        rto_max: u64,
        rto_min: u64,
        t1_init_timeout: u64,
        t1_cookie_timeout: u64,
        t2_shutdown_timeout: u64,
        max_timer_backoff_duration: u64,
        heartbeat_interval: u64,
        delayed_ack_max_timeout: u64,
        min_rtt_variance: u64,
        cwnd_mtus_initial: usize,
        cwnd_mtus_min: usize,
        avoid_fragmentation_cwnd_mtus: usize,
        max_burst: i32,
        max_retransmissions: u32,
        max_init_retransmits: u32,
        enable_partial_reliability: bool,
        enable_message_interleaving: bool,
        heartbeat_interval_include_rtt: bool,
        zero_checksum_alternate_error_detection_method: u32,
        disable_checksum_verification: bool,
    }

    extern "Rust" {
        type DcSctpSocket;

        fn version() -> String;
        fn default_options() -> Options;
        fn create_message(stream_id: u16, ppid: u32, payload_size: usize) -> Message;
        fn new_socket(name: &str, options: &Options) -> *mut DcSctpSocket;
        unsafe fn delete_socket(socket: *mut DcSctpSocket);
        fn state(socket: &DcSctpSocket) -> SocketState;
        fn connect(socket: &mut DcSctpSocket);
        fn restore_from_state(socket: &mut DcSctpSocket, state: &SocketHandoverState);
        fn shutdown(socket: &mut DcSctpSocket);
        fn close(socket: &mut DcSctpSocket);
        fn options(socket: &DcSctpSocket) -> Options;
        fn set_max_message_size(socket: &mut DcSctpSocket, max_message_size: usize);
        fn set_stream_priority(socket: &mut DcSctpSocket, stream_id: u16, priority: u16);
        fn get_stream_priority(socket: &mut DcSctpSocket, stream_id: u16) -> u16;
        fn buffered_amount(socket: &DcSctpSocket, stream_id: u16) -> usize;
        fn buffered_amount_low_threshold(socket: &DcSctpSocket, stream_id: u16) -> usize;
        fn set_buffered_amount_low_threshold(
            socket: &mut DcSctpSocket,
            stream_id: u16,
            bytes: usize,
        );
        fn handle_input(socket: &mut DcSctpSocket, data: &[u8]);
        fn poll_event(socket: &mut DcSctpSocket) -> Event;
        fn advance_time(socket: &mut DcSctpSocket, ns: u64);
        fn poll_timeout(socket: &DcSctpSocket) -> u64;
        fn message_ready_count(socket: &DcSctpSocket) -> usize;
        fn get_next_message(socket: &mut DcSctpSocket) -> Message;
        fn get_handover_readiness(socket: &DcSctpSocket) -> u32;
        fn get_handover_readiness_string(socket: &DcSctpSocket) -> String;
        fn get_handover_state_and_close(socket: &mut DcSctpSocket) -> SocketHandoverState;
        fn new_send_options() -> SendOptions;
        fn send(socket: &mut DcSctpSocket, message: Message, options: &SendOptions) -> SendStatus;
        fn send_many(
            socket: &mut DcSctpSocket,
            messages: Vec<Message>,
            options: &SendOptions,
        ) -> Vec<SendStatus>;
        fn reset_streams(socket: &mut DcSctpSocket, stream_ids: Vec<u16>) -> ResetStreamsStatus;
        fn get_metrics(socket: &DcSctpSocket) -> Metrics;
    }
}

pub const fn to_saturating_u64(d: Duration) -> u64 {
    let nanos = d.as_nanos();
    if nanos > u64::MAX as u128 { u64::MAX } else { nanos as u64 }
}

impl Default for bridge::Event {
    fn default() -> Self {
        Self {
            event_type: bridge::EventType::Nothing,
            error_kind: bridge::ErrorKind::NoError,
            stream_id: 0,
            lifecycle_id: 0,
            error_reason: "".to_string(),
            packet: vec![],
            stream_ids: vec![],
        }
    }
}

impl Default for bridge::HandoverSocketState {
    fn default() -> Self {
        bridge::HandoverSocketState::Closed
    }
}

impl From<DcSctpHandoverSocketState> for bridge::HandoverSocketState {
    fn from(value: DcSctpHandoverSocketState) -> Self {
        match value {
            DcSctpHandoverSocketState::Closed => bridge::HandoverSocketState::Closed,
            DcSctpHandoverSocketState::Connected => bridge::HandoverSocketState::Connected,
        }
    }
}

impl From<&bridge::HandoverSocketState> for DcSctpHandoverSocketState {
    fn from(value: &bridge::HandoverSocketState) -> Self {
        match *value {
            bridge::HandoverSocketState::Closed => DcSctpHandoverSocketState::Closed,
            bridge::HandoverSocketState::Connected => DcSctpHandoverSocketState::Connected,
            _ => DcSctpHandoverSocketState::Closed,
        }
    }
}

impl From<DcSctpHandoverCapabilities> for bridge::HandoverCapabilities {
    fn from(value: DcSctpHandoverCapabilities) -> Self {
        Self {
            partial_reliability: value.partial_reliability,
            message_interleaving: value.message_interleaving,
            reconfig: value.reconfig,
            zero_checksum: value.zero_checksum,
            negotiated_maximum_incoming_streams: value.negotiated_maximum_incoming_streams,
            negotiated_maximum_outgoing_streams: value.negotiated_maximum_outgoing_streams,
        }
    }
}

impl From<&bridge::HandoverCapabilities> for DcSctpHandoverCapabilities {
    fn from(value: &bridge::HandoverCapabilities) -> Self {
        Self {
            partial_reliability: value.partial_reliability,
            message_interleaving: value.message_interleaving,
            reconfig: value.reconfig,
            zero_checksum: value.zero_checksum,
            negotiated_maximum_incoming_streams: value.negotiated_maximum_incoming_streams,
            negotiated_maximum_outgoing_streams: value.negotiated_maximum_outgoing_streams,
        }
    }
}

impl From<DcSctpHandoverOutgoingStream> for bridge::HandoverOutgoingStream {
    fn from(value: DcSctpHandoverOutgoingStream) -> Self {
        Self {
            id: value.id,
            next_ssn: value.next_ssn,
            next_unordered_mid: value.next_unordered_mid,
            next_ordered_mid: value.next_ordered_mid,
            priority: value.priority,
        }
    }
}

impl From<&bridge::HandoverOutgoingStream> for DcSctpHandoverOutgoingStream {
    fn from(value: &bridge::HandoverOutgoingStream) -> Self {
        Self {
            id: value.id,
            next_ssn: value.next_ssn,
            next_unordered_mid: value.next_unordered_mid,
            next_ordered_mid: value.next_ordered_mid,
            priority: value.priority,
        }
    }
}

impl From<DcSctpHandoverTransmission> for bridge::HandoverTransmission {
    fn from(value: DcSctpHandoverTransmission) -> Self {
        Self {
            next_tsn: value.next_tsn,
            next_reset_req_sn: value.next_reset_req_sn,
            cwnd: value.cwnd,
            rwnd: value.rwnd,
            ssthresh: value.ssthresh,
            partial_bytes_acked: value.partial_bytes_acked,
            streams: value.streams.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<&bridge::HandoverTransmission> for DcSctpHandoverTransmission {
    fn from(value: &bridge::HandoverTransmission) -> Self {
        Self {
            next_tsn: value.next_tsn,
            next_reset_req_sn: value.next_reset_req_sn,
            cwnd: value.cwnd,
            rwnd: value.rwnd,
            ssthresh: value.ssthresh,
            partial_bytes_acked: value.partial_bytes_acked,
            streams: value.streams.iter().map(Into::into).collect(),
        }
    }
}

impl From<DcSctpHandoverOrderedStream> for bridge::HandoverOrderedStream {
    fn from(value: DcSctpHandoverOrderedStream) -> Self {
        Self { id: value.id, next_ssn: value.next_ssn }
    }
}

impl From<&bridge::HandoverOrderedStream> for DcSctpHandoverOrderedStream {
    fn from(value: &bridge::HandoverOrderedStream) -> Self {
        Self { id: value.id, next_ssn: value.next_ssn }
    }
}

impl From<DcSctpHandoverUnorderedStream> for bridge::HandoverUnorderedStream {
    fn from(value: DcSctpHandoverUnorderedStream) -> Self {
        Self { id: value.id }
    }
}

impl From<&bridge::HandoverUnorderedStream> for DcSctpHandoverUnorderedStream {
    fn from(value: &bridge::HandoverUnorderedStream) -> Self {
        Self { id: value.id }
    }
}

impl From<DcSctpHandoverReceive> for bridge::HandoverReceive {
    fn from(value: DcSctpHandoverReceive) -> Self {
        Self {
            seen_packet: value.seen_packet,
            last_cumulative_acked_tsn: value.last_cumulative_acked_tsn,
            last_assembled_tsn: value.last_assembled_tsn,
            last_completed_deferred_reset_req_sn: value.last_completed_deferred_reset_req_sn,
            last_completed_reset_req_sn: value.last_completed_reset_req_sn,
            ordered_streams: value.ordered_streams.into_iter().map(Into::into).collect(),
            unordered_streams: value.unordered_streams.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<&bridge::HandoverReceive> for DcSctpHandoverReceive {
    fn from(value: &bridge::HandoverReceive) -> Self {
        Self {
            seen_packet: value.seen_packet,
            last_cumulative_acked_tsn: value.last_cumulative_acked_tsn,
            last_assembled_tsn: value.last_assembled_tsn,
            last_completed_deferred_reset_req_sn: value.last_completed_deferred_reset_req_sn,
            last_completed_reset_req_sn: value.last_completed_reset_req_sn,
            ordered_streams: value.ordered_streams.iter().map(Into::into).collect(),
            unordered_streams: value.unordered_streams.iter().map(Into::into).collect(),
        }
    }
}

impl From<DcSctpSocketHandoverState> for bridge::SocketHandoverState {
    fn from(value: DcSctpSocketHandoverState) -> Self {
        Self {
            has_value: true,
            socket_state: value.socket_state.into(),
            my_verification_tag: value.my_verification_tag,
            my_initial_tsn: value.my_initial_tsn,
            peer_verification_tag: value.peer_verification_tag,
            peer_initial_tsn: value.peer_initial_tsn,
            tie_tag: value.tie_tag,
            capabilities: value.capabilities.into(),
            tx: value.tx.into(),
            rx: value.rx.into(),
        }
    }
}

impl From<&bridge::SocketHandoverState> for DcSctpSocketHandoverState {
    fn from(value: &bridge::SocketHandoverState) -> Self {
        Self {
            socket_state: (&value.socket_state).into(),
            my_verification_tag: value.my_verification_tag,
            my_initial_tsn: value.my_initial_tsn,
            peer_verification_tag: value.peer_verification_tag,
            peer_initial_tsn: value.peer_initial_tsn,
            tie_tag: value.tie_tag,
            capabilities: (&value.capabilities).into(),
            tx: (&value.tx).into(),
            rx: (&value.rx).into(),
        }
    }
}

impl From<DcSctpErrorKind> for bridge::ErrorKind {
    fn from(value: DcSctpErrorKind) -> Self {
        match value {
            DcSctpErrorKind::NoError => bridge::ErrorKind::NoError,
            DcSctpErrorKind::TooManyRetries => bridge::ErrorKind::TooManyRetries,
            DcSctpErrorKind::NotConnected => bridge::ErrorKind::NotConnected,
            DcSctpErrorKind::ParseFailed => bridge::ErrorKind::ParseFailed,
            DcSctpErrorKind::WrongSequence => bridge::ErrorKind::WrongSequence,
            DcSctpErrorKind::PeerReported => bridge::ErrorKind::PeerReported,
            DcSctpErrorKind::ProtocolViolation => bridge::ErrorKind::ProtocolViolation,
            DcSctpErrorKind::ResourceExhaustion => bridge::ErrorKind::ResourceExhaustion,
            DcSctpErrorKind::UnsupportedOperation => bridge::ErrorKind::UnsupportedOperation,
        }
    }
}

impl From<DcSctpSocketEvent> for bridge::Event {
    fn from(event: DcSctpSocketEvent) -> Self {
        match event {
            DcSctpSocketEvent::SendPacket(p) => bridge::Event {
                event_type: bridge::EventType::SendPacket,
                packet: p,
                ..Default::default()
            },
            DcSctpSocketEvent::OnConnected() => {
                bridge::Event { event_type: bridge::EventType::OnConnected, ..Default::default() }
            }
            DcSctpSocketEvent::OnClosed() => {
                bridge::Event { event_type: bridge::EventType::OnClosed, ..Default::default() }
            }
            DcSctpSocketEvent::OnConnectionRestarted() => bridge::Event {
                event_type: bridge::EventType::OnConnectionRestarted,
                ..Default::default()
            },
            DcSctpSocketEvent::OnAborted(kind, error_reason) => bridge::Event {
                event_type: bridge::EventType::OnAborted,
                error_kind: kind.into(),
                error_reason: error_reason.to_string(),
                ..Default::default()
            },
            DcSctpSocketEvent::OnError(kind, error_reason) => bridge::Event {
                event_type: bridge::EventType::OnError,
                error_kind: kind.into(),
                error_reason: error_reason.to_string(),
                ..Default::default()
            },
            DcSctpSocketEvent::OnBufferedAmountLow(stream_id) => bridge::Event {
                event_type: bridge::EventType::OnBufferedAmountLow,
                stream_id: stream_id.0,
                ..Default::default()
            },
            DcSctpSocketEvent::OnTotalBufferedAmountLow() => bridge::Event {
                event_type: bridge::EventType::OnTotalBufferedAmountLow,
                ..Default::default()
            },
            DcSctpSocketEvent::OnStreamsResetFailed(streams) => bridge::Event {
                event_type: bridge::EventType::OnStreamsResetFailed,
                stream_ids: streams.iter().map(|s| s.0).collect(),
                ..Default::default()
            },
            DcSctpSocketEvent::OnStreamsResetPerformed(streams) => bridge::Event {
                event_type: bridge::EventType::OnStreamsResetPerformed,
                stream_ids: streams.iter().map(|s| s.0).collect(),
                ..Default::default()
            },
            DcSctpSocketEvent::OnIncomingStreamReset(streams) => bridge::Event {
                event_type: bridge::EventType::OnIncomingStreamReset,
                stream_ids: streams.iter().map(|s| s.0).collect(),
                ..Default::default()
            },
            DcSctpSocketEvent::OnLifecycleMessageFullySent(lifecyle_id) => bridge::Event {
                event_type: bridge::EventType::OnLifecycleMessageFullySent,
                lifecycle_id: lifecyle_id.value(),
                ..Default::default()
            },
            DcSctpSocketEvent::OnLifecycleMessageMaybeExpired(lifecyle_id) => bridge::Event {
                event_type: bridge::EventType::OnLifecycleMessageMaybeExpired,
                lifecycle_id: lifecyle_id.value(),
                ..Default::default()
            },
            DcSctpSocketEvent::OnLifecycleMessageExpired(lifecyle_id) => bridge::Event {
                event_type: bridge::EventType::OnLifecycleMessageExpired,
                lifecycle_id: lifecyle_id.value(),
                ..Default::default()
            },
            DcSctpSocketEvent::OnLifecycleMessageDelivered(lifecyle_id) => bridge::Event {
                event_type: bridge::EventType::OnLifecycleMessageDelivered,
                lifecycle_id: lifecyle_id.value(),
                ..Default::default()
            },
            DcSctpSocketEvent::OnLifecycleEnd(lifecyle_id) => bridge::Event {
                event_type: bridge::EventType::OnLifecycleEnd,
                lifecycle_id: lifecyle_id.value(),
                ..Default::default()
            },
        }
    }
}

impl From<DcSctpOptions> for bridge::Options {
    fn from(value: DcSctpOptions) -> Self {
        // Destructure value to catch when fields are added to it.
        let DcSctpOptions {
            local_port,
            remote_port,
            announced_maximum_incoming_streams,
            announced_maximum_outgoing_streams,
            mtu,
            max_message_size,
            default_stream_priority,
            max_receiver_window_buffer_size,
            max_send_buffer_size,
            per_stream_send_queue_limit,
            total_buffered_amount_low_threshold,
            default_stream_buffered_amount_low_threshold,
            rtt_max,
            rto_initial,
            rto_max,
            rto_min,
            t1_init_timeout,
            t1_cookie_timeout,
            t2_shutdown_timeout,
            max_timer_backoff_duration,
            heartbeat_interval,
            delayed_ack_max_timeout,
            min_rtt_variance,
            cwnd_mtus_initial,
            cwnd_mtus_min,
            avoid_fragmentation_cwnd_mtus,
            max_burst,
            max_retransmissions,
            max_init_retransmits,
            enable_partial_reliability,
            enable_message_interleaving,
            heartbeat_interval_include_rtt,
            zero_checksum_alternate_error_detection_method,
            disable_checksum_verification,
        } = value;

        Self {
            local_port,
            remote_port,
            announced_maximum_incoming_streams,
            announced_maximum_outgoing_streams,
            mtu,
            max_message_size,
            default_stream_priority,
            max_receiver_window_buffer_size,
            max_send_buffer_size,
            per_stream_send_queue_limit,
            total_buffered_amount_low_threshold,
            default_stream_buffered_amount_low_threshold,
            rtt_max: to_saturating_u64(rtt_max),
            rto_initial: to_saturating_u64(rto_initial),
            rto_max: to_saturating_u64(rto_max),
            rto_min: to_saturating_u64(rto_min),
            t1_init_timeout: to_saturating_u64(t1_init_timeout),
            t1_cookie_timeout: to_saturating_u64(t1_cookie_timeout),
            t2_shutdown_timeout: to_saturating_u64(t2_shutdown_timeout),
            max_timer_backoff_duration: max_timer_backoff_duration
                .map(to_saturating_u64)
                .unwrap_or(u64::MAX),
            heartbeat_interval: to_saturating_u64(heartbeat_interval),
            delayed_ack_max_timeout: to_saturating_u64(delayed_ack_max_timeout),
            min_rtt_variance: to_saturating_u64(min_rtt_variance),
            cwnd_mtus_initial,
            cwnd_mtus_min,
            avoid_fragmentation_cwnd_mtus,
            max_burst,
            max_retransmissions: max_retransmissions.unwrap_or(u32::MAX),
            max_init_retransmits: max_init_retransmits.unwrap_or(u32::MAX),
            enable_partial_reliability,
            enable_message_interleaving,
            heartbeat_interval_include_rtt,
            zero_checksum_alternate_error_detection_method:
                zero_checksum_alternate_error_detection_method.0,
            disable_checksum_verification,
        }
    }
}

impl From<&bridge::Options> for DcSctpOptions {
    fn from(val: &bridge::Options) -> Self {
        DcSctpOptions {
            local_port: val.local_port,
            remote_port: val.remote_port,
            announced_maximum_incoming_streams: val.announced_maximum_incoming_streams,
            announced_maximum_outgoing_streams: val.announced_maximum_outgoing_streams,
            mtu: val.mtu,
            max_message_size: val.max_message_size,
            default_stream_priority: val.default_stream_priority,
            max_receiver_window_buffer_size: val.max_receiver_window_buffer_size,
            max_send_buffer_size: val.max_send_buffer_size,
            per_stream_send_queue_limit: val.per_stream_send_queue_limit,
            total_buffered_amount_low_threshold: val.total_buffered_amount_low_threshold,
            default_stream_buffered_amount_low_threshold: val
                .default_stream_buffered_amount_low_threshold,
            rtt_max: Duration::from_nanos(val.rtt_max),
            rto_initial: Duration::from_nanos(val.rto_initial),
            rto_max: Duration::from_nanos(val.rto_max),
            rto_min: Duration::from_nanos(val.rto_min),
            t1_init_timeout: Duration::from_nanos(val.t1_init_timeout),
            t1_cookie_timeout: Duration::from_nanos(val.t1_cookie_timeout),
            t2_shutdown_timeout: Duration::from_nanos(val.t2_shutdown_timeout),
            max_timer_backoff_duration: (val.max_timer_backoff_duration != u64::MAX)
                .then_some(Duration::from_nanos(val.max_timer_backoff_duration)),
            heartbeat_interval: Duration::from_nanos(val.heartbeat_interval),
            delayed_ack_max_timeout: Duration::from_nanos(val.delayed_ack_max_timeout),
            min_rtt_variance: Duration::from_nanos(val.min_rtt_variance),
            cwnd_mtus_initial: val.cwnd_mtus_initial,
            cwnd_mtus_min: val.cwnd_mtus_min,
            avoid_fragmentation_cwnd_mtus: val.avoid_fragmentation_cwnd_mtus,
            max_burst: val.max_burst,
            max_retransmissions: (val.max_retransmissions != u32::MAX)
                .then_some(val.max_retransmissions),
            max_init_retransmits: (val.max_init_retransmits != u32::MAX)
                .then_some(val.max_init_retransmits),
            enable_partial_reliability: val.enable_partial_reliability,
            enable_message_interleaving: val.enable_message_interleaving,
            heartbeat_interval_include_rtt: val.heartbeat_interval_include_rtt,
            zero_checksum_alternate_error_detection_method:
                crate::api::ZeroChecksumAlternateErrorDetectionMethod(
                    val.zero_checksum_alternate_error_detection_method,
                ),
            disable_checksum_verification: val.disable_checksum_verification,
        }
    }
}

impl From<DcSctpSendStatus> for bridge::SendStatus {
    fn from(status: DcSctpSendStatus) -> Self {
        match status {
            DcSctpSendStatus::Success => bridge::SendStatus::Success,
            DcSctpSendStatus::ErrorMessageEmpty => bridge::SendStatus::ErrorMessageEmpty,
            DcSctpSendStatus::ErrorMessageTooLarge => bridge::SendStatus::ErrorMessageTooLarge,
            DcSctpSendStatus::ErrorResourceExhaustion => {
                bridge::SendStatus::ErrorResourceExhaustion
            }
            DcSctpSendStatus::ErrorShuttingDown => bridge::SendStatus::ErrorShuttingDown,
        }
    }
}

impl From<&bridge::SendOptions> for DcSctpSendOptions {
    fn from(options: &bridge::SendOptions) -> Self {
        DcSctpSendOptions {
            unordered: options.unordered,
            lifetime: (options.lifetime_ms < MAX_LIFETIME_MS)
                .then_some(Duration::from_millis(options.lifetime_ms)),
            max_retransmissions: (options.max_retransmissions != u16::MAX)
                .then_some(options.max_retransmissions),
            lifecycle_id: LifecycleId::new(options.lifecycle_id),
        }
    }
}

impl From<DcSctpResetStreamsStatus> for bridge::ResetStreamsStatus {
    fn from(status: DcSctpResetStreamsStatus) -> Self {
        match status {
            DcSctpResetStreamsStatus::NotConnected => bridge::ResetStreamsStatus::NotConnected,
            DcSctpResetStreamsStatus::Performed => bridge::ResetStreamsStatus::Performed,
            DcSctpResetStreamsStatus::NotSupported => bridge::ResetStreamsStatus::NotSupported,
        }
    }
}

impl From<DcSctpSctpImplementation> for bridge::SctpImplementation {
    fn from(impl_: DcSctpSctpImplementation) -> Self {
        match impl_ {
            DcSctpSctpImplementation::Unknown => bridge::SctpImplementation::Unknown,
            DcSctpSctpImplementation::DcsctpRs => bridge::SctpImplementation::DcsctpRs,
            DcSctpSctpImplementation::DcsctpCc => bridge::SctpImplementation::DcsctpCc,
            DcSctpSctpImplementation::UsrSctp => bridge::SctpImplementation::UsrSctp,
            DcSctpSctpImplementation::Other => bridge::SctpImplementation::Other,
        }
    }
}

impl Default for bridge::Metrics {
    fn default() -> Self {
        Self {
            has_value: false,
            tx_packets_count: 0,
            tx_messages_count: 0,
            rtx_packets_count: 0,
            rtx_bytes_count: 0,
            cwnd_bytes: 0,
            srtt_ms: 0,
            unack_data_count: 0,
            rx_packets_count: 0,
            rx_messages_count: 0,
            peer_rwnd_bytes: 0,
            peer_implementation: bridge::SctpImplementation::Unknown,
            uses_message_interleaving: false,
            uses_zero_checksum: false,
            negotiated_maximum_incoming_streams: 0,
            negotiated_maximum_outgoing_streams: 0,
        }
    }
}

impl From<DcSctpMetrics> for bridge::Metrics {
    fn from(metrics: DcSctpMetrics) -> Self {
        Self {
            has_value: true,
            tx_packets_count: metrics.tx_packets_count,
            tx_messages_count: metrics.tx_messages_count,
            rtx_packets_count: metrics.rtx_packets_count,
            rtx_bytes_count: metrics.rtx_bytes_count,
            cwnd_bytes: metrics.cwnd_bytes,
            srtt_ms: metrics.srtt.as_millis().try_into().unwrap_or(u64::MAX),
            unack_data_count: metrics.unack_data_count,
            rx_packets_count: metrics.rx_packets_count,
            rx_messages_count: metrics.rx_messages_count,
            peer_rwnd_bytes: metrics.peer_rwnd_bytes,
            peer_implementation: metrics.peer_implementation.into(),
            uses_message_interleaving: metrics.uses_message_interleaving,
            uses_zero_checksum: metrics.uses_zero_checksum,
            negotiated_maximum_incoming_streams: metrics.negotiated_maximum_incoming_streams,
            negotiated_maximum_outgoing_streams: metrics.negotiated_maximum_outgoing_streams,
        }
    }
}

pub struct DcSctpSocket(Box<dyn DcSctpSocketTrait>);

fn version() -> String {
    crate::version().to_string()
}

fn default_options() -> bridge::Options {
    DcSctpOptions::default().into()
}

fn create_message(stream_id: u16, ppid: u32, payload_size: usize) -> bridge::Message {
    bridge::Message { stream_id, ppid, payload: vec![0; payload_size] }
}

fn new_socket(name: &str, options: &bridge::Options) -> *mut DcSctpSocket {
    let socket = crate::new_socket(name, &options.into());
    let boxed_socket = Box::new(DcSctpSocket(socket));
    Box::into_raw(boxed_socket)
}

unsafe fn delete_socket(socket: *mut DcSctpSocket) {
    if !socket.is_null() {
        // SAFETY: The `socket` pointer must have been obtained from `new_socket` and must not be
        // used after this call.
        unsafe {
            drop(Box::from_raw(socket));
        }
    }
}

fn state(socket: &DcSctpSocket) -> bridge::SocketState {
    match socket.0.state() {
        DcSctpSocketState::Closed => bridge::SocketState::Closed,
        DcSctpSocketState::Connecting => bridge::SocketState::Connecting,
        DcSctpSocketState::Connected => bridge::SocketState::Connected,
        DcSctpSocketState::ShuttingDown => bridge::SocketState::ShuttingDown,
    }
}

fn connect(socket: &mut DcSctpSocket) {
    socket.0.connect();
}

fn shutdown(socket: &mut DcSctpSocket) {
    socket.0.shutdown();
}

fn close(socket: &mut DcSctpSocket) {
    socket.0.close();
}

fn options(socket: &DcSctpSocket) -> bridge::Options {
    socket.0.options().into()
}

fn set_max_message_size(socket: &mut DcSctpSocket, max_message_size: usize) {
    socket.0.set_max_message_size(max_message_size);
}

fn set_stream_priority(socket: &mut DcSctpSocket, stream_id: u16, priority: u16) {
    socket.0.set_stream_priority(StreamId(stream_id), priority);
}

fn get_stream_priority(socket: &mut DcSctpSocket, stream_id: u16) -> u16 {
    socket.0.get_stream_priority(StreamId(stream_id))
}

fn buffered_amount(socket: &DcSctpSocket, stream_id: u16) -> usize {
    socket.0.buffered_amount(StreamId(stream_id))
}

fn buffered_amount_low_threshold(socket: &DcSctpSocket, stream_id: u16) -> usize {
    socket.0.buffered_amount_low_threshold(StreamId(stream_id))
}

fn set_buffered_amount_low_threshold(socket: &mut DcSctpSocket, stream_id: u16, bytes: usize) {
    socket.0.set_buffered_amount_low_threshold(StreamId(stream_id), bytes);
}

fn handle_input(socket: &mut DcSctpSocket, data: &[u8]) {
    socket.0.handle_input(data)
}

fn poll_event(socket: &mut DcSctpSocket) -> bridge::Event {
    socket.0.poll_event().map(Into::into).unwrap_or_default()
}

fn advance_time(socket: &mut DcSctpSocket, ns: u64) {
    socket.0.advance_time(Duration::from_nanos(ns).into())
}

fn poll_timeout(socket: &DcSctpSocket) -> u64 {
    Duration::from(socket.0.poll_timeout()).as_nanos().try_into().unwrap_or(u64::MAX)
}

fn message_ready_count(socket: &DcSctpSocket) -> usize {
    socket.0.messages_ready_count()
}

fn get_next_message(socket: &mut DcSctpSocket) -> bridge::Message {
    match socket.0.get_next_message() {
        Some(msg) => {
            bridge::Message { stream_id: msg.stream_id.0, ppid: msg.ppid.0, payload: msg.payload }
        }
        None => bridge::Message::default(),
    }
}

fn new_send_options() -> bridge::SendOptions {
    bridge::SendOptions {
        unordered: false,
        lifetime_ms: MAX_LIFETIME_MS,
        max_retransmissions: u16::MAX,
        lifecycle_id: 0,
    }
}

fn send(
    socket: &mut DcSctpSocket,
    message: bridge::Message,
    options: &bridge::SendOptions,
) -> bridge::SendStatus {
    let msg = DcSctpMessage::new(StreamId(message.stream_id), PpId(message.ppid), message.payload);
    socket.0.send(msg, &options.into()).into()
}

fn send_many(
    socket: &mut DcSctpSocket,
    messages: Vec<bridge::Message>,
    options: &bridge::SendOptions,
) -> Vec<bridge::SendStatus> {
    let messages = messages
        .into_iter()
        .map(|msg| DcSctpMessage::new(StreamId(msg.stream_id), PpId(msg.ppid), msg.payload))
        .collect();
    socket.0.send_many(messages, &options.into()).into_iter().map(Into::into).collect()
}

fn restore_from_state(socket: &mut DcSctpSocket, state: &bridge::SocketHandoverState) {
    socket.0.restore_from_state(&state.into());
}

fn get_handover_readiness(socket: &DcSctpSocket) -> u32 {
    socket.0.get_handover_readiness().0
}

fn get_handover_readiness_string(socket: &DcSctpSocket) -> String {
    socket.0.get_handover_readiness().to_string()
}

fn get_handover_state_and_close(socket: &mut DcSctpSocket) -> bridge::SocketHandoverState {
    socket.0.get_handover_state_and_close().map(Into::into).unwrap_or_default()
}

fn reset_streams(socket: &mut DcSctpSocket, stream_ids: Vec<u16>) -> bridge::ResetStreamsStatus {
    let stream_ids: Vec<StreamId> = stream_ids.into_iter().map(StreamId).collect();
    socket.0.reset_streams(&stream_ids).into()
}

fn get_metrics(socket: &DcSctpSocket) -> bridge::Metrics {
    socket.0.get_metrics().map(Into::into).unwrap_or_default()
}
