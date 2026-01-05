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
use crate::api::Options as DcSctpOptions;
use crate::api::SocketEvent as DcSctpSocketEvent;
use crate::api::SocketState as DcSctpSocketState;
use std::time::Duration;

#[cxx::bridge(namespace = "dcsctp_cxx")]
mod bridge {
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

    struct Event {
        event_type: EventType,
        error_kind: ErrorKind,
        stream_id: u16,
        lifecycle_id: u64,
        error_reason: String,
        packet: Vec<u8>,
        stream_ids: Vec<u16>,
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
        fn new_socket(name: &str, options: &Options) -> *mut DcSctpSocket;
        unsafe fn delete_socket(socket: *mut DcSctpSocket);
        fn state(socket: &DcSctpSocket) -> SocketState;
        fn connect(socket: &mut DcSctpSocket);
        fn options(socket: &DcSctpSocket) -> Options;
        fn handle_input(socket: &mut DcSctpSocket, data: &[u8]);
        fn poll_event(socket: &mut DcSctpSocket) -> Event;
        fn advance_time(socket: &mut DcSctpSocket, ns: u64);
        fn poll_timeout(socket: &DcSctpSocket) -> u64;
    }
}

pub const fn to_saturating_u64(d: Duration) -> u64 {
    let nanos = d.as_nanos();
    if nanos > u64::MAX as u128 {
        u64::MAX
    } else {
        nanos as u64
    }
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

pub struct DcSctpSocket(Box<dyn DcSctpSocketTrait>);

fn version() -> String {
    crate::version().to_string()
}

fn default_options() -> bridge::Options {
    DcSctpOptions::default().into()
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
        drop(Box::from_raw(socket));
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

fn options(socket: &DcSctpSocket) -> bridge::Options {
    socket.0.options().into()
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
