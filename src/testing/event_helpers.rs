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

use crate::api::LifecycleId;
use crate::api::SocketEvent;

#[macro_export]
macro_rules! expect_event_0 {
    ($event:expr, $event_type:ident) => {
        match $event {
            None => panic!("No event emitted"),
            Some(e) => match (e) {
                SocketEvent::$event_type() => {}
                _ => panic!("Expected $event_type, got {:?}", e),
            },
        }
    };
}

#[macro_export]
macro_rules! expect_event_1 {
    ($event:expr, $event_type:ident) => {
        match $event {
            None => panic!("No event emitted"),
            Some(e) => match (e) {
                SocketEvent::$event_type(d) => d,
                _ => panic!("Expected $event_type, got {:?}", e),
            },
        }
    };
}

macro_rules! expect_sent_packet {
    ($event:expr) => {
        crate::expect_event_1!($event, SendPacket)
    };
}

macro_rules! expect_on_connected {
    ($event:expr) => {
        crate::expect_event_0!($event, OnConnected)
    };
}

macro_rules! expect_on_closed {
    ($event:expr) => {
        crate::expect_event_0!($event, OnClosed)
    };
}

macro_rules! expect_buffered_amount_low {
    ($event:expr) => {
        crate::expect_event_1!($event, OnBufferedAmountLow)
    };
}

macro_rules! expect_total_buffered_amount_low {
    ($event:expr) => {
        crate::expect_event_0!($event, OnTotalBufferedAmountLow)
    };
}

macro_rules! expect_on_lifecycle_message_fully_sent {
    ($event:expr) => {
        crate::expect_event_1!($event, OnLifecycleMessageFullySent)
    };
}

macro_rules! expect_on_lifecycle_message_expired {
    ($event:expr) => {
        crate::expect_event_1!($event, OnLifecycleMessageExpired)
    };
}

macro_rules! expect_on_lifecycle_message_maybe_sent {
    ($event:expr) => {
        crate::expect_event_1!($event, OnLifecycleMessageMaybeExpired)
    };
}

macro_rules! expect_on_lifecycle_message_delivered {
    ($event:expr) => {
        crate::expect_event_1!($event, OnLifecycleMessageDelivered)
    };
}

macro_rules! expect_on_lifecycle_end {
    ($event:expr) => {
        crate::expect_event_1!($event, OnLifecycleEnd)
    };
}

macro_rules! expect_on_error {
    ($event:expr) => {
        match $event {
            None => panic!("No event emitted"),
            Some(e) => match (e) {
                SocketEvent::OnError(kind, _) => kind,
                _ => panic!("Expected OnError, got {:?}", e),
            },
        }
    };
}

macro_rules! expect_on_aborted {
    ($event:expr) => {
        match $event {
            None => panic!("No event emitted"),
            Some(e) => match (e) {
                SocketEvent::OnAborted(kind, _) => kind,
                _ => panic!("Expected OnAborted, got {:?}", e),
            },
        }
    };
}

macro_rules! expect_on_streams_reset_performed {
    ($event:expr) => {
        crate::expect_event_1!($event, OnStreamsResetPerformed)
    };
}

macro_rules! expect_on_incoming_stream_reset {
    ($event:expr) => {
        crate::expect_event_1!($event, OnIncomingStreamReset)
    };
}

macro_rules! expect_no_event {
    ($event:expr) => {
        match $event {
            None => {}
            Some(e) => panic!("Expected no event, got {:?}", e),
        }
    };
}

pub fn is_lifecycle_message_delivered(lid: LifecycleId) -> impl Fn(&SocketEvent) -> bool {
    move |e| match e {
        SocketEvent::OnLifecycleMessageDelivered(l) => *l == lid,
        _ => false,
    }
}

pub fn is_lifecycle_message_maybe_expired(lid: LifecycleId) -> impl Fn(&SocketEvent) -> bool {
    move |e| match e {
        SocketEvent::OnLifecycleMessageMaybeExpired(l) => *l == lid,
        _ => false,
    }
}

pub fn is_lifecycle_message_expired(lid: LifecycleId) -> impl Fn(&SocketEvent) -> bool {
    move |e| match e {
        SocketEvent::OnLifecycleMessageExpired(l) => *l == lid,
        _ => false,
    }
}

pub fn is_lifecycle_end(lid: LifecycleId) -> impl Fn(&SocketEvent) -> bool {
    move |e| match e {
        SocketEvent::OnLifecycleEnd(l) => *l == lid,
        _ => false,
    }
}

pub(crate) use expect_buffered_amount_low;
pub(crate) use expect_no_event;
pub(crate) use expect_on_aborted;
pub(crate) use expect_on_closed;
pub(crate) use expect_on_connected;
pub(crate) use expect_on_error;
pub(crate) use expect_on_incoming_stream_reset;
pub(crate) use expect_on_lifecycle_end;
#[allow(unused_imports)]
pub(crate) use expect_on_lifecycle_message_delivered;
pub(crate) use expect_on_lifecycle_message_expired;
pub(crate) use expect_on_lifecycle_message_fully_sent;
#[allow(unused_imports)]
pub(crate) use expect_on_lifecycle_message_maybe_sent;
pub(crate) use expect_on_streams_reset_performed;
pub(crate) use expect_sent_packet;
pub(crate) use expect_total_buffered_amount_low;
