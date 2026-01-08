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
use crate::api::Options;
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
    enum EventType {
        Nothing,
        OnConnected,
        SendPacket,
        Other,
    }

    struct Event {
        event_type: EventType,
        packet: Vec<u8>,
    }

    extern "Rust" {
        type DcSctpSocket;

        fn version() -> String;
        fn new_socket() -> *mut DcSctpSocket;
        unsafe fn delete_socket(socket: *mut DcSctpSocket);
        fn state(socket: &DcSctpSocket) -> SocketState;
        fn connect(socket: &mut DcSctpSocket);
        fn handle_input(socket: &mut DcSctpSocket, data: &[u8]);
        fn poll_event(socket: &mut DcSctpSocket) -> Event;
        fn advance_time(socket: &mut DcSctpSocket, ns: u64);
        fn poll_timeout(socket: &DcSctpSocket) -> u64;
    }
}

pub struct DcSctpSocket(Box<dyn DcSctpSocketTrait>);

fn version() -> String {
    crate::version().to_string()
}

fn new_socket() -> *mut DcSctpSocket {
    let options = Options::default();
    let socket = crate::new_socket("cxx-socket", &options);
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

fn handle_input(socket: &mut DcSctpSocket, data: &[u8]) {
    socket.0.handle_input(data)
}

fn poll_event(socket: &mut DcSctpSocket) -> bridge::Event {
    match socket.0.poll_event() {
        Some(DcSctpSocketEvent::SendPacket(p)) => {
            bridge::Event { event_type: bridge::EventType::SendPacket, packet: p }
        }
        Some(DcSctpSocketEvent::OnConnected()) => {
            bridge::Event { event_type: bridge::EventType::OnConnected, packet: Vec::new() }
        }
        Some(_) => bridge::Event { event_type: bridge::EventType::Other, packet: Vec::new() },
        None => bridge::Event { event_type: bridge::EventType::Nothing, packet: Vec::new() },
    }
}

fn advance_time(socket: &mut DcSctpSocket, ns: u64) {
    socket.0.advance_time(Duration::from_nanos(ns).into())
}

fn poll_timeout(socket: &DcSctpSocket) -> u64 {
    Duration::from(socket.0.poll_timeout()).as_nanos().try_into().unwrap_or(u64::MAX)
}
