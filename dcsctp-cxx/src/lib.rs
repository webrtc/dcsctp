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

use dcsctp::api::DcSctpSocket as DcSctpSocketTrait;
use dcsctp::api::Options;
use dcsctp::api::SocketState as DcSctpSocketState;
use std::time::Instant;

#[cxx::bridge(namespace = "dcsctp_cxx")]
mod ffi {
    #[derive(Debug)]
    enum SocketState {
        Closed,
        Connecting,
        Connected,
        ShuttingDown,
    }

    extern "Rust" {
        type DcSctpSocket;

        fn version() -> String;
        fn new_socket() -> *mut DcSctpSocket;
        unsafe fn delete_socket(socket: *mut DcSctpSocket);
        fn state(socket: &DcSctpSocket) -> SocketState;
    }
}

pub struct DcSctpSocket(Box<dyn DcSctpSocketTrait>);

fn version() -> String {
    dcsctp::version().to_string()
}

fn new_socket() -> *mut DcSctpSocket {
    let options = Options::default();
    let socket = dcsctp::new_socket("cxx-socket", Instant::now(), &options);
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

fn state(socket: &DcSctpSocket) -> ffi::SocketState {
    match socket.0.state() {
        DcSctpSocketState::Closed => ffi::SocketState::Closed,
        DcSctpSocketState::Connecting => ffi::SocketState::Connecting,
        DcSctpSocketState::Connected => ffi::SocketState::Connected,
        DcSctpSocketState::ShuttingDown => ffi::SocketState::ShuttingDown,
    }
}
