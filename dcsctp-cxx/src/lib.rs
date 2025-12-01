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
