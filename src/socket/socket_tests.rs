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

#[cfg(test)]
mod tests {
    use crate::api::DcSctpSocket;
    use crate::api::ErrorKind;
    use crate::api::LifecycleId;
    use crate::api::Message;
    use crate::api::Options;
    use crate::api::PpId;
    use crate::api::ResetStreamsStatus;
    use crate::api::SctpImplementation;
    use crate::api::SendOptions;
    use crate::api::SendStatus;
    use crate::api::SocketEvent;
    use crate::api::SocketState;
    use crate::api::SocketTime;
    use crate::api::StreamId;
    use crate::api::ZERO_CHECKSUM_ALTERNATE_ERROR_DETECTION_METHOD_LOWER_LAYER_DTLS;
    use crate::api::ZERO_CHECKSUM_ALTERNATE_ERROR_DETECTION_METHOD_NONE;
    use crate::math::round_down_to_4;
    use crate::packet::chunk::Chunk;
    use crate::packet::data::Data;
    use crate::packet::data_chunk;
    use crate::packet::data_chunk::DataChunk;
    use crate::packet::error_causes::ErrorCause;
    use crate::packet::error_chunk::ErrorChunk;
    use crate::packet::heartbeat_ack_chunk::HeartbeatAckChunk;
    use crate::packet::heartbeat_info_parameter::HeartbeatInfoParameter;
    use crate::packet::heartbeat_request_chunk::HeartbeatRequestChunk;
    use crate::packet::init_ack_chunk::InitAckChunk;
    use crate::packet::parameter::Parameter;
    use crate::packet::sctp_packet;
    use crate::packet::sctp_packet::SctpPacket;
    use crate::packet::sctp_packet::SctpPacketBuilder;
    use crate::packet::unknown_chunk::UnknownChunk;
    use crate::packet::unrecognized_chunk_error_cause::UnrecognizedChunkErrorCause;
    use crate::rx::reassembly_queue::HIGH_WATERMARK_LIMIT;
    use crate::socket::Socket;
    use crate::testing::event_helpers::expect_buffered_amount_low;
    use crate::testing::event_helpers::expect_no_event;
    use crate::testing::event_helpers::expect_on_aborted;
    use crate::testing::event_helpers::expect_on_closed;
    use crate::testing::event_helpers::expect_on_connected;
    use crate::testing::event_helpers::expect_on_error;
    use crate::testing::event_helpers::expect_on_incoming_stream_reset;
    use crate::testing::event_helpers::expect_on_lifecycle_end;
    use crate::testing::event_helpers::expect_on_streams_reset_performed;
    use crate::testing::event_helpers::expect_sent_packet;
    use crate::testing::event_helpers::expect_total_buffered_amount_low;
    use crate::testing::event_helpers::is_lifecycle_end;
    use crate::testing::event_helpers::is_lifecycle_message_delivered;
    use crate::testing::event_helpers::is_lifecycle_message_expired;
    use crate::testing::event_helpers::is_lifecycle_message_maybe_expired;
    use crate::types::Ssn;
    use crate::types::StreamKey;
    use core::panic;
    use std::cmp::min;
    use std::collections::HashSet;
    use std::collections::VecDeque;
    use std::time::Duration;

    fn unordered_eq<T>(a: &[T], b: &[T]) -> bool
    where
        T: Eq + std::hash::Hash,
    {
        let a: HashSet<_> = a.iter().collect();
        let b: HashSet<_> = b.iter().collect();

        a == b
    }

    fn default_options() -> Options {
        Options {
            default_stream_buffered_amount_low_threshold: 1_800_000,
            rto_min: Duration::from_millis(100),
            rto_initial: Duration::from_millis(100),
            rto_max: Duration::from_millis(100),
            delayed_ack_max_timeout: Duration::from_millis(10),
            heartbeat_interval: Duration::ZERO,
            ..Options::default()
        }
    }

    fn exchange_packets(
        socket_a: &mut Socket<'_>,
        socket_z: &mut Socket<'_>,
    ) -> (VecDeque<SocketEvent>, VecDeque<SocketEvent>) {
        let mut events_a: VecDeque<SocketEvent> = VecDeque::new();
        let mut events_z: VecDeque<SocketEvent> = VecDeque::new();
        loop {
            let mut again = false;
            if let Some(e) = socket_a.poll_event() {
                if let SocketEvent::SendPacket(ref send) = e {
                    socket_z.handle_input(send);
                } else {
                    events_a.push_back(e);
                }
                again = true;
            }
            if let Some(e) = socket_z.poll_event() {
                if let SocketEvent::SendPacket(ref send) = e {
                    socket_a.handle_input(send);
                } else {
                    events_z.push_back(e);
                }
                again = true;
            }
            if !again {
                let timeout = min(socket_a.poll_timeout(), socket_z.poll_timeout());
                if timeout != SocketTime::infinite_future() {
                    socket_a.advance_time(timeout);
                    socket_z.advance_time(timeout);
                    again = true;
                }
            }

            if !again {
                return (events_a, events_z);
            }
        }
    }

    fn connect_sockets(socket_a: &mut Socket<'_>, socket_z: &mut Socket<'_>) {
        socket_a.connect();
        // A -> INIT -> Z
        socket_z.handle_input(&expect_sent_packet!(socket_a.poll_event()));
        // A <- INIT_ACK <- Z
        socket_a.handle_input(&expect_sent_packet!(socket_z.poll_event()));
        // A -> COOKIE_ECHO -> Z
        socket_z.handle_input(&expect_sent_packet!(socket_a.poll_event()));
        expect_on_connected!(socket_z.poll_event());
        // A <- COOKIE_ACK <- Z
        socket_a.handle_input(&expect_sent_packet!(socket_z.poll_event()));
        expect_on_connected!(socket_a.poll_event());
        expect_no_event!(socket_a.poll_event());
        expect_no_event!(socket_z.poll_event());

        assert_eq!(socket_a.state(), SocketState::Connected);
        assert_eq!(socket_z.state(), SocketState::Connected);
    }

    fn handover_socket(from_socket: &mut Socket<'_>, to_socket: &mut Socket<'_>) {
        assert!(matches!(to_socket.state(), SocketState::Closed));
        expect_no_event!(from_socket.poll_event());
        assert!(from_socket.get_handover_readiness().is_ready());
        let is_closed = matches!(from_socket.state(), SocketState::Closed);

        let Some(handover_state) = from_socket.get_handover_state_and_close() else {
            panic!();
        };

        if !is_closed {
            expect_on_closed!(from_socket.poll_event());
        }
        expect_no_event!(from_socket.poll_event());

        to_socket.restore_from_state(&handover_state);
        if !is_closed {
            expect_on_connected!(to_socket.poll_event());
        }
        expect_no_event!(to_socket.poll_event());
    }

    #[test]
    fn establish_connection() {
        let options = default_options();
        let mut socket_a = Socket::new("A", &options);
        let mut socket_z = Socket::new("Z", &options);

        socket_a.connect();
        // A -> INIT -> Z
        socket_z.handle_input(&expect_sent_packet!(socket_a.poll_event()));
        // A <- INIT_ACK <- Z
        socket_a.handle_input(&expect_sent_packet!(socket_z.poll_event()));
        // A -> COOKIE_ECHO -> Z
        socket_z.handle_input(&expect_sent_packet!(socket_a.poll_event()));
        expect_on_connected!(socket_z.poll_event());
        // A <- COOKIE_ACK <- Z
        socket_a.handle_input(&expect_sent_packet!(socket_z.poll_event()));
        expect_on_connected!(socket_a.poll_event());
        expect_no_event!(socket_a.poll_event());
        expect_no_event!(socket_z.poll_event());

        assert_eq!(socket_a.state(), SocketState::Connected);
        assert_eq!(socket_z.state(), SocketState::Connected);
    }

    #[test]
    fn send_many_api_method() {
        let options = default_options();
        let mut socket_a = Socket::new("A", &options);
        let mut socket_z = Socket::new("Z", &options);

        connect_sockets(&mut socket_a, &mut socket_z);

        let messages = vec![
            Message::new(StreamId(1), PpId(1), b"hello".to_vec()),
            Message::new(StreamId(2), PpId(2), b"world".to_vec()),
        ];
        let statuses = socket_a.send_many(messages, &SendOptions::default());
        assert_eq!(statuses, vec![SendStatus::Success, SendStatus::Success]);

        exchange_packets(&mut socket_a, &mut socket_z);

        let msg1 = socket_z.get_next_message().unwrap();
        assert_eq!(msg1.payload, b"hello");
        assert_eq!(msg1.stream_id, StreamId(1));

        let msg2 = socket_z.get_next_message().unwrap();
        assert_eq!(msg2.payload, b"world");
        assert_eq!(msg2.stream_id, StreamId(2));
    }

    #[test]
    fn establish_connection_with_setup_collision() {
        let options = default_options();
        let mut socket_a = Socket::new("A", &options);
        let mut socket_z = Socket::new("Z", &options);
        socket_a.connect();
        socket_z.connect();

        exchange_packets(&mut socket_a, &mut socket_z);

        assert_eq!(socket_a.state(), SocketState::Connected);
        assert_eq!(socket_z.state(), SocketState::Connected);
    }

    #[test]
    fn shutting_down_while_establishing_connection() {
        let options = default_options();
        let mut socket_a = Socket::new("A", &options);
        let mut socket_z = Socket::new("Z", &options);
        socket_a.connect();

        // A -> INIT -> Z
        socket_z.handle_input(&expect_sent_packet!(socket_a.poll_event()));
        // A <- INIT_ACK <- Z
        socket_a.handle_input(&expect_sent_packet!(socket_z.poll_event()));
        // A -> COOKIE_ECHO -> Z
        socket_z.handle_input(&expect_sent_packet!(socket_a.poll_event()));
        expect_on_connected!(socket_z.poll_event());
        // A /lost/ <- COOKIE_ACK <- Z
        expect_sent_packet!(socket_z.poll_event());

        // As Socket A has received INIT_ACK, it has a TCB and is connected, while Socket Z needs to
        // receive COOKIE_ECHO to get there. Socket A still has timers running at this point.
        assert_eq!(socket_a.state(), SocketState::Connecting);
        assert_eq!(socket_z.state(), SocketState::Connected);

        // Socket A is shutting down, which should make it stop those timers.
        socket_a.shutdown();

        // A -> SHUTDOWN -> Z
        socket_z.handle_input(&expect_sent_packet!(socket_a.poll_event()));
        // A <- SHUTDOWN_ACK <- Z
        socket_a.handle_input(&expect_sent_packet!(socket_z.poll_event()));
        // A -> SHUTDOWN_COMPLETE -> Z
        socket_z.handle_input(&expect_sent_packet!(socket_a.poll_event()));

        expect_on_closed!(socket_a.poll_event());
        expect_on_closed!(socket_z.poll_event());
        expect_no_event!(socket_a.poll_event());
        expect_no_event!(socket_z.poll_event());

        assert_eq!(socket_a.state(), SocketState::Closed);
        assert_eq!(socket_z.state(), SocketState::Closed);
    }

    #[test]
    fn establish_simultaneous_connection() {
        let options = default_options();
        let mut socket_a = Socket::new("A", &options);
        let mut socket_z = Socket::new("Z", &options);

        socket_a.connect();
        // INIT isn't received by Z, as it wasn't ready yet.
        assert!(matches!(socket_a.poll_event().unwrap(), SocketEvent::SendPacket(_)));

        socket_z.connect();

        // A <- INIT <- Z
        socket_a.handle_input(&expect_sent_packet!(socket_z.poll_event()));
        // A -> INIT_ACK -> Z
        socket_z.handle_input(&expect_sent_packet!(socket_a.poll_event()));
        // A <- COOKIE_ECHO <- Z
        socket_a.handle_input(&expect_sent_packet!(socket_z.poll_event()));
        expect_on_connected!(socket_a.poll_event());
        assert_eq!(socket_a.state(), SocketState::Connected);

        // A -> COOKIE_ACK -> Z
        socket_z.handle_input(&expect_sent_packet!(socket_a.poll_event()));
        expect_on_connected!(socket_z.poll_event());
        assert_eq!(socket_z.state(), SocketState::Connected);

        expect_no_event!(socket_a.poll_event());
        expect_no_event!(socket_z.poll_event());
    }

    #[test]
    fn attempt_connect_without_cookie() {
        let options = default_options();
        let mut socket_a = Socket::new("A", &options);
        let mut socket_z = Socket::new("Z", &options);
        socket_a.connect();
        // A -> INIT -> Z
        socket_z.handle_input(&expect_sent_packet!(socket_a.poll_event()));
        // A <- INIT_ACK <- Z
        let packet = &expect_sent_packet!(socket_z.poll_event());
        let Chunk::InitAck(init_ack) =
            SctpPacket::from_bytes(packet, &options).unwrap().chunks.pop().unwrap()
        else {
            unreachable!()
        };

        // Create a new INIT_ACK and filter out the state cookie.
        let parameters = init_ack
            .parameters
            .into_iter()
            .filter(|p| !matches!(p, Parameter::StateCookie(_)))
            .collect::<Vec<_>>();
        let packet = SctpPacketBuilder::new(
            socket_a.verification_tag(),
            options.local_port,
            options.remote_port,
            options.mtu,
        )
        .add(&Chunk::InitAck(InitAckChunk { parameters, ..init_ack }))
        .build();
        socket_a.handle_input(&packet);

        assert!(matches!(
            SctpPacket::from_bytes(&expect_sent_packet!(socket_a.poll_event()), &options)
                .unwrap()
                .chunks[0],
            Chunk::Abort(_)
        ));
        assert_eq!(expect_on_aborted!(socket_a.poll_event()), ErrorKind::ProtocolViolation);
    }

    #[test]
    fn establish_connection_lost_cookie_ack() {
        let options = default_options();
        let mut socket_a = Socket::new("A", &options);
        let mut socket_z = Socket::new("Z", &options);

        socket_a.connect();
        // A -> INIT -> Z
        socket_z.handle_input(&expect_sent_packet!(socket_a.poll_event()));
        // A <- INIT_ACK <- Z
        socket_a.handle_input(&expect_sent_packet!(socket_z.poll_event()));
        // A -> COOKIE_ECHO -> Z
        socket_z.handle_input(&expect_sent_packet!(socket_a.poll_event()));
        expect_on_connected!(socket_z.poll_event());
        // A /lost/<- COOKIE_ACK <- Z
        expect_sent_packet!(socket_z.poll_event());

        assert_eq!(socket_a.state(), SocketState::Connecting);
        assert_eq!(socket_z.state(), SocketState::Connected);

        let expected_timeout = SocketTime::from(options.t1_cookie_timeout);
        assert_eq!(socket_a.poll_timeout(), expected_timeout);

        // This will make A re-send the COOKIE_ECHO
        socket_a.advance_time(expected_timeout);

        // A -> COOKIE_ECHO -> Z
        socket_z.handle_input(&expect_sent_packet!(socket_a.poll_event()));
        // A <- COOKIE_ACK <- Z
        socket_a.handle_input(&expect_sent_packet!(socket_z.poll_event()));
        expect_on_connected!(socket_a.poll_event());
        assert_eq!(socket_a.state(), SocketState::Connected);

        expect_no_event!(socket_a.poll_event());
        expect_no_event!(socket_z.poll_event());
    }

    #[test]
    fn resend_init_and_establish_connection() {
        let options = default_options();
        let mut socket_a = Socket::new("A", &options);
        let mut socket_z = Socket::new("Z", &options);

        socket_a.connect();
        // A -> INIT ->/lost/ Z
        expect_sent_packet!(socket_a.poll_event());

        let expected_timeout = SocketTime::from(options.t1_init_timeout);
        assert_eq!(socket_a.poll_timeout(), expected_timeout);

        // This will make A re-send the COOKIE_ECHO
        socket_a.advance_time(expected_timeout);

        // A -> INIT -> Z
        socket_z.handle_input(&expect_sent_packet!(socket_a.poll_event()));
        // A <- INIT_ACK <- Z
        socket_a.handle_input(&expect_sent_packet!(socket_z.poll_event()));
        // A -> COOKIE_ECHO -> Z
        socket_z.handle_input(&expect_sent_packet!(socket_a.poll_event()));
        expect_on_connected!(socket_z.poll_event());
        // A <- COOKIE_ACK <- Z
        socket_a.handle_input(&expect_sent_packet!(socket_z.poll_event()));
        expect_on_connected!(socket_a.poll_event());

        assert_eq!(socket_a.state(), SocketState::Connected);
        assert_eq!(socket_z.state(), SocketState::Connected);
        expect_no_event!(socket_a.poll_event());
        expect_no_event!(socket_z.poll_event());
    }

    #[test]
    fn resending_init_too_many_times_aborts() {
        let options = default_options();
        let mut now = SocketTime::zero();
        let mut socket_a = Socket::new("A", &options);

        socket_a.connect();
        // A -> INIT -> / lost/
        expect_sent_packet!(socket_a.poll_event());
        expect_no_event!(socket_a.poll_event());

        for i in 0..options.max_init_retransmits.unwrap() {
            now = now + options.t1_init_timeout * (1 << i);
            socket_a.advance_time(now);
            // A -> INIT -> / lost/
            expect_sent_packet!(socket_a.poll_event());
            expect_no_event!(socket_a.poll_event());
        }

        // Let the last retransmit expire as well.
        now = now + options.t1_init_timeout * (1 << options.max_init_retransmits.unwrap());
        socket_a.advance_time(now);

        assert_eq!(expect_on_aborted!(socket_a.poll_event()), ErrorKind::TooManyRetries);
        expect_no_event!(socket_a.poll_event());
    }

    #[test]
    fn resend_cookie_echo_and_establish_connection() {
        let options = default_options();
        let mut socket_a = Socket::new("A", &options);
        let mut socket_z = Socket::new("Z", &options);

        socket_a.connect();
        // A -> INIT -> Z
        socket_z.handle_input(&expect_sent_packet!(socket_a.poll_event()));
        // A <- INIT_ACK <- Z
        socket_a.handle_input(&expect_sent_packet!(socket_z.poll_event()));
        // A -> COOKIE_ECHO ->/lost/ Z
        expect_sent_packet!(socket_a.poll_event());

        assert_eq!(socket_a.state(), SocketState::Connecting);
        assert_eq!(socket_z.state(), SocketState::Closed);

        let expected_timeout = SocketTime::from(options.t1_cookie_timeout);
        assert_eq!(socket_a.poll_timeout(), expected_timeout);

        // This will make A re-send the COOKIE_ECHO.
        socket_a.advance_time(expected_timeout);

        // A -> COOKIE_ECHO -> Z
        socket_z.handle_input(&expect_sent_packet!(socket_a.poll_event()));
        expect_on_connected!(socket_z.poll_event());
        // A <- COOKIE_ACK <- Z
        socket_a.handle_input(&expect_sent_packet!(socket_z.poll_event()));
        expect_on_connected!(socket_a.poll_event());

        assert_eq!(socket_a.state(), SocketState::Connected);
        assert_eq!(socket_z.state(), SocketState::Connected);
        expect_no_event!(socket_a.poll_event());
        expect_no_event!(socket_z.poll_event());
    }

    #[test]
    fn resending_cookie_echo_too_many_times_aborts() {
        let options = default_options();
        let mut now = SocketTime::zero();
        let mut socket_a = Socket::new("A", &options);
        let mut socket_z = Socket::new("Z", &options);

        socket_a.connect();
        // A -> INIT -> Z
        socket_z.handle_input(&expect_sent_packet!(socket_a.poll_event()));
        // A <- INIT_ACK <- Z
        socket_a.handle_input(&expect_sent_packet!(socket_z.poll_event()));

        // A -> COOKIE_ECHO ->/lost/ Z
        expect_sent_packet!(socket_a.poll_event());
        expect_no_event!(socket_a.poll_event());

        for i in 0..options.max_init_retransmits.unwrap() {
            now = now + options.t1_cookie_timeout * (1 << i);
            socket_a.advance_time(now);
            // A -> COOKIE_ECHO ->/lost/ Z
            expect_sent_packet!(socket_a.poll_event());
            expect_no_event!(socket_a.poll_event());
        }

        // Let the last retransmit expire as well.
        now = now + options.t1_cookie_timeout * (1 << options.max_init_retransmits.unwrap());
        socket_a.advance_time(now);

        assert_eq!(expect_on_aborted!(socket_a.poll_event()), ErrorKind::TooManyRetries);
        expect_no_event!(socket_a.poll_event());
    }

    #[test]
    fn doesnt_send_more_packets_until_cookie_ack_has_been_received() {
        let options = default_options();
        let mut now = SocketTime::zero();
        let mut socket_a = Socket::new("A", &options);
        let mut socket_z = Socket::new("Z", &options);

        let payload_size = options.mtu + 100;
        socket_a.send(
            Message::new(StreamId(1), PpId(53), vec![0; payload_size]),
            &SendOptions::default(),
        );
        socket_a.connect();
        // A -> INIT -> Z
        socket_z.handle_input(&expect_sent_packet!(socket_a.poll_event()));
        // A <- INIT_ACK <- Z
        socket_a.handle_input(&expect_sent_packet!(socket_z.poll_event()));

        // A -> COOKIE_ECHO ->/lost/ Z
        let packet = expect_sent_packet!(socket_a.poll_event());
        let packet = SctpPacket::from_bytes(&packet, &options).unwrap();
        assert!(matches!(packet.chunks[0], Chunk::CookieEcho(_)));
        assert!(matches!(packet.chunks[1], Chunk::Data(_)));
        expect_no_event!(socket_a.poll_event());

        // There are DATA chunks in the sent packet (that was lost), which means that the T3-RTX
        // timer is running, but as the socket is in `CookieEcho` state, it will be T1-COOKIE that
        // drives retransmissions, so when the T3-RTX expires, nothing should be retransmitted.

        assert!(options.rto_initial < options.t1_cookie_timeout);
        now = now + options.rto_initial;
        socket_a.advance_time(now);
        expect_no_event!(socket_a.poll_event());

        // When T1-COOKIE expires, both the COOKIE-ECHO and DATA should be present.
        now = now + options.t1_cookie_timeout - options.rto_initial;
        socket_a.advance_time(now);
        let packet = expect_sent_packet!(socket_a.poll_event());
        let packet = SctpPacket::from_bytes(&packet, &options).unwrap();
        assert!(matches!(packet.chunks[0], Chunk::CookieEcho(_)));
        assert!(matches!(packet.chunks[1], Chunk::Data(_)));
        expect_no_event!(socket_a.poll_event());

        // COOKIE_ECHO has exponential backoff.
        now = now + options.t1_cookie_timeout * 2;
        socket_a.advance_time(now);

        // A -> COOKIE_ECHO -> Z
        socket_z.handle_input(&expect_sent_packet!(socket_a.poll_event()));
        expect_on_connected!(socket_z.poll_event());
        // A <- COOKIE_ACK <- Z
        socket_a.handle_input(&expect_sent_packet!(socket_z.poll_event()));
        expect_on_connected!(socket_a.poll_event());

        exchange_packets(&mut socket_a, &mut socket_z);

        let message = socket_z.get_next_message().unwrap();
        assert_eq!(message.stream_id, StreamId(1));
        assert_eq!(message.payload.len(), payload_size);
        assert!(socket_z.get_next_message().is_none());
    }

    #[test]
    fn shutdown_connection() {
        let mut socket_a = Socket::new("A", &default_options());
        let mut socket_z = Socket::new("Z", &default_options());
        connect_sockets(&mut socket_a, &mut socket_z);

        socket_a.shutdown();

        // A -> SHUTDOWN -> Z
        socket_z.handle_input(&expect_sent_packet!(socket_a.poll_event()));
        // A <- SHUTDOWN_ACK <- Z
        socket_a.handle_input(&expect_sent_packet!(socket_z.poll_event()));
        // A -> SHUTDOWN_COMPLETE -> Z
        socket_z.handle_input(&expect_sent_packet!(socket_a.poll_event()));

        expect_on_closed!(socket_a.poll_event());
        expect_on_closed!(socket_z.poll_event());
        expect_no_event!(socket_a.poll_event());
        expect_no_event!(socket_z.poll_event());

        assert_eq!(socket_a.state(), SocketState::Closed);
        assert_eq!(socket_z.state(), SocketState::Closed);
    }

    #[test]
    fn shutdown_timer_expires_too_many_time_closes_connection() {
        let mut now = SocketTime::zero();
        let options = default_options();
        let mut socket_a = Socket::new("A", &options);
        let mut socket_z = Socket::new("Z", &options);
        connect_sockets(&mut socket_a, &mut socket_z);

        socket_a.shutdown();
        assert_eq!(socket_a.state(), SocketState::ShuttingDown);

        // Drop first SHUTDOWN packet.
        // A -> SHUTDOWN -> /lost/ Z
        expect_sent_packet!(socket_a.poll_event());

        for i in 0..options.max_retransmissions.unwrap() {
            // Dropping every shutdown chunk.
            now = now + options.rto_initial * (1 << i);
            socket_a.advance_time(now);

            let packet = expect_sent_packet!(socket_a.poll_event());
            let packet = SctpPacket::from_bytes(&packet, &options).unwrap();
            assert!(matches!(packet.chunks[0], Chunk::Shutdown(_)));
            expect_no_event!(socket_a.poll_event());
        }

        // The last expiry, makes it abort the connection.
        now = now + options.rto_initial * (1 << options.max_retransmissions.unwrap());
        socket_a.advance_time(now);

        assert_eq!(socket_a.state(), SocketState::Closed);

        assert!(matches!(
            SctpPacket::from_bytes(&expect_sent_packet!(socket_a.poll_event()), &options)
                .unwrap()
                .chunks[0],
            Chunk::Abort(_)
        ));
        assert_eq!(expect_on_aborted!(socket_a.poll_event()), ErrorKind::TooManyRetries);
        expect_no_event!(socket_a.poll_event());
    }

    #[test]
    fn establish_connection_while_sending_data() {
        let options = default_options();
        let mut socket_a = Socket::new("A", &options);
        let mut socket_z = Socket::new("Z", &options);

        socket_a.connect();
        socket_a.send(Message::new(StreamId(1), PpId(53), vec![1, 2]), &SendOptions::default());

        // A -> INIT -> Z
        socket_z.handle_input(&expect_sent_packet!(socket_a.poll_event()));
        // A <- INIT_ACK <- Z
        socket_a.handle_input(&expect_sent_packet!(socket_z.poll_event()));
        // A -> COOKIE_ECHO + DATA -> Z
        socket_z.handle_input(&expect_sent_packet!(socket_a.poll_event()));
        expect_on_connected!(socket_z.poll_event());
        // A <- COOKIE_ACK <- Z
        socket_a.handle_input(&expect_sent_packet!(socket_z.poll_event()));
        expect_on_connected!(socket_a.poll_event());
        assert_eq!(socket_a.state(), SocketState::Connected);
        assert_eq!(socket_z.state(), SocketState::Connected);

        let msg = socket_z.get_next_message().unwrap();
        assert_eq!(msg.stream_id, StreamId(1));
        assert_eq!(msg.payload, vec![1, 2]);

        // A -> SACK -> Z
        socket_a.handle_input(&expect_sent_packet!(socket_z.poll_event()));

        expect_no_event!(socket_a.poll_event());
        expect_no_event!(socket_z.poll_event());
    }

    #[test]
    fn send_message_after_established() {
        let options = default_options();
        let mut socket_a = Socket::new("A", &options);
        let mut socket_z = Socket::new("Z", &options);
        connect_sockets(&mut socket_a, &mut socket_z);

        socket_z.send(Message::new(StreamId(1), PpId(53), vec![1, 2]), &SendOptions::default());
        // A <- DATA <- Z
        socket_a.handle_input(&expect_sent_packet!(socket_z.poll_event()));
        let msg = socket_a.get_next_message().unwrap();
        assert_eq!(msg.stream_id, StreamId(1));
        assert_eq!(msg.payload, vec![1, 2]);

        // A -> SACK -> Z
        socket_z.handle_input(&expect_sent_packet!(socket_a.poll_event()));

        expect_no_event!(socket_a.poll_event());
        expect_no_event!(socket_z.poll_event());
    }

    #[test]
    fn timeout_resends_packet() {
        let options = default_options();
        let mut socket_a = Socket::new("A", &options);
        let mut socket_z = Socket::new("Z", &options);
        connect_sockets(&mut socket_a, &mut socket_z);

        socket_z.send(Message::new(StreamId(1), PpId(53), vec![1, 2]), &SendOptions::default());
        // A /lost/ <- DATA <- Z
        expect_sent_packet!(socket_z.poll_event());
        let expected_timeout = SocketTime::from(options.rto_initial);
        assert_eq!(socket_z.poll_timeout(), expected_timeout);
        socket_z.advance_time(expected_timeout);

        socket_a.handle_input(&expect_sent_packet!(socket_z.poll_event()));
        let msg = socket_a.get_next_message().unwrap();
        assert_eq!(msg.stream_id, StreamId(1));
        assert_eq!(msg.payload, vec![1, 2]);

        // A -> SACK -> Z
        socket_z.handle_input(&expect_sent_packet!(socket_a.poll_event()));

        expect_no_event!(socket_a.poll_event());
        expect_no_event!(socket_z.poll_event());
    }

    #[test]
    fn send_a_lot_of_bytes_missed_second_packet() {
        let options = default_options();
        let mut socket_a = Socket::new("A", &options);
        let mut socket_z = Socket::new("Z", &options);
        connect_sockets(&mut socket_a, &mut socket_z);

        let payload: Vec<u8> = vec![0; 20 * options.mtu];

        socket_z
            .send(Message::new(StreamId(1), PpId(53), payload.clone()), &SendOptions::default());

        // A <- DATA <- Z
        socket_a.handle_input(&expect_sent_packet!(socket_z.poll_event()));
        // A /lost/ <- DATA <- Z
        expect_sent_packet!(socket_z.poll_event());

        exchange_packets(&mut socket_a, &mut socket_z);

        let message = socket_a.get_next_message().unwrap();
        assert_eq!(message.stream_id, StreamId(1));
        assert_eq!(message.payload, payload);
        assert!(socket_a.get_next_message().is_none());
    }

    #[test]
    fn sending_heartbeat_answers_with_ack() {
        let options = default_options();
        let mut socket_a = Socket::new("A", &options);
        let mut socket_z = Socket::new("Z", &options);
        connect_sockets(&mut socket_a, &mut socket_z);

        const HEARTBEAT_PAYLOAD: &[u8; 4] = &[1, 2, 3, 4];
        let packet = SctpPacketBuilder::new(
            socket_a.verification_tag(),
            options.local_port,
            options.remote_port,
            options.mtu,
        )
        .add(&Chunk::HeartbeatRequest(HeartbeatRequestChunk {
            parameters: vec![Parameter::HeartbeatInfo(HeartbeatInfoParameter {
                info: HEARTBEAT_PAYLOAD.to_vec(),
            })],
        }))
        .build();
        socket_a.handle_input(&packet);
        let packet =
            SctpPacket::from_bytes(&expect_sent_packet!(socket_a.poll_event()), &options).unwrap();
        assert_eq!(packet.chunks.len(), 1);
        let Chunk::HeartbeatAck(ack) = &packet.chunks[0] else {
            panic!();
        };
        assert_eq!(ack.parameters.len(), 1);

        let Parameter::HeartbeatInfo(HeartbeatInfoParameter { info }) = &ack.parameters[0] else {
            panic!()
        };
        assert_eq!(info, HEARTBEAT_PAYLOAD);
    }

    #[test]
    fn expect_heartbeat_to_be_sent() {
        let mut options = default_options();
        options.heartbeat_interval = Duration::from_secs(30);

        let mut socket_a = Socket::new("A", &options);
        let mut socket_z = Socket::new("Z", &options);
        connect_sockets(&mut socket_a, &mut socket_z);

        // There should only be the heartbeat timer running.
        let expected_timeout = SocketTime::from(options.heartbeat_interval);
        assert_eq!(socket_a.poll_timeout(), expected_timeout);
        socket_a.advance_time(expected_timeout);
        let request_packet = expect_sent_packet!(socket_a.poll_event());
        let packet = SctpPacket::from_bytes(&request_packet, &options).unwrap();
        assert_eq!(packet.chunks.len(), 1);
        assert!(matches!(packet.chunks[0], Chunk::HeartbeatRequest { .. }));

        // Feed it to Sock-z and expect a HEARTBEAT_ACK that will be propagated back.
        socket_z.handle_input(&request_packet);
        let ack_packet = expect_sent_packet!(socket_z.poll_event());
        let packet = SctpPacket::from_bytes(&ack_packet, &options).unwrap();
        assert_eq!(packet.chunks.len(), 1);
        assert!(matches!(packet.chunks[0], Chunk::HeartbeatAck { .. }));

        socket_a.handle_input(&ack_packet);
    }

    #[test]
    fn expect_heartbeats_not_sent_when_sending_data() {
        let mut options = default_options();
        options.heartbeat_interval = Duration::from_secs(30);

        let mut now = SocketTime::zero();
        let mut socket_a = Socket::new("A", &options);
        let mut socket_z = Socket::new("Z", &options);
        connect_sockets(&mut socket_a, &mut socket_z);

        // Verify that the heartbeat timer is restarted when sending any data.
        let original_heartbeat_timeout = now + options.heartbeat_interval;
        now = now + Duration::from_secs(20);
        let restarted_heartbeat_timeout = now + options.heartbeat_interval;

        socket_a.advance_time(now);
        socket_z.advance_time(now);

        socket_a.send(Message::new(StreamId(1), PpId(53), vec![1, 2]), &SendOptions::default());

        // A -> DATA -> Z
        socket_z.handle_input(&expect_sent_packet!(socket_a.poll_event()));
        assert!(socket_z.get_next_message().is_some());
        // A <- SACK <- Z
        socket_a.handle_input(&expect_sent_packet!(socket_z.poll_event()));

        // Verify that the heartbeat timer was restarted by the sent DATA.
        socket_a.advance_time(original_heartbeat_timeout);
        expect_no_event!(socket_a.poll_event());

        socket_a.advance_time(restarted_heartbeat_timeout);
        let request_packet = expect_sent_packet!(socket_a.poll_event());
        let packet = SctpPacket::from_bytes(&request_packet, &options).unwrap();
        assert_eq!(packet.chunks.len(), 1);
        assert!(matches!(packet.chunks[0], Chunk::HeartbeatRequest { .. }));
    }

    #[test]
    fn close_connection_after_first_lost_heartbeat() {
        let mut options = default_options();
        options.heartbeat_interval = Duration::from_secs(30);
        options.max_retransmissions = Some(0);
        let mut now = SocketTime::zero();
        let mut socket_a = Socket::new("A", &options);
        let mut socket_z = Socket::new("Z", &options);
        connect_sockets(&mut socket_a, &mut socket_z);

        // Dropping heartbeat
        now = now + options.heartbeat_interval;
        socket_a.advance_time(now);
        let hb_packet = expect_sent_packet!(socket_a.poll_event());
        let hb_packet = SctpPacket::from_bytes(&hb_packet, &options).unwrap();
        assert!(matches!(hb_packet.chunks[0], Chunk::HeartbeatRequest(_)));

        // Letting the heartbeat expire
        now = now + options.rto_initial;
        socket_a.advance_time(now);

        let abort_packet = expect_sent_packet!(socket_a.poll_event());
        let abort_packet = SctpPacket::from_bytes(&abort_packet, &options).unwrap();
        assert!(matches!(abort_packet.chunks[0], Chunk::Abort(_)));

        assert_eq!(expect_on_aborted!(socket_a.poll_event()), ErrorKind::TooManyRetries);
        expect_no_event!(socket_a.poll_event());
    }

    #[test]
    fn close_connection_after_second_lost_heartbeat() {
        let mut options = default_options();
        options.heartbeat_interval = Duration::from_secs(30);
        options.max_retransmissions = Some(1);
        let mut now = SocketTime::zero();
        let mut socket_a = Socket::new("A", &options);
        let mut socket_z = Socket::new("Z", &options);
        connect_sockets(&mut socket_a, &mut socket_z);

        // Dropping heartbeat
        now = now + options.heartbeat_interval;
        socket_a.advance_time(now);
        let hb_packet = expect_sent_packet!(socket_a.poll_event());
        let hb_packet = SctpPacket::from_bytes(&hb_packet, &options).unwrap();
        assert!(matches!(hb_packet.chunks[0], Chunk::HeartbeatRequest(_)));

        // Letting the heartbeat expire
        now = now + options.rto_initial;
        socket_a.advance_time(now);

        // Dropping second heartbeat
        now = now + options.heartbeat_interval - options.rto_initial;
        socket_a.advance_time(now);
        let hb_packet = expect_sent_packet!(socket_a.poll_event());
        let hb_packet = SctpPacket::from_bytes(&hb_packet, &options).unwrap();
        assert!(matches!(hb_packet.chunks[0], Chunk::HeartbeatRequest(_)));

        // Letting the heartbeat expire
        now = now + options.rto_initial;
        socket_a.advance_time(now);

        let abort_packet = expect_sent_packet!(socket_a.poll_event());
        let abort_packet = SctpPacket::from_bytes(&abort_packet, &options).unwrap();
        assert!(matches!(abort_packet.chunks[0], Chunk::Abort(_)));

        assert_eq!(expect_on_aborted!(socket_a.poll_event()), ErrorKind::TooManyRetries);
        expect_no_event!(socket_a.poll_event());
    }

    #[test]
    fn close_connection_after_too_many_lost_heartbeats() {
        let mut options = default_options();
        options.heartbeat_interval = Duration::from_secs(30);
        options.max_retransmissions = Some(10);
        let mut now = SocketTime::zero();
        let mut socket_a = Socket::new("A", &options);
        let mut socket_z = Socket::new("Z", &options);
        connect_sockets(&mut socket_a, &mut socket_z);

        // Force-close socket Z so that it doesn't interfere from now on.
        socket_z.close();

        let mut time_to_next_heartbeat = options.heartbeat_interval;
        for _ in 0..options.max_retransmissions.unwrap() {
            now = now + time_to_next_heartbeat;
            socket_a.advance_time(now);

            // Dropping every heartbeat.
            let hb_packet = expect_sent_packet!(socket_a.poll_event());
            let hb_packet = SctpPacket::from_bytes(&hb_packet, &options).unwrap();
            assert!(matches!(hb_packet.chunks[0], Chunk::HeartbeatRequest(_)));

            // Letting the heartbeat expire
            now = now + Duration::from_secs(1);
            socket_a.advance_time(now);

            time_to_next_heartbeat = options.heartbeat_interval - Duration::from_secs(1);
        }

        // Letting HEARTBEAT interval timer expire - sending...
        now = now + options.heartbeat_interval;
        socket_a.advance_time(now);

        // Last heartbeat
        let hb_packet = expect_sent_packet!(socket_a.poll_event());
        let hb_packet = SctpPacket::from_bytes(&hb_packet, &options).unwrap();
        assert!(matches!(hb_packet.chunks[0], Chunk::HeartbeatRequest(_)));

        now = now + Duration::from_secs(1);
        socket_a.advance_time(now);

        let abort_packet = expect_sent_packet!(socket_a.poll_event());
        let abort_packet = SctpPacket::from_bytes(&abort_packet, &options).unwrap();
        assert!(matches!(abort_packet.chunks[0], Chunk::Abort(_)));

        assert_eq!(expect_on_aborted!(socket_a.poll_event()), ErrorKind::TooManyRetries);
    }

    #[test]
    fn recovers_after_a_successful_ack() {
        let mut options = default_options();
        options.heartbeat_interval = Duration::from_secs(30);
        options.max_retransmissions = Some(10);
        let mut now = SocketTime::zero();
        let mut socket_a = Socket::new("A", &options);
        let mut socket_z = Socket::new("Z", &options);
        connect_sockets(&mut socket_a, &mut socket_z);

        // Force-close socket Z so that it doesn't interfere from now on.
        socket_z.close();

        let mut time_to_next_heartbeat = options.heartbeat_interval;
        for _ in 0..options.max_retransmissions.unwrap() - 1 {
            now = now + time_to_next_heartbeat;
            socket_a.advance_time(now);

            // Dropping every heartbeat.
            let hb_packet = expect_sent_packet!(socket_a.poll_event());
            let hb_packet = SctpPacket::from_bytes(&hb_packet, &options).unwrap();
            assert!(matches!(hb_packet.chunks[0], Chunk::HeartbeatRequest(_)));

            // Letting the heartbeat expire
            now = now + Duration::from_secs(1);
            socket_a.advance_time(now);

            time_to_next_heartbeat = options.heartbeat_interval - Duration::from_secs(1);
        }

        // Letting HEARTBEAT interval timer expire - sending...
        now = now + options.heartbeat_interval;
        socket_a.advance_time(now);

        // Last heartbeat
        let hb_packet = expect_sent_packet!(socket_a.poll_event());
        let mut hb_packet = SctpPacket::from_bytes(&hb_packet, &options).unwrap();
        let Some(Chunk::HeartbeatRequest(req)) = hb_packet.chunks.pop() else {
            panic!();
        };

        // Ack the very last request.
        let ack_packet = SctpPacketBuilder::new(
            socket_a.verification_tag(),
            options.local_port,
            options.remote_port,
            options.mtu,
        )
        .add(&Chunk::HeartbeatAck(HeartbeatAckChunk { parameters: req.parameters }))
        .build();
        socket_a.handle_input(&ack_packet);

        // Should suffice as exceeding RTO - which will not fire.
        now = now + Duration::from_secs(1);
        socket_a.advance_time(now);
        expect_no_event!(socket_a.poll_event());

        // Verify that we get new heartbeats again.
        now = now + time_to_next_heartbeat;
        socket_a.advance_time(now);

        let hb_packet = expect_sent_packet!(socket_a.poll_event());
        let hb_packet = SctpPacket::from_bytes(&hb_packet, &options).unwrap();
        assert!(matches!(hb_packet.chunks[0], Chunk::HeartbeatRequest(_)));
    }

    #[test]
    fn error_counter_is_reset_on_heartbeat_ack() {
        let mut options = default_options();
        options.heartbeat_interval = Duration::from_secs(30);
        options.max_retransmissions = Some(1);
        let mut now = SocketTime::zero();
        let mut socket_a = Socket::new("A", &options);
        let mut socket_z = Socket::new("Z", &options);
        connect_sockets(&mut socket_a, &mut socket_z);

        // Drop first heartbeat.
        now = now + options.heartbeat_interval;
        socket_a.advance_time(now);

        let hb_packet = expect_sent_packet!(socket_a.poll_event());
        assert!(matches!(
            SctpPacket::from_bytes(&hb_packet, &options).unwrap().chunks[0],
            Chunk::HeartbeatRequest(_)
        ));

        now = now + options.rto_initial;
        socket_a.advance_time(now);

        // Ack second heartbeat. This will clear the TX error counter.
        now = now + options.heartbeat_interval - options.rto_initial;
        socket_a.advance_time(now);

        let hb_packet = expect_sent_packet!(socket_a.poll_event());
        let mut hb_packet = SctpPacket::from_bytes(&hb_packet, &options).unwrap();
        let Some(Chunk::HeartbeatRequest(req)) = hb_packet.chunks.pop() else {
            panic!();
        };
        socket_a.handle_input(
            &SctpPacketBuilder::new(
                socket_a.verification_tag(),
                options.local_port,
                options.remote_port,
                options.mtu,
            )
            .add(&Chunk::HeartbeatAck(HeartbeatAckChunk { parameters: req.parameters }))
            .build(),
        );

        // Drop third heartbeat. As it's recovered on previous ack, this is okey.
        now = now + options.heartbeat_interval;
        socket_a.advance_time(now);

        let hb_packet = expect_sent_packet!(socket_a.poll_event());
        assert!(matches!(
            SctpPacket::from_bytes(&hb_packet, &options).unwrap().chunks[0],
            Chunk::HeartbeatRequest(_)
        ));

        now = now + options.rto_initial;
        socket_a.advance_time(now);

        // The socket should not abort.
        expect_no_event!(socket_a.poll_event());
    }

    #[test]
    fn reset_stream() {
        let options = default_options();

        let mut socket_a = Socket::new("A", &options);
        let mut socket_z = Socket::new("Z", &options);
        connect_sockets(&mut socket_a, &mut socket_z);

        socket_a.send(Message::new(StreamId(1), PpId(53), vec![1, 2]), &SendOptions::default());

        // A -> DATA -> Z
        socket_z.handle_input(&expect_sent_packet!(socket_a.poll_event()));
        assert!(socket_z.get_next_message().is_some());
        // A <- SACK <- Z
        socket_a.handle_input(&expect_sent_packet!(socket_z.poll_event()));

        // Reset the outgoing stream. This will directly send a RE-CONFIG.
        assert_eq!(socket_a.reset_streams(&[StreamId(1)]), ResetStreamsStatus::Performed);

        // Receiving the packet will trigger an event, indicating that A has reset its stream. It
        // will also send a RE-CONFIG with a response.
        expect_no_event!(socket_z.poll_event());
        // A -> RECONFIG -> Z
        socket_z.handle_input(&expect_sent_packet!(socket_a.poll_event()));
        let streams = expect_on_incoming_stream_reset!(socket_z.poll_event());
        assert_eq!(streams, &[StreamId(1)]);

        // Receiving a response will trigger a callback. Streams are now reset.
        expect_no_event!(socket_a.poll_event());
        // A <- RECONFIG <- Z
        socket_a.handle_input(&expect_sent_packet!(socket_z.poll_event()));
        let streams = expect_on_streams_reset_performed!(socket_a.poll_event());
        assert_eq!(streams, &[StreamId(1)]);
        expect_no_event!(socket_z.poll_event());
    }

    #[test]
    fn send_reset_stream_when_streams_ready() {
        let options = Options { cwnd_mtus_initial: 1, ..default_options() };

        let mut socket_a = Socket::new("A", &options);
        let mut socket_z = Socket::new("Z", &options);
        connect_sockets(&mut socket_a, &mut socket_z);

        let ordered = SendOptions { unordered: false, ..Default::default() };

        socket_a.send(Message::new(StreamId(1), PpId(51), vec![0; 3000]), &ordered);

        socket_a.reset_streams(&[StreamId(1)]);

        socket_a.send(Message::new(StreamId(1), PpId(53), vec![0; 100]), &ordered);

        exchange_packets(&mut socket_a, &mut socket_z);

        assert_eq!(socket_z.get_next_message().unwrap().ppid, PpId(51));
        assert_eq!(socket_z.get_next_message().unwrap().ppid, PpId(53));
        assert!(socket_z.get_next_message().is_none());
    }

    #[test]
    fn reset_stream_will_make_chunks_start_at_zero_ssn() {
        let options = default_options();

        let mut socket_a = Socket::new("A", &options);
        let mut socket_z = Socket::new("Z", &options);
        connect_sockets(&mut socket_a, &mut socket_z);

        socket_a.send(
            Message::new(StreamId(1), PpId(53), vec![0; options.mtu - 100]),
            &SendOptions::default(),
        );
        socket_a.send(
            Message::new(StreamId(1), PpId(53), vec![0; options.mtu - 100]),
            &SendOptions::default(),
        );
        // A -> DATA -> Z
        socket_z.handle_input(&expect_sent_packet!(socket_a.poll_event()));
        // A -> DATA -> Z
        socket_z.handle_input(&expect_sent_packet!(socket_a.poll_event()));
        // A <- SACK <- Z
        assert!(socket_z.get_next_message().is_some());
        socket_a.handle_input(&expect_sent_packet!(socket_z.poll_event()));

        assert!(socket_z.get_next_message().is_some());

        // Reset the outgoing stream. This will directly send a RE-CONFIG.
        assert_eq!(socket_a.reset_streams(&[StreamId(1)]), ResetStreamsStatus::Performed);

        // TODO: Verify SSNs. Right now verified in Wireshark.
        // A -> RECONFIG -> Z
        let packet = expect_sent_packet!(socket_a.poll_event());
        socket_z.handle_input(&packet);
        expect_on_incoming_stream_reset!(socket_z.poll_event());
        // A <- RECONFIG <- Z
        socket_a.handle_input(&expect_sent_packet!(socket_z.poll_event()));
        expect_on_streams_reset_performed!(socket_a.poll_event());
        // A <- SACK <- Z
        socket_a.handle_input(&expect_sent_packet!(socket_z.poll_event()));

        socket_a.send(
            Message::new(StreamId(1), PpId(53), vec![0; options.mtu - 100]),
            &SendOptions::default(),
        );
        socket_a.send(
            Message::new(StreamId(1), PpId(53), vec![0; options.mtu - 100]),
            &SendOptions::default(),
        );

        // A -> DATA -> Z
        socket_z.handle_input(&expect_sent_packet!(socket_a.poll_event()));
        // A -> DATA -> Z
        socket_z.handle_input(&expect_sent_packet!(socket_a.poll_event()));
        assert_eq!(socket_z.messages_ready_count(), 2);

        // A <- SACK <- Z
        socket_a.handle_input(&expect_sent_packet!(socket_z.poll_event()));

        expect_no_event!(socket_a.poll_event());
        expect_no_event!(socket_z.poll_event());
    }

    #[test]
    fn reset_stream_will_only_reset_the_requested_streams() {
        let options = default_options();
        let mut socket_a = Socket::new("A", &options);
        let mut socket_z = Socket::new("Z", &options);
        connect_sockets(&mut socket_a, &mut socket_z);

        // Send two ordered messages on SID 1
        let s = SendOptions::default();
        let payload = vec![0; options.mtu - 100];
        socket_a.send(Message::new(StreamId(1), PpId(53), payload.clone()), &s);
        socket_a.send(Message::new(StreamId(1), PpId(53), payload.clone()), &s);

        exchange_packets(&mut socket_a, &mut socket_z);

        // Do the same, for SID 3
        socket_a.send(Message::new(StreamId(3), PpId(53), payload.clone()), &s);
        socket_a.send(Message::new(StreamId(3), PpId(53), payload.clone()), &s);

        exchange_packets(&mut socket_a, &mut socket_z);

        // Reset SID 3. This will directly send a RE-CONFIG.
        socket_a.reset_streams(&[StreamId(3)]);

        // RE-CONFIG, req, RE-CONFIG resp
        exchange_packets(&mut socket_a, &mut socket_z);

        // Send a message on SID 1 and 3 - SID 1 should not be reset, but 3 should.
        socket_a.send(Message::new(StreamId(1), PpId(53), payload.clone()), &s);
        socket_a.send(Message::new(StreamId(3), PpId(53), payload.clone()), &s);

        let packet =
            SctpPacket::from_bytes(&expect_sent_packet!(socket_a.poll_event()), &options).unwrap();
        assert_eq!(packet.chunks.len(), 1);
        let Chunk::Data(chunk) = &packet.chunks[0] else {
            panic!();
        };
        assert_eq!(chunk.data.stream_key, StreamKey::Ordered(StreamId(1)));
        assert_eq!(chunk.data.ssn, Ssn(2));

        let packet =
            SctpPacket::from_bytes(&expect_sent_packet!(socket_a.poll_event()), &options).unwrap();
        assert_eq!(packet.chunks.len(), 1);
        let Chunk::Data(chunk) = &packet.chunks[0] else {
            panic!();
        };
        assert_eq!(chunk.data.stream_key, StreamKey::Ordered(StreamId(3)));
        assert_eq!(chunk.data.ssn, Ssn(0));
    }

    #[test]
    fn one_peer_reconnects() {
        let mut socket_a = Socket::new("A", &default_options());
        let mut socket_z = Socket::new("Z", &default_options());

        connect_sockets(&mut socket_a, &mut socket_z);

        socket_a.close();
        assert_eq!(socket_a.state(), SocketState::Closed);

        socket_a.connect();
        exchange_packets(&mut socket_a, &mut socket_z);
    }

    #[test]
    fn one_peer_reconnects_with_pending_data() {
        let options = default_options();
        let mut socket_a = Socket::new("A", &options);
        let mut socket_z = Socket::new("Z", &options);

        connect_sockets(&mut socket_a, &mut socket_z);

        // Let's be evil here - reconnect while a fragmented packet was about to be sent. The
        // receiving side should get it in full.
        socket_a.send(
            Message::new(StreamId(1), PpId(51), vec![0; options.mtu * 10]),
            &SendOptions::default(),
        );

        socket_z.handle_input(&expect_sent_packet!(socket_a.poll_event()));

        // Create a new association, z2 - and don't use z anymore.
        let mut socket_z2 = Socket::new("Z2", &options);

        socket_z2.connect();

        // Retransmit and handle the rest. As there will be some chunks in-flight that have the
        // wrong verification tag, those will yield errors.
        exchange_packets(&mut socket_a, &mut socket_z2);

        let message = socket_z2.get_next_message().unwrap();
        assert_eq!(message.ppid, PpId(51));
        assert!(socket_z2.get_next_message().is_none());
    }

    #[test]
    fn send_message_with_limited_rtx() {
        let options = default_options();

        let mut socket_a = Socket::new("A", &options);
        let mut socket_z = Socket::new("Z", &options);
        connect_sockets(&mut socket_a, &mut socket_z);
        let s = SendOptions { max_retransmissions: Some(0), ..Default::default() };
        let data = vec![0; options.mtu - 100];
        socket_a.send(Message::new(StreamId(1), PpId(51), data.clone()), &s);
        socket_a.send(Message::new(StreamId(1), PpId(52), data.clone()), &s);
        socket_a.send(Message::new(StreamId(1), PpId(53), data.clone()), &s);

        // A -> DATA -> Z
        socket_z.handle_input(&expect_sent_packet!(socket_a.poll_event()));
        assert_eq!(socket_z.get_next_message().unwrap().ppid, PpId(51));

        // A <- SACK <- Z
        socket_a.handle_input(&expect_sent_packet!(socket_z.poll_event()));

        // A -> DATA -> /lost/ Z
        expect_sent_packet!(socket_a.poll_event());
        // A -> DATA -> Z
        socket_z.handle_input(&expect_sent_packet!(socket_a.poll_event()));

        // A <- SACK <- Z (packet loss detected).
        socket_a.handle_input(&expect_sent_packet!(socket_z.poll_event()));

        expect_no_event!(socket_a.poll_event());
        expect_no_event!(socket_z.poll_event());

        // Now the missing data chunk will be marked as nacked, but it might still be in-flight and
        // the reported gap could be due to out-of-order delivery. So the RetransmissionQueue will
        // not mark it as "to be retransmitted" until after the t3-rtx timer has expired.
        let now = socket_a.poll_timeout();
        socket_a.advance_time(now);
        socket_z.advance_time(now);

        // The chunk will be marked as retransmitted, and then as abandoned, which will trigger a
        // FORWARD-TSN to be sent.

        // A -> FORWARD-TSN -> Z
        socket_z.handle_input(&expect_sent_packet!(socket_a.poll_event()));
        assert_eq!(socket_z.get_next_message().unwrap().ppid, PpId(53));

        // Delayed SACK
        let now = socket_z.poll_timeout();
        socket_z.advance_time(now);

        // A <- SACK <- Z
        socket_a.handle_input(&expect_sent_packet!(socket_z.poll_event()));

        expect_no_event!(socket_a.poll_event());
        expect_no_event!(socket_z.poll_event());
    }

    #[test]
    fn close_connection_after_first_failed_transmission() {
        let mut options = default_options();
        options.max_retransmissions = Some(0);
        let mut now = SocketTime::zero();
        let mut socket_a = Socket::new("A", &options);
        let mut socket_z = Socket::new("Z", &options);
        connect_sockets(&mut socket_a, &mut socket_z);

        socket_a.send(Message::new(StreamId(1), PpId(51), vec![0; 2]), &SendOptions::default());

        // Dropping first transmission.
        let packet = expect_sent_packet!(socket_a.poll_event());
        let packet = SctpPacket::from_bytes(&packet, &options).unwrap();
        assert!(matches!(packet.chunks[0], Chunk::Data(_)));

        // Letting it expire.
        now = now + options.rto_initial;
        socket_a.advance_time(now);

        let packet = expect_sent_packet!(socket_a.poll_event());
        let packet = SctpPacket::from_bytes(&packet, &options).unwrap();
        assert!(matches!(packet.chunks[0], Chunk::Abort(_)));

        assert_eq!(expect_on_aborted!(socket_a.poll_event()), ErrorKind::TooManyRetries);
        expect_no_event!(socket_a.poll_event());
    }

    #[test]
    fn close_connection_after_one_failed_retransmission() {
        let mut options = default_options();
        options.max_retransmissions = Some(1);
        let mut now = SocketTime::zero();
        let mut socket_a = Socket::new("A", &options);
        let mut socket_z = Socket::new("Z", &options);
        connect_sockets(&mut socket_a, &mut socket_z);

        socket_a.send(Message::new(StreamId(1), PpId(51), vec![0; 2]), &SendOptions::default());
        // Dropping first transmission.
        let packet = expect_sent_packet!(socket_a.poll_event());
        let packet = SctpPacket::from_bytes(&packet, &options).unwrap();
        assert!(matches!(packet.chunks[0], Chunk::Data(_)));

        // Dropping the one allowed re-transmission.
        now = now + options.rto_initial;
        socket_a.advance_time(now);

        let packet = expect_sent_packet!(socket_a.poll_event());
        let packet = SctpPacket::from_bytes(&packet, &options).unwrap();
        assert!(matches!(packet.chunks[0], Chunk::Data(_)));

        now = now + options.rto_initial * 2;
        socket_a.advance_time(now);

        let packet = expect_sent_packet!(socket_a.poll_event());
        let packet = SctpPacket::from_bytes(&packet, &options).unwrap();
        assert!(matches!(packet.chunks[0], Chunk::Abort(_)));

        assert_eq!(expect_on_aborted!(socket_a.poll_event()), ErrorKind::TooManyRetries);
        expect_no_event!(socket_a.poll_event());
    }

    #[test]
    fn error_counter_is_reset_on_data_ack() {
        let mut options = default_options();
        options.max_retransmissions = Some(1);
        let mut now = SocketTime::zero();
        let mut socket_a = Socket::new("A", &options);
        let mut socket_z = Socket::new("Z", &options);
        connect_sockets(&mut socket_a, &mut socket_z);

        socket_a.send(Message::new(StreamId(1), PpId(51), vec![0; 2]), &SendOptions::default());
        // Dropping first transmission.
        let packet = expect_sent_packet!(socket_a.poll_event());
        let packet = SctpPacket::from_bytes(&packet, &options).unwrap();
        assert!(matches!(packet.chunks[0], Chunk::Data(_)));

        // Acking the retransmission
        now = now + options.rto_initial;
        socket_a.advance_time(now);

        let packet = expect_sent_packet!(socket_a.poll_event());
        assert!(matches!(
            SctpPacket::from_bytes(&packet, &options).unwrap().chunks[0],
            Chunk::Data(_)
        ));
        socket_z.handle_input(&packet);
        assert!(socket_z.get_next_message().is_some());

        let packet = expect_sent_packet!(socket_z.poll_event());
        assert!(matches!(
            SctpPacket::from_bytes(&packet, &options).unwrap().chunks[0],
            Chunk::Sack(_)
        ));
        socket_a.handle_input(&packet);

        // Send another message
        socket_a.send(Message::new(StreamId(1), PpId(51), vec![0; 2]), &SendOptions::default());

        // Dropping first transmission of second message. The TX error counter recovered before.
        let packet = expect_sent_packet!(socket_a.poll_event());
        let packet = SctpPacket::from_bytes(&packet, &options).unwrap();
        assert!(matches!(packet.chunks[0], Chunk::Data(_)));

        now = now + options.rto_initial;
        socket_a.advance_time(now);

        // The socket should not abort, but retransmit the packet.
        let packet = expect_sent_packet!(socket_a.poll_event());
        assert!(matches!(
            SctpPacket::from_bytes(&packet, &options).unwrap().chunks[0],
            Chunk::Data(_)
        ));
        expect_no_event!(socket_a.poll_event());
    }

    #[test]
    fn both_sides_send_heartbeats() {
        // On an idle connection, both sides send heartbeats, and both sides acks. Make them have
        // slightly different heartbeat intervals, to validate that sending an ack by Z doesn't
        // restart its heartbeat timer.
        let options_a =
            Options { heartbeat_interval: Duration::from_millis(1000), ..default_options() };
        let options_z =
            Options { heartbeat_interval: Duration::from_millis(1100), ..default_options() };
        let mut now = SocketTime::zero();
        let mut socket_a = Socket::new("A", &options_a);
        let mut socket_z = Socket::new("Z", &options_z);
        connect_sockets(&mut socket_a, &mut socket_z);

        now = now + options_a.heartbeat_interval;
        socket_a.advance_time(now);
        socket_z.advance_time(now);
        let packet = expect_sent_packet!(socket_a.poll_event());
        expect_no_event!(socket_a.poll_event());
        expect_no_event!(socket_z.poll_event());
        assert!(matches!(
            SctpPacket::from_bytes(&packet, &options_a).unwrap().chunks[0],
            Chunk::HeartbeatRequest(_)
        ));

        socket_z.handle_input(&packet);
        socket_a.handle_input(&expect_sent_packet!(socket_z.poll_event()));

        now = now + options_z.heartbeat_interval - options_a.heartbeat_interval;
        socket_a.advance_time(now);
        socket_z.advance_time(now);
        let packet = expect_sent_packet!(socket_z.poll_event());
        expect_no_event!(socket_a.poll_event());
        expect_no_event!(socket_z.poll_event());
        assert!(matches!(
            SctpPacket::from_bytes(&packet, &options_a).unwrap().chunks[0],
            Chunk::HeartbeatRequest(_)
        ));
    }

    #[test]
    fn close_connection_after_too_many_retransmissions() {
        let mut options = default_options();
        options.max_retransmissions = Some(10);
        let mut now = SocketTime::zero();
        let mut socket_a = Socket::new("A", &options);
        let mut socket_z = Socket::new("Z", &options);
        connect_sockets(&mut socket_a, &mut socket_z);

        socket_a.send(Message::new(StreamId(1), PpId(51), vec![0; 2]), &SendOptions::default());
        // Dropping first transmission.
        let packet = expect_sent_packet!(socket_a.poll_event());
        let packet = SctpPacket::from_bytes(&packet, &options).unwrap();
        assert!(matches!(packet.chunks[0], Chunk::Data(_)));

        for i in 0..options.max_retransmissions.unwrap() {
            // Dropping every re-transmission.
            now = now + options.rto_initial * (1 << i);
            socket_a.advance_time(now);

            let packet = expect_sent_packet!(socket_a.poll_event());
            let packet = SctpPacket::from_bytes(&packet, &options).unwrap();
            assert!(matches!(packet.chunks[0], Chunk::Data(_)));
        }

        // The last retransmission times out as well.
        println!("Waiting for last retransmission to time out");
        now = now + options.rto_initial * (1 << options.max_retransmissions.unwrap());
        socket_a.advance_time(now);
        println!("Done");

        let packet = expect_sent_packet!(socket_a.poll_event());
        let packet = SctpPacket::from_bytes(&packet, &options).unwrap();
        assert!(matches!(packet.chunks[0], Chunk::Abort(_)));

        assert_eq!(expect_on_aborted!(socket_a.poll_event()), ErrorKind::TooManyRetries);
        expect_no_event!(socket_a.poll_event());
    }

    #[test]
    fn recover_on_last_retransmission() {
        let mut options = default_options();
        options.max_retransmissions = Some(10);
        let mut now = SocketTime::zero();
        let mut socket_a = Socket::new("A", &options);
        let mut socket_z = Socket::new("Z", &options);
        connect_sockets(&mut socket_a, &mut socket_z);

        socket_a.send(Message::new(StreamId(1), PpId(51), vec![0; 2]), &SendOptions::default());
        // Dropping first transmission.
        let packet = expect_sent_packet!(socket_a.poll_event());
        let packet = SctpPacket::from_bytes(&packet, &options).unwrap();
        assert!(matches!(packet.chunks[0], Chunk::Data(_)));

        for i in 0..options.max_retransmissions.unwrap() - 1 {
            // Dropping every re-transmission.
            now = now + options.rto_initial * (1 << i);
            socket_a.advance_time(now);

            let packet = expect_sent_packet!(socket_a.poll_event());
            let packet = SctpPacket::from_bytes(&packet, &options).unwrap();
            assert!(matches!(packet.chunks[0], Chunk::Data(_)));
        }

        // The last retransmission is actually received and acked.
        now = now + options.rto_initial * (1 << (options.max_retransmissions.unwrap() - 1));
        socket_a.advance_time(now);

        exchange_packets(&mut socket_a, &mut socket_z);
        let message = socket_z.get_next_message().unwrap();
        assert_eq!(message.stream_id, StreamId(1));
        assert!(socket_z.get_next_message().is_none());
    }

    #[test]
    fn send_many_fragmented_messages_with_limited_rtx() {
        let options = default_options();
        let mut socket_a = Socket::new("A", &options);
        let mut socket_z = Socket::new("Z", &options);
        connect_sockets(&mut socket_a, &mut socket_z);

        let s =
            SendOptions { unordered: true, max_retransmissions: Some(0), ..SendOptions::default() };
        let p = vec![0; 2 * options.mtu - 100 /* margin */];
        socket_a.send(Message::new(StreamId(1), PpId(51), p.clone()), &s);
        socket_a.send(Message::new(StreamId(1), PpId(52), p.clone()), &s);
        socket_a.send(Message::new(StreamId(1), PpId(53), p.clone()), &s);
        socket_a.send(Message::new(StreamId(1), PpId(54), p.clone()), &s);

        // A -> DATA (msg 1, fragment 1) -> Z
        socket_z.handle_input(&expect_sent_packet!(socket_a.poll_event()));
        // A -> DATA (msg 1, fragment 2) /lost/ -> Z
        expect_sent_packet!(socket_a.poll_event());
        // A -> DATA (msg 2, fragment 1) -> Z
        socket_z.handle_input(&expect_sent_packet!(socket_a.poll_event()));
        // A -> DATA (msg 2, fragment 2) /lost/ -> Z
        expect_sent_packet!(socket_a.poll_event());
        // A -> DATA (msg 3, fragment 1) -> Z
        socket_z.handle_input(&expect_sent_packet!(socket_a.poll_event()));
        // A -> DATA (msg 3, fragment 2) /lost/ -> Z
        expect_sent_packet!(socket_a.poll_event());
        // A -> DATA (msg 4, fragment 1) -> Z
        socket_z.handle_input(&expect_sent_packet!(socket_a.poll_event()));
        // A -> DATA (msg 4, fragment 2) -> Z
        socket_z.handle_input(&expect_sent_packet!(socket_a.poll_event()));

        exchange_packets(&mut socket_a, &mut socket_z);

        assert_eq!(socket_z.get_next_message().unwrap().ppid, PpId(54));
        assert!(socket_z.get_next_message().is_none());
    }

    #[test]
    fn receiving_unknown_chunk_responds_with_error() {
        let options = default_options();
        let mut socket_a = Socket::new("A", &options);
        let mut socket_z = Socket::new("Z", &options);
        connect_sockets(&mut socket_a, &mut socket_z);

        let packet = SctpPacketBuilder::new(
            socket_a.verification_tag(),
            options.local_port,
            options.remote_port,
            options.mtu,
        )
        .add(&Chunk::Unknown(UnknownChunk { typ: 0x49, flags: 0, value: vec![] }))
        .build();
        socket_a.handle_input(&packet);

        assert_eq!(expect_on_error!(socket_a.poll_event()), ErrorKind::ParseFailed);
    }

    #[test]
    fn receiving_error_chunk_reports_as_callback() {
        let options = default_options();
        let mut socket_a = Socket::new("A", &options);
        let mut socket_z = Socket::new("Z", &options);
        connect_sockets(&mut socket_a, &mut socket_z);

        let packet = SctpPacketBuilder::new(
            socket_a.verification_tag(),
            options.local_port,
            options.remote_port,
            options.mtu,
        )
        .add(&Chunk::Error(ErrorChunk {
            error_causes: vec![ErrorCause::UnrecognizedChunk(UnrecognizedChunkErrorCause {
                chunk: vec![1, 2, 3, 4],
            })],
        }))
        .build();
        socket_a.handle_input(&packet);

        assert_eq!(expect_on_error!(socket_a.poll_event()), ErrorKind::PeerReported);
    }

    #[test]
    fn set_max_message_size() {
        let mut socket_a = Socket::new("A", &default_options());
        socket_a.set_max_message_size(42);
        assert_eq!(socket_a.options().max_message_size, 42);
    }

    #[test]
    fn send_many_messages() {
        let mut socket_a = Socket::new("A", &default_options());
        let mut socket_z = Socket::new("Z", &default_options());
        connect_sockets(&mut socket_a, &mut socket_z);

        const ITERATIONS: usize = 100;
        for _ in 0..ITERATIONS {
            socket_a.send(Message::new(StreamId(1), PpId(51), vec![0; 2]), &SendOptions::default());
        }

        exchange_packets(&mut socket_a, &mut socket_z);

        assert_eq!(socket_z.messages_ready_count(), ITERATIONS);
    }

    #[test]
    fn sends_messages_with_low_lifetime() {
        let mut now = SocketTime::zero();
        let mut socket_a = Socket::new("A", &default_options());
        let mut socket_z = Socket::new("Z", &default_options());
        connect_sockets(&mut socket_a, &mut socket_z);

        // Queue a few small messages with low lifetime, both ordered and unordered, and validate
        // that all are delivered.
        const ITERATIONS: usize = 100;
        for i in 0..ITERATIONS {
            let s = SendOptions {
                unordered: (i % 2) == 0,
                lifetime: Some(Duration::from_millis(i as u64 % 3)),
                ..Default::default()
            };
            socket_a.send(Message::new(StreamId(1), PpId(51), vec![0; 2]), &s);
        }

        loop {
            // Mock that the time always goes forward.
            now = now + Duration::from_millis(1);
            socket_a.advance_time(now);
            socket_z.advance_time(now);

            let mut again = false;
            if let Some(e) = socket_a.poll_event() {
                if let SocketEvent::SendPacket(send) = e {
                    socket_z.handle_input(&send);
                }
                again = true;
            }
            if let Some(e) = socket_z.poll_event() {
                if let SocketEvent::SendPacket(send) = e {
                    socket_a.handle_input(&send);
                }
                again = true;
            }
            if !again {
                break;
            }
        }
        assert_eq!(socket_z.messages_ready_count(), ITERATIONS);
    }

    #[test]
    fn discards_messages_with_low_lifetime_if_must_buffer() {
        let options = default_options();
        let mut now = SocketTime::zero();
        let mut socket_a = Socket::new("A", &options);
        let mut socket_z = Socket::new("Z", &options);
        connect_sockets(&mut socket_a, &mut socket_z);

        // Fill up the send buffer with a large message.
        socket_a.send(
            Message::new(StreamId(1), PpId(51), vec![0; 20 * options.mtu]),
            &SendOptions::default(),
        );

        let lifetime_0 =
            SendOptions { unordered: true, lifetime: Some(Duration::ZERO), ..Default::default() };
        let lifetime_1 = SendOptions {
            unordered: true,
            lifetime: Some(Duration::from_millis(1)),
            ..Default::default()
        };
        socket_a.send(Message::new(StreamId(1), PpId(51), vec![0; 3]), &lifetime_0);
        socket_a.send(Message::new(StreamId(1), PpId(51), vec![0; 3]), &lifetime_1);
        socket_a.send(Message::new(StreamId(1), PpId(51), vec![0; 2]), &lifetime_0);

        loop {
            // Mock that the time always goes forward.
            now = now + Duration::from_millis(1);
            socket_a.advance_time(now);
            socket_z.advance_time(now);

            let mut again = false;
            if let Some(e) = socket_a.poll_event() {
                if let SocketEvent::SendPacket(send) = e {
                    socket_z.handle_input(&send);
                }
                again = true;
            }
            if let Some(e) = socket_z.poll_event() {
                if let SocketEvent::SendPacket(send) = e {
                    socket_a.handle_input(&send);
                }
                again = true;
            }
            if !again {
                break;
            }
        }

        // The large message should be delivered. It was sent reliably.
        assert_eq!(socket_z.get_next_message().unwrap().payload.len(), 20 * options.mtu);
        assert!(socket_z.get_next_message().is_none());
    }

    #[test]
    fn respects_per_stream_queue_limit() {
        let options = Options {
            max_send_buffer_size: 4000,
            per_stream_send_queue_limit: 1000,
            ..default_options()
        };
        let mut socket = Socket::new("A", &options);
        let lifecycle_id = LifecycleId::from(123);
        let s = SendOptions { lifecycle_id: Some(lifecycle_id.clone()), ..Default::default() };

        assert_eq!(
            socket.send(Message::new(StreamId(1), PpId(53), vec![0; 600]), &s),
            SendStatus::Success
        );
        assert_eq!(
            socket.send(Message::new(StreamId(1), PpId(53), vec![0; 600]), &s),
            SendStatus::Success
        );
        assert_eq!(
            socket.send(Message::new(StreamId(1), PpId(53), vec![0; 600]), &s),
            SendStatus::ErrorResourceExhaustion
        );
        assert_eq!(expect_on_lifecycle_end!(socket.poll_event()), lifecycle_id.clone());
        assert_eq!(expect_on_error!(socket.poll_event()), ErrorKind::ResourceExhaustion);

        // The per-stream limit for SID=1 is reached, but not SID=2.
        assert_eq!(
            socket.send(Message::new(StreamId(2), PpId(53), vec![0; 600]), &s),
            SendStatus::Success
        );
        assert_eq!(
            socket.send(Message::new(StreamId(2), PpId(53), vec![0; 600]), &s),
            SendStatus::Success
        );
        assert_eq!(
            socket.send(Message::new(StreamId(2), PpId(53), vec![0; 600]), &s),
            SendStatus::ErrorResourceExhaustion
        );
        assert_eq!(expect_on_lifecycle_end!(socket.poll_event()), lifecycle_id.clone());
        assert_eq!(expect_on_error!(socket.poll_event()), ErrorKind::ResourceExhaustion);
    }

    #[test]
    fn cannot_send_empty_messages() {
        let mut socket = Socket::new("A", &default_options());

        let lifecycle_id = LifecycleId::from(123);
        let s = SendOptions { lifecycle_id: Some(lifecycle_id.clone()), ..Default::default() };
        assert_eq!(
            socket.send(Message::new(StreamId(1), PpId(53), vec![]), &s),
            SendStatus::ErrorMessageEmpty
        );

        assert_eq!(expect_on_lifecycle_end!(socket.poll_event()), lifecycle_id.clone());
        assert_eq!(expect_on_error!(socket.poll_event()), ErrorKind::ProtocolViolation);
    }

    #[test]
    fn cannot_send_too_large_message() {
        let options = Options { max_message_size: 100, ..default_options() };
        let mut socket = Socket::new("A", &options);

        let lifecycle_id = LifecycleId::from(123);
        let s = SendOptions { lifecycle_id: Some(lifecycle_id.clone()), ..Default::default() };
        assert_eq!(
            socket.send(Message::new(StreamId(1), PpId(53), vec![0; 101]), &s),
            SendStatus::ErrorMessageTooLarge
        );

        assert_eq!(expect_on_lifecycle_end!(socket.poll_event()), lifecycle_id.clone());
        assert_eq!(expect_on_error!(socket.poll_event()), ErrorKind::ProtocolViolation);
    }

    #[test]
    fn has_reasonable_buffered_amount_values() {
        let options = default_options();
        let mut socket_a = Socket::new("A", &options);
        let mut socket_z = Socket::new("Z", &options);
        connect_sockets(&mut socket_a, &mut socket_z);

        assert_eq!(socket_a.buffered_amount(StreamId(1)), 0);

        socket_a.send(Message::new(StreamId(1), PpId(53), vec![0; 100]), &SendOptions::default());

        // Sending a small message will directly send it as a single packet, so nothing is left in
        // the queue.
        assert_eq!(socket_a.buffered_amount(StreamId(1)), 0);

        socket_a.send(
            Message::new(StreamId(1), PpId(53), vec![0; 20 * options.mtu]),
            &SendOptions::default(),
        );

        // Sending a message will directly start sending a few packets, so the buffered amount is
        // not the full message size.
        assert!(socket_a.buffered_amount(StreamId(1)) > 0);
        assert!(socket_a.buffered_amount(StreamId(1)) < 20 * options.mtu);
    }

    #[test]
    fn has_default_on_buffered_amount_low_value_zero() {
        let socket_a = Socket::new("A", &Options::default());
        assert_eq!(socket_a.buffered_amount_low_threshold(StreamId(1)), 0);
    }

    #[test]
    fn triggers_on_buffered_amount_low_with_default_value_zero() {
        let options =
            Options { default_stream_buffered_amount_low_threshold: 0, ..default_options() };
        let mut socket_a = Socket::new("A", &options);
        let mut socket_z = Socket::new("Z", &options);
        connect_sockets(&mut socket_a, &mut socket_z);
        expect_no_event!(socket_a.poll_event());
        expect_no_event!(socket_z.poll_event());

        socket_a.send(Message::new(StreamId(1), PpId(53), vec![0; 100]), &SendOptions::default());
        let (mut events_a, _) = exchange_packets(&mut socket_a, &mut socket_z);

        assert_eq!(expect_buffered_amount_low!(events_a.pop_front()), StreamId(1));
        assert!(socket_z.get_next_message().is_some());
    }

    #[test]
    fn doesnt_trigger_on_buffered_amount_low_if_below_threshold() {
        let mut socket_a = Socket::new("A", &default_options());
        let mut socket_z = Socket::new("Z", &default_options());
        connect_sockets(&mut socket_a, &mut socket_z);
        expect_no_event!(socket_a.poll_event());
        expect_no_event!(socket_z.poll_event());

        socket_a.set_buffered_amount_low_threshold(StreamId(1), 1001);

        socket_a.send(Message::new(StreamId(1), PpId(53), vec![0; 1000]), &SendOptions::default());
        let (mut events_a, mut events_z) = exchange_packets(&mut socket_a, &mut socket_z);

        expect_no_event!(events_a.pop_front());
        expect_no_event!(events_z.pop_front());
        assert!(socket_z.get_next_message().is_some());
        assert!(socket_z.get_next_message().is_none());

        socket_a.send(Message::new(StreamId(1), PpId(53), vec![0; 1000]), &SendOptions::default());
        let (mut events_a, mut events_z) = exchange_packets(&mut socket_a, &mut socket_z);
        expect_no_event!(events_a.pop_front());
        expect_no_event!(events_z.pop_front());
        assert!(socket_z.get_next_message().is_some());
        assert!(socket_z.get_next_message().is_none());
    }

    #[test]
    fn triggers_on_buffered_amount_multiple_times() {
        let mut socket_a = Socket::new("A", &default_options());
        let mut socket_z = Socket::new("Z", &default_options());
        connect_sockets(&mut socket_a, &mut socket_z);
        expect_no_event!(socket_a.poll_event());
        expect_no_event!(socket_z.poll_event());

        socket_a.set_buffered_amount_low_threshold(StreamId(1), 500);
        socket_a.set_buffered_amount_low_threshold(StreamId(2), 500);

        let s = SendOptions::default();

        socket_a.send(Message::new(StreamId(1), PpId(53), vec![0; 1000]), &s);
        let (mut events_a, _) = exchange_packets(&mut socket_a, &mut socket_z);
        assert_eq!(expect_buffered_amount_low!(events_a.pop_front()), StreamId(1));
        assert!(socket_z.get_next_message().is_some());
        assert!(socket_z.get_next_message().is_none());

        socket_a.send(Message::new(StreamId(2), PpId(53), vec![0; 1000]), &s);
        let (mut events_a, _) = exchange_packets(&mut socket_a, &mut socket_z);
        assert_eq!(expect_buffered_amount_low!(events_a.pop_front()), StreamId(2));
        assert!(socket_z.get_next_message().is_some());
        assert!(socket_z.get_next_message().is_none());

        socket_a.send(Message::new(StreamId(1), PpId(53), vec![0; 1000]), &s);
        let (mut events_a, _) = exchange_packets(&mut socket_a, &mut socket_z);
        assert_eq!(expect_buffered_amount_low!(events_a.pop_front()), StreamId(1));
        assert!(socket_z.get_next_message().is_some());
        assert!(socket_z.get_next_message().is_none());

        socket_a.send(Message::new(StreamId(2), PpId(53), vec![0; 1000]), &s);
        let (mut events_a, _) = exchange_packets(&mut socket_a, &mut socket_z);
        assert_eq!(expect_buffered_amount_low!(events_a.pop_front()), StreamId(2));
        assert!(socket_z.get_next_message().is_some());
        assert!(socket_z.get_next_message().is_none());
    }

    #[test]
    fn triggers_on_buffered_amount_low_only_when_crossing_threshold() {
        let mut socket_a = Socket::new("A", &default_options());
        let mut socket_z = Socket::new("Z", &default_options());
        connect_sockets(&mut socket_a, &mut socket_z);

        socket_a.set_buffered_amount_low_threshold(StreamId(1), 1500);

        // Add a few messages to fill up the congestion window. When that is full, messages will
        // start to be fully buffered.
        while socket_a.buffered_amount(StreamId(1)) <= 1500 {
            let s = SendOptions::default();
            socket_a.send(Message::new(StreamId(1), PpId(53), vec![0; 1000]), &s);
        }

        let (mut events_a, _) = exchange_packets(&mut socket_a, &mut socket_z);
        assert_eq!(expect_buffered_amount_low!(events_a.pop_front()), StreamId(1));
        expect_no_event!(events_a.pop_front());
    }

    #[test]
    fn doesnt_trigger_on_total_buffer_amount_low_when_below() {
        let mut socket_a = Socket::new("A", &default_options());
        let mut socket_z = Socket::new("Z", &default_options());
        connect_sockets(&mut socket_a, &mut socket_z);

        let s = SendOptions::default();
        socket_a.send(Message::new(StreamId(1), PpId(53), vec![0; 20000]), &s);

        let (mut events_a, _) = exchange_packets(&mut socket_a, &mut socket_z);
        expect_no_event!(events_a.pop_front());
    }

    #[test]
    fn triggers_on_total_buffer_amount_low_when_crossing_threshold() {
        let options = Options {
            max_send_buffer_size: 200_000,
            total_buffered_amount_low_threshold: 180_000,
            default_stream_buffered_amount_low_threshold: usize::MAX,
            ..default_options()
        };
        let mut socket_a = Socket::new("A", &options);
        let mut socket_z = Socket::new("Z", &options);
        connect_sockets(&mut socket_a, &mut socket_z);

        // Fill up the send queue completely.
        loop {
            if let SendStatus::ErrorResourceExhaustion = socket_a.send(
                Message::new(StreamId(1), PpId(53), vec![0; 20 * 1000]),
                &SendOptions::default(),
            ) {
                break;
            }
        }

        let (mut events_a, _) = exchange_packets(&mut socket_a, &mut socket_z);
        assert_eq!(expect_on_error!(events_a.pop_front()), ErrorKind::ResourceExhaustion);
        expect_total_buffered_amount_low!(events_a.pop_front());
        expect_no_event!(events_a.pop_front());
    }

    #[test]
    fn initial_metrics_are_unset() {
        let socket_a = Socket::new("A", &default_options());
        assert!(socket_a.get_metrics().is_none());
    }

    #[test]
    fn message_interleaving_metrics_are_set() {
        let combinations = vec![(false, false), (false, true), (true, false), (true, true)];
        for (a_enable, z_enable) in combinations {
            let a_options = Options { enable_message_interleaving: a_enable, ..Default::default() };
            let z_options = Options { enable_message_interleaving: z_enable, ..Default::default() };
            let mut socket_a = Socket::new("A", &a_options);
            let mut socket_z = Socket::new("Z", &z_options);
            connect_sockets(&mut socket_a, &mut socket_z);

            assert_eq!(
                socket_a.get_metrics().unwrap().uses_message_interleaving,
                a_enable && z_enable
            );
            assert_eq!(
                socket_z.get_metrics().unwrap().uses_message_interleaving,
                a_enable && z_enable
            );
        }
    }

    #[test]
    fn rx_and_tx_packet_metrics_increase() {
        let options = default_options();
        let mut socket_a = Socket::new("A", &options);
        let mut socket_z = Socket::new("Z", &options);
        connect_sockets(&mut socket_a, &mut socket_z);

        let initial_a_rwnd =
            ((options.max_receiver_window_buffer_size as f32) * HIGH_WATERMARK_LIMIT) as u32;

        let metrics = socket_a.get_metrics().unwrap();
        assert_eq!(metrics.tx_packets_count, 2);
        assert_eq!(metrics.rx_packets_count, 2);
        assert_eq!(metrics.tx_messages_count, 0);
        assert_eq!(metrics.cwnd_bytes, options.cwnd_mtus_initial * options.mtu,);
        assert_eq!(metrics.unack_data_count, 0);

        let metrics = socket_z.get_metrics().unwrap();
        assert_eq!(metrics.rx_packets_count, 2);
        assert_eq!(metrics.rx_messages_count, 0);

        let payload_size = 2;
        socket_a.send(
            Message::new(StreamId(1), PpId(53), vec![0; payload_size]),
            &SendOptions::default(),
        );

        let metrics = socket_a.get_metrics().unwrap();
        assert_eq!(metrics.unack_data_count, 1);

        // A -> DATA -> Z
        socket_z.handle_input(&expect_sent_packet!(socket_a.poll_event()));
        assert_eq!(socket_z.messages_ready_count(), 1);

        // A <- SACK <- Z
        socket_a.handle_input(&expect_sent_packet!(socket_z.poll_event()));

        let metrics = socket_a.get_metrics().unwrap();
        // The reassembled message is still in the socket, and not consumed, so the receiver window
        // size doesn't recover to its initial value.
        assert_eq!(metrics.peer_rwnd_bytes, initial_a_rwnd - (payload_size as u32));
        assert_eq!(metrics.unack_data_count, 0);
        assert_eq!(metrics.tx_packets_count, 3);
        assert_eq!(metrics.rx_packets_count, 3);
        assert_eq!(metrics.tx_messages_count, 1);

        let metrics = socket_z.get_metrics().unwrap();
        assert_eq!(metrics.rx_packets_count, 3);
        assert_eq!(metrics.rx_messages_count, 1);

        // Send one more (large - fragmented), and receive the delayed SACK.
        socket_a.send(
            Message::new(StreamId(1), PpId(53), vec![0; options.mtu * 2 + 1]),
            &SendOptions::default(),
        );
        let metrics = socket_a.get_metrics().unwrap();
        assert_eq!(metrics.unack_data_count, 3);

        // A -> DATA -> Z
        socket_z.handle_input(&expect_sent_packet!(socket_a.poll_event()));
        expect_no_event!(socket_z.poll_event());
        // A -> DATA -> Z
        socket_z.handle_input(&expect_sent_packet!(socket_a.poll_event()));
        // A <- SACK <- Z
        socket_a.handle_input(&expect_sent_packet!(socket_z.poll_event()));

        let metrics = socket_a.get_metrics().unwrap();
        assert_eq!(metrics.unack_data_count, 1);
        assert!(metrics.peer_rwnd_bytes > 0 && metrics.peer_rwnd_bytes < initial_a_rwnd);

        // A -> DATA -> Z
        socket_z.handle_input(&expect_sent_packet!(socket_a.poll_event()));
        assert_eq!(socket_z.messages_ready_count(), 2);
        socket_z.get_next_message().unwrap();
        socket_z.get_next_message().unwrap();

        // Delayed sack
        let now = socket_z.poll_timeout();
        socket_a.advance_time(now);
        socket_z.advance_time(now);

        // A <- SACK <- Z
        socket_a.handle_input(&expect_sent_packet!(socket_z.poll_event()));

        let metrics = socket_a.get_metrics().unwrap();
        assert_eq!(metrics.unack_data_count, 0);
        assert_eq!(metrics.rx_packets_count, 5);
        // With all reassembled messages consumed from `socket_z`, the receiver window recovers.
        assert_eq!(metrics.peer_rwnd_bytes, initial_a_rwnd);
    }

    #[test]
    fn retransmission_metrics_are_set_for_fast_retransmit() {
        let options = default_options();
        let mut socket_a = Socket::new("A", &options);
        let mut socket_z = Socket::new("Z", &options);
        connect_sockets(&mut socket_a, &mut socket_z);

        // Enough to trigger fast retransmit of the missing second packet.
        socket_a.send(
            Message::new(StreamId(1), PpId(53), vec![0; options.mtu * 5]),
            &SendOptions::default(),
        );

        // Receive first packet, drop second, receive and retransmit the remaining.
        // A -> DATA -> Z
        socket_z.handle_input(&expect_sent_packet!(socket_a.poll_event()));
        expect_sent_packet!(socket_a.poll_event());
        exchange_packets(&mut socket_a, &mut socket_z);

        let metrics = socket_a.get_metrics().unwrap();
        assert_eq!(metrics.rtx_packets_count, 1);
        assert_eq!(
            metrics.rtx_bytes_count,
            round_down_to_4!(options.mtu - sctp_packet::COMMON_HEADER_SIZE) as u64
        );
    }

    #[test]
    fn retransmission_metrics_are_set_for_normal_retransmit() {
        let options = default_options();
        let mut socket_a = Socket::new("A", &options);
        let mut socket_z = Socket::new("Z", &options);
        connect_sockets(&mut socket_a, &mut socket_z);

        socket_a.send(Message::new(StreamId(1), PpId(53), vec![0; 12]), &SendOptions::default());

        expect_sent_packet!(socket_a.poll_event());
        exchange_packets(&mut socket_a, &mut socket_z);

        let metrics = socket_a.get_metrics().unwrap();
        assert_eq!(metrics.rtx_packets_count, 1);
        assert_eq!(metrics.rtx_bytes_count, 12 + data_chunk::HEADER_SIZE as u64);
    }

    #[test]
    fn unack_data_also_includes_send_queue() {
        let options = default_options();
        let mut socket_a = Socket::new("A", &options);
        let mut socket_z = Socket::new("Z", &options);
        connect_sockets(&mut socket_a, &mut socket_z);

        let message_bytes = options.mtu * 10;
        socket_a.send(
            Message::new(StreamId(1), PpId(53), vec![0; message_bytes]),
            &SendOptions::default(),
        );

        let payload_bytes = options.mtu - sctp_packet::COMMON_HEADER_SIZE - data_chunk::HEADER_SIZE;
        let expected_sent_packets = options.cwnd_mtus_initial;
        let expected_queued_bytes = message_bytes - (expected_sent_packets * payload_bytes);
        let expected_queued_packets = expected_queued_bytes / payload_bytes;

        // Due to alignment, padding etc, it's hard to calculate the exact number, but it should be
        // in this range.
        let unack_data_count = socket_a.get_metrics().unwrap().unack_data_count;
        assert!(unack_data_count >= expected_sent_packets + expected_queued_packets);
        assert!(unack_data_count <= expected_sent_packets + expected_queued_packets + 2);
    }

    #[test]
    fn doesnt_send_more_than_max_burst_packets() {
        let options = &Options { max_burst: 3, cwnd_mtus_initial: 500, ..default_options() };
        let mut socket_a = Socket::new("A", options);
        let mut socket_z = Socket::new("Z", options);
        connect_sockets(&mut socket_a, &mut socket_z);

        socket_a.send(
            Message::new(StreamId(1), PpId(53), vec![0; options.mtu * 10]),
            &SendOptions::default(),
        );

        expect_sent_packet!(socket_a.poll_event());
        expect_sent_packet!(socket_a.poll_event());
        expect_sent_packet!(socket_a.poll_event());
        // A fourth packet should not be attempted to be sent, until an ack is received.
        expect_no_event!(socket_a.poll_event());

        exchange_packets(&mut socket_a, &mut socket_z);

        assert_eq!(socket_z.get_next_message().unwrap().ppid, PpId(53));
        assert!(socket_z.get_next_message().is_none());
    }

    #[test]
    fn is_ready_for_handover_when_established() {
        let mut socket_a = Socket::new("A", &default_options());
        let mut socket_z = Socket::new("Z", &default_options());

        // A closed socket is ready.
        assert!(socket_a.get_handover_readiness().is_ready());

        socket_a.connect();
        // A connecting socket is not ready.
        assert!(!socket_a.get_handover_readiness().is_ready());

        exchange_packets(&mut socket_a, &mut socket_z);

        assert!(socket_a.state() == SocketState::Connected);

        // An established socket is ready.
        assert!(socket_a.get_handover_readiness().is_ready());
    }

    #[test]
    fn send_messages_after_handover() {
        let mut socket_a = Socket::new("A", &default_options());
        let mut socket_z = Socket::new("Z", &default_options());
        connect_sockets(&mut socket_a, &mut socket_z);

        let s = SendOptions::default();
        socket_a.send(Message::new(StreamId(1), PpId(51), vec![0; 100]), &s);

        // Send message before handover to move socket to a not initial state
        exchange_packets(&mut socket_a, &mut socket_z);

        let mut new_socket_z = Socket::new("Z2", &default_options());
        handover_socket(&mut socket_z, &mut new_socket_z);

        socket_a.send(Message::new(StreamId(1), PpId(53), vec![0; 2]), &s);
        socket_a.send(Message::new(StreamId(2), PpId(53), vec![0; 2]), &s);
        socket_a.send(Message::new(StreamId(1), PpId(53), vec![0; 2]), &s);

        exchange_packets(&mut socket_a, &mut new_socket_z);
        let msg = new_socket_z.get_next_message().unwrap();
        assert_eq!(msg.stream_id, StreamId(1));
        let msg = new_socket_z.get_next_message().unwrap();
        assert_eq!(msg.stream_id, StreamId(2));
        let msg = new_socket_z.get_next_message().unwrap();
        assert_eq!(msg.stream_id, StreamId(1));
        assert!(new_socket_z.get_next_message().is_none());
    }

    #[test]
    fn can_detect_dcsctp_implementation() {
        let mut socket_a = Socket::new("A", &default_options());
        let mut socket_z = Socket::new("Z", &default_options());
        socket_a.connect();

        exchange_packets(&mut socket_a, &mut socket_z);
        assert_eq!(socket_a.state(), SocketState::Connected);
        assert_eq!(socket_z.state(), SocketState::Connected);

        assert_eq!(
            socket_a.get_metrics().unwrap().peer_implementation,
            SctpImplementation::DcsctpRs
        );
        assert_eq!(
            socket_z.get_metrics().unwrap().peer_implementation,
            SctpImplementation::Unknown
        );
    }

    #[test]
    fn both_can_detect_dcsctp_implementation() {
        let mut socket_a = Socket::new("A", &default_options());
        let mut socket_z = Socket::new("Z", &default_options());
        socket_a.connect();
        socket_z.connect();

        exchange_packets(&mut socket_a, &mut socket_z);
        assert_eq!(socket_a.state(), SocketState::Connected);
        assert_eq!(socket_z.state(), SocketState::Connected);

        assert_eq!(
            socket_a.get_metrics().unwrap().peer_implementation,
            SctpImplementation::DcsctpRs
        );
        assert_eq!(
            socket_z.get_metrics().unwrap().peer_implementation,
            SctpImplementation::DcsctpRs
        );
    }

    #[test]
    fn can_lose_first_ordered_message() {
        let options = default_options();
        let mut socket_a = Socket::new("A", &options);
        let mut socket_z = Socket::new("Z", &options);
        connect_sockets(&mut socket_a, &mut socket_z);

        let send_options = SendOptions {
            unordered: false,
            max_retransmissions: Some(0),
            ..SendOptions::default()
        };

        // Send a first message (SID=1, SSN=0)
        socket_a
            .send(Message::new(StreamId(1), PpId(51), vec![0; options.mtu - 100]), &send_options);

        // First DATA is lost, and retransmission timer will delete it.
        // A -> DATA -> /lost/ Z
        expect_sent_packet!(socket_a.poll_event());
        exchange_packets(&mut socket_a, &mut socket_z);

        // Send a second message (SID=0, SSN=1).
        socket_a
            .send(Message::new(StreamId(1), PpId(52), vec![0; options.mtu - 100]), &send_options);

        exchange_packets(&mut socket_a, &mut socket_z);

        assert_eq!(socket_z.get_next_message().unwrap().ppid, PpId(52));
        assert!(socket_z.get_next_message().is_none());
    }

    #[test]
    fn close_two_streams_at_the_same_time() {
        let mut socket_a = Socket::new("A", &default_options());
        let mut socket_z = Socket::new("Z", &default_options());
        connect_sockets(&mut socket_a, &mut socket_z);

        let s = SendOptions::default();
        socket_a.send(Message::new(StreamId(1), PpId(53), vec![0; 2]), &s);
        socket_a.send(Message::new(StreamId(2), PpId(53), vec![0; 2]), &s);

        let (mut events_a, _) = exchange_packets(&mut socket_a, &mut socket_z);
        expect_no_event!(events_a.pop_front());

        socket_a.reset_streams(&[StreamId(1)]);
        socket_a.reset_streams(&[StreamId(2)]);

        let (mut events_a, mut events_z) = exchange_packets(&mut socket_a, &mut socket_z);
        assert_eq!(expect_on_incoming_stream_reset!(events_z.pop_front()), vec![StreamId(1)]);
        assert_eq!(expect_on_incoming_stream_reset!(events_z.pop_front()), vec![StreamId(2)]);
        assert_eq!(expect_on_streams_reset_performed!(events_a.pop_front()), vec![StreamId(1)]);
        assert_eq!(expect_on_streams_reset_performed!(events_a.pop_front()), vec![StreamId(2)]);
        expect_no_event!(events_a.pop_front());
        expect_no_event!(events_z.pop_front());
    }

    #[test]
    fn close_three_streams_at_the_same_time() {
        // Similar to `test_close_two_streams_at_the_same_time`, but ensuring that the two remaining
        // streams are reset at the same time in the second request.
        let mut socket_a = Socket::new("A", &default_options());
        let mut socket_z = Socket::new("Z", &default_options());
        connect_sockets(&mut socket_a, &mut socket_z);

        let s = SendOptions::default();
        socket_a.send(Message::new(StreamId(1), PpId(53), vec![0; 2]), &s);
        socket_a.send(Message::new(StreamId(2), PpId(53), vec![0; 2]), &s);
        socket_a.send(Message::new(StreamId(3), PpId(53), vec![0; 2]), &s);

        let (mut events_a, _) = exchange_packets(&mut socket_a, &mut socket_z);
        expect_no_event!(events_a.pop_front());

        socket_a.reset_streams(&[StreamId(1)]);
        socket_a.reset_streams(&[StreamId(2)]);
        socket_a.reset_streams(&[StreamId(3)]);

        let (mut events_a, mut events_z) = exchange_packets(&mut socket_a, &mut socket_z);
        assert_eq!(expect_on_incoming_stream_reset!(events_z.pop_front()), vec![StreamId(1)]);
        assert!(unordered_eq(
            &expect_on_incoming_stream_reset!(events_z.pop_front()),
            &[StreamId(2), StreamId(3)]
        ));
        assert_eq!(expect_on_streams_reset_performed!(events_a.pop_front()), vec![StreamId(1)]);
        assert!(unordered_eq(
            &expect_on_streams_reset_performed!(events_a.pop_front()),
            &[StreamId(2), StreamId(3)]
        ));
        expect_no_event!(events_a.pop_front());
        expect_no_event!(events_z.pop_front());
    }

    #[test]
    fn close_streams_with_pending_request() {
        // Checks that stream reset requests are properly paused when they can't be immediately
        // reset - i.e. when there is already an ongoing stream reset request (and there can only be
        // a single one in-flight).
        let mut socket_a = Socket::new("A", &default_options());
        let mut socket_z = Socket::new("Z", &default_options());
        connect_sockets(&mut socket_a, &mut socket_z);

        let s = SendOptions { unordered: false, ..Default::default() };
        socket_a.send(Message::new(StreamId(1), PpId(53), vec![0; 2]), &s);
        socket_a.send(Message::new(StreamId(2), PpId(53), vec![0; 2]), &s);
        socket_a.send(Message::new(StreamId(3), PpId(53), vec![0; 2]), &s);

        let (mut events_a, _) = exchange_packets(&mut socket_a, &mut socket_z);
        expect_no_event!(events_a.pop_front());

        socket_a.reset_streams(&[StreamId(1)]);
        socket_a.reset_streams(&[StreamId(2)]);
        socket_a.reset_streams(&[StreamId(3)]);

        exchange_packets(&mut socket_a, &mut socket_z);
        // Drain any received messages.
        socket_z.get_next_message();
        socket_z.get_next_message();
        socket_z.get_next_message();

        socket_a.send(Message::new(StreamId(1), PpId(53), vec![0; 2]), &s);
        socket_a.send(Message::new(StreamId(2), PpId(53), vec![0; 2]), &s);
        socket_a.send(Message::new(StreamId(3), PpId(53), vec![0; 2]), &s);

        exchange_packets(&mut socket_a, &mut socket_z);
        let msg = socket_z.get_next_message().unwrap();
        assert_eq!(msg.stream_id, StreamId(1));
        let msg = socket_z.get_next_message().unwrap();
        assert_eq!(msg.stream_id, StreamId(2));
        let msg = socket_z.get_next_message().unwrap();
        assert_eq!(msg.stream_id, StreamId(3));
    }

    #[test]
    fn stream_has_initial_priority() {
        let options = Options { default_stream_priority: 42, ..Default::default() };
        let socket_a = Socket::new("A", &options);

        assert_eq!(socket_a.get_stream_priority(StreamId(1)), 42);
        assert_eq!(socket_a.get_stream_priority(StreamId(2)), 42);
    }

    #[test]
    fn can_change_stream_priority() {
        let mut socket_a = Socket::new("A", &default_options());

        socket_a.set_stream_priority(StreamId(1), 42);
        assert_eq!(socket_a.get_stream_priority(StreamId(1)), 42);

        socket_a.set_stream_priority(StreamId(2), 43);
        assert_eq!(socket_a.get_stream_priority(StreamId(2)), 43);

        assert_eq!(socket_a.get_stream_priority(StreamId(1)), 42);
    }

    #[test]
    fn will_handover_priority() {
        // This is an issue found by fuzzing, and doesn't really make sense in WebRTC data channels
        // as a SCTP connection is never ever closed and then reconnected. SCTP connections are
        // closed when the peer connection is deleted, and then it doesn't do more with SCTP.
        let mut socket_a = Socket::new("A", &default_options());
        let mut socket_z = Socket::new("Z", &default_options());
        connect_sockets(&mut socket_a, &mut socket_z);

        socket_a.set_stream_priority(StreamId(1), 43);
        let s = SendOptions::default();
        socket_a.send(Message::new(StreamId(1), PpId(51), vec![0; 100]), &s);
        socket_a.set_stream_priority(StreamId(2), 34);

        exchange_packets(&mut socket_a, &mut socket_z);

        let mut new_socket_a = Socket::new("A2", &default_options());
        handover_socket(&mut socket_a, &mut new_socket_a);

        assert_eq!(new_socket_a.get_stream_priority(StreamId(1)), 43);
        assert_eq!(new_socket_a.get_stream_priority(StreamId(2)), 34);
    }

    #[test]
    fn reconnect_socket_with_pending_stream_reset() {
        // This is an issue found by fuzzing, and doesn't really make sense in WebRTC data channels
        // as a SCTP connection is never ever closed and then reconnected. SCTP connections are
        // closed when the peer connection is deleted, and then it doesn't do more with SCTP.
        let mut socket_a = Socket::new("A", &default_options());
        let mut socket_z = Socket::new("Z", &default_options());

        connect_sockets(&mut socket_a, &mut socket_z);

        assert_eq!(socket_a.reset_streams(&[StreamId(1)]), ResetStreamsStatus::Performed);

        socket_a.close();
        assert_eq!(socket_a.state(), SocketState::Closed);

        socket_a.connect();
        exchange_packets(&mut socket_a, &mut socket_z);

        assert_eq!(socket_a.reset_streams(&[StreamId(2)]), ResetStreamsStatus::Performed);
    }

    #[test]
    fn small_sent_messages_with_prio_will_arrive_in_specific_order() {
        let options = Options { enable_message_interleaving: true, ..default_options() };

        let mut socket_a = Socket::new("A", &options);
        let mut socket_z = Socket::new("Z", &options);

        socket_a.set_stream_priority(StreamId(1), 700);
        socket_a.set_stream_priority(StreamId(2), 200);
        socket_a.set_stream_priority(StreamId(3), 100);

        // Enqueue messages before connecting the socket, to ensure they aren't sent as soon as
        // `send` is called.
        let s = SendOptions::default();
        socket_a.send(Message::new(StreamId(3), PpId(301), vec![0; 10]), &s);
        socket_a.send(Message::new(StreamId(1), PpId(101), vec![0; 10]), &s);
        socket_a.send(Message::new(StreamId(2), PpId(201), vec![0; 10]), &s);
        socket_a.send(Message::new(StreamId(1), PpId(102), vec![0; 10]), &s);
        socket_a.send(Message::new(StreamId(1), PpId(103), vec![0; 10]), &s);

        socket_a.connect();
        exchange_packets(&mut socket_a, &mut socket_z);

        assert_eq!(socket_z.get_next_message().unwrap().ppid, PpId(101));
        assert_eq!(socket_z.get_next_message().unwrap().ppid, PpId(102));
        assert_eq!(socket_z.get_next_message().unwrap().ppid, PpId(103));
        assert_eq!(socket_z.get_next_message().unwrap().ppid, PpId(201));
        assert_eq!(socket_z.get_next_message().unwrap().ppid, PpId(301));
        assert!(socket_z.get_next_message().is_none());
    }

    #[test]
    fn large_sent_messages_with_prio_will_arrive_in_specific_order() {
        let options = Options { enable_message_interleaving: true, ..default_options() };

        let mut socket_a = Socket::new("A", &options);
        let mut socket_z = Socket::new("Z", &options);

        socket_a.set_stream_priority(StreamId(1), 700);
        socket_a.set_stream_priority(StreamId(2), 200);
        socket_a.set_stream_priority(StreamId(3), 100);

        // Enqueue messages before connecting the socket, to ensure they aren't sent as soon as
        // `send` is called.
        let s = SendOptions::default();
        let payload = vec![0; options.mtu * 2];
        socket_a.send(Message::new(StreamId(3), PpId(301), payload.clone()), &s);
        socket_a.send(Message::new(StreamId(1), PpId(101), payload.clone()), &s);
        socket_a.send(Message::new(StreamId(2), PpId(201), payload.clone()), &s);
        socket_a.send(Message::new(StreamId(1), PpId(102), payload.clone()), &s);
        socket_a.send(Message::new(StreamId(1), PpId(103), payload.clone()), &s);

        socket_a.connect();
        exchange_packets(&mut socket_a, &mut socket_z);

        assert_eq!(socket_z.get_next_message().unwrap().ppid, PpId(101));
        assert_eq!(socket_z.get_next_message().unwrap().ppid, PpId(102));
        assert_eq!(socket_z.get_next_message().unwrap().ppid, PpId(103));
        assert_eq!(socket_z.get_next_message().unwrap().ppid, PpId(201));
        assert_eq!(socket_z.get_next_message().unwrap().ppid, PpId(301));
        assert!(socket_z.get_next_message().is_none());
    }

    #[test]
    fn message_with_higher_prio_will_interrupt_lower_prio_message() {
        let options = Options { enable_message_interleaving: true, ..default_options() };
        let s = SendOptions::default();

        let mut socket_a = Socket::new("A", &options);
        let mut socket_z = Socket::new("Z", &options);
        connect_sockets(&mut socket_a, &mut socket_z);

        socket_a.set_stream_priority(StreamId(2), 128);
        socket_a.send(Message::new(StreamId(2), PpId(201), vec![0; 20 * options.mtu]), &s);

        // Due to a non-zero initial congestion window, the message will already start to send, but
        // will not succeed to be sent completely before filling the congestion window or stopping
        // due to reaching how many packets that can be sent at once (max burst). The important
        // thing is that the entire message doesn't get sent in full.

        // Now enqueue two messages; one small and one large higher priority message.

        socket_a.set_stream_priority(StreamId(1), 512);
        socket_a.send(Message::new(StreamId(1), PpId(101), vec![0; 10]), &s);
        socket_a.send(Message::new(StreamId(1), PpId(102), vec![0; 20 * options.mtu]), &s);

        exchange_packets(&mut socket_a, &mut socket_z);

        assert_eq!(socket_z.get_next_message().unwrap().ppid, PpId(101));
        assert_eq!(socket_z.get_next_message().unwrap().ppid, PpId(102));
        assert_eq!(socket_z.get_next_message().unwrap().ppid, PpId(201));
        assert!(socket_z.get_next_message().is_none());
    }

    #[test]
    fn lifecycle_events_are_generated_for_acked_messages() {
        let options = default_options();

        let mut socket_a = Socket::new("A", &options);
        let mut socket_z = Socket::new("Z", &options);
        connect_sockets(&mut socket_a, &mut socket_z);

        socket_a.send(
            Message::new(StreamId(1), PpId(101), vec![0; options.mtu]),
            &SendOptions { lifecycle_id: LifecycleId::new(41), ..Default::default() },
        );
        socket_a.send(
            Message::new(StreamId(1), PpId(102), vec![0; options.mtu]),
            &SendOptions::default(),
        );
        socket_a.send(
            Message::new(StreamId(1), PpId(103), vec![0; options.mtu]),
            &SendOptions { lifecycle_id: LifecycleId::new(42), ..Default::default() },
        );

        let (events_a, _) = exchange_packets(&mut socket_a, &mut socket_z);
        assert!(events_a.iter().any(is_lifecycle_message_delivered(LifecycleId::from(41))));
        assert!(events_a.iter().any(is_lifecycle_message_delivered(LifecycleId::from(42))));
        assert!(events_a.iter().any(is_lifecycle_end(LifecycleId::from(41))));
        assert!(events_a.iter().any(is_lifecycle_end(LifecycleId::from(42))));
    }

    #[test]
    fn lifecycle_events_for_fail_max_retransmissions() {
        let options = default_options();

        let mut socket_a = Socket::new("A", &options);
        let mut socket_z = Socket::new("Z", &options);
        connect_sockets(&mut socket_a, &mut socket_z);

        socket_a.send(
            Message::new(StreamId(1), PpId(101), vec![0; options.mtu - 100]),
            &SendOptions {
                max_retransmissions: Some(0),
                lifecycle_id: LifecycleId::new(41),
                ..Default::default()
            },
        );
        socket_a.send(
            Message::new(StreamId(1), PpId(102), vec![0; options.mtu - 100]),
            &SendOptions {
                max_retransmissions: Some(0),
                lifecycle_id: LifecycleId::new(42),
                ..Default::default()
            },
        );
        socket_a.send(
            Message::new(StreamId(1), PpId(103), vec![0; options.mtu - 100]),
            &SendOptions {
                max_retransmissions: Some(0),
                lifecycle_id: LifecycleId::new(43),
                ..Default::default()
            },
        );

        // A -> DATA -> Z
        socket_z.handle_input(&expect_sent_packet!(socket_a.poll_event()));
        // A -> DATA -> /lost/ Z
        expect_sent_packet!(socket_a.poll_event());

        let (events_a, _) = exchange_packets(&mut socket_a, &mut socket_z);
        assert!(events_a.iter().any(is_lifecycle_message_delivered(LifecycleId::from(41))));
        assert!(events_a.iter().any(is_lifecycle_message_maybe_expired(LifecycleId::from(42))));
        assert!(events_a.iter().any(is_lifecycle_message_delivered(LifecycleId::from(43))));
        assert!(events_a.iter().any(is_lifecycle_end(LifecycleId::from(41))));
        assert!(events_a.iter().any(is_lifecycle_end(LifecycleId::from(42))));
        assert!(events_a.iter().any(is_lifecycle_end(LifecycleId::from(43))));
    }

    #[test]
    fn lifecycle_events_for_expired_message_with_retransmit_limit() {
        let options = default_options();

        let mut socket_a = Socket::new("A", &options);
        let mut socket_z = Socket::new("Z", &options);
        connect_sockets(&mut socket_a, &mut socket_z);

        socket_a.send(
            Message::new(StreamId(1), PpId(101), vec![0; 20 * options.mtu]),
            &SendOptions {
                max_retransmissions: Some(0),
                lifecycle_id: LifecycleId::new(41),
                ..Default::default()
            },
        );

        // A -> DATA -> Z
        socket_z.handle_input(&expect_sent_packet!(socket_a.poll_event()));
        // A -> DATA -> /lost/ Z
        expect_sent_packet!(socket_a.poll_event());

        let (events_a, _) = exchange_packets(&mut socket_a, &mut socket_z);
        assert!(events_a.iter().any(is_lifecycle_message_expired(LifecycleId::from(41))));
        assert!(events_a.iter().any(is_lifecycle_end(LifecycleId::from(41))));
    }

    #[test]
    fn lifecycle_events_for_expired_message_with_lifetime_limit() {
        let options = default_options();

        let mut socket_a = Socket::new("A", &options);
        let mut socket_z = Socket::new("Z", &options);

        // Send it before the socket is connected, to prevent it from being sent too quickly. The
        // idea is that it should be expired before even attempting to send it in full.
        socket_a.send(
            Message::new(StreamId(1), PpId(101), vec![0; 20 * options.mtu]),
            &SendOptions {
                lifetime: Some(Duration::from_millis(100)),
                lifecycle_id: LifecycleId::new(41),
                ..Default::default()
            },
        );
        socket_a.advance_time(SocketTime::from(Duration::from_millis(200)));
        socket_a.connect();

        let (events_a, _) = exchange_packets(&mut socket_a, &mut socket_z);
        assert!(events_a.iter().any(is_lifecycle_message_expired(LifecycleId::from(41))));
        assert!(events_a.iter().any(is_lifecycle_end(LifecycleId::from(41))));
    }

    #[test]
    fn exposes_the_number_of_negotiated_streams() {
        let options_a = Options {
            announced_maximum_incoming_streams: 12,
            announced_maximum_outgoing_streams: 45,
            ..default_options()
        };
        let options_z = Options {
            announced_maximum_incoming_streams: 23,
            announced_maximum_outgoing_streams: 34,
            ..default_options()
        };

        let mut socket_a = Socket::new("A", &options_a);
        let mut socket_z = Socket::new("Z", &options_z);
        connect_sockets(&mut socket_a, &mut socket_z);

        let metrics = socket_a.get_metrics().unwrap();
        assert_eq!(metrics.negotiated_maximum_incoming_streams, 12);
        assert_eq!(metrics.negotiated_maximum_outgoing_streams, 23);

        let metrics = socket_z.get_metrics().unwrap();
        assert_eq!(metrics.negotiated_maximum_incoming_streams, 23);
        assert_eq!(metrics.negotiated_maximum_outgoing_streams, 12);
    }

    #[test]
    fn reset_streams_deferred() {
        let options = default_options();
        let mut socket_a = Socket::new("A", &options);
        let mut socket_z = Socket::new("Z", &options);
        connect_sockets(&mut socket_a, &mut socket_z);

        // Guaranteed to be fragmented into two fragments.
        socket_a.send(
            Message::new(StreamId(1), PpId(53), vec![0; options.mtu + 100]),
            &SendOptions::default(),
        );
        socket_a.send(Message::new(StreamId(1), PpId(54), vec![0; 100]), &SendOptions::default());

        assert_eq!(socket_a.reset_streams(&[StreamId(1)]), ResetStreamsStatus::Performed);

        let data1 = expect_sent_packet!(socket_a.poll_event());
        assert!(matches!(
            SctpPacket::from_bytes(&data1, &options).unwrap().chunks[0],
            Chunk::Data(DataChunk { data: Data { ssn: Ssn(0), .. }, .. })
        ));
        let data2 = expect_sent_packet!(socket_a.poll_event());
        assert!(matches!(
            SctpPacket::from_bytes(&data2, &options).unwrap().chunks[0],
            Chunk::Data(DataChunk { data: Data { ssn: Ssn(0), .. }, .. })
        ));
        let data3 = expect_sent_packet!(socket_a.poll_event());
        assert!(matches!(
            SctpPacket::from_bytes(&data3, &options).unwrap().chunks[0],
            Chunk::Data(DataChunk { data: Data { ssn: Ssn(1), .. }, .. })
        ));
        let reconfig = expect_sent_packet!(socket_a.poll_event());
        assert!(matches!(
            SctpPacket::from_bytes(&reconfig, &options).unwrap().chunks[0],
            Chunk::ReConfig(_)
        ));

        // Receive them slightly out of order to make stream resetting deferred.
        socket_z.handle_input(&reconfig);
        // A <- RECONFIG RESPONSE(in progress) <- Z
        socket_a.handle_input(&expect_sent_packet!(socket_z.poll_event()));
        socket_z.handle_input(&data1);
        // A <- SACK <- Z
        socket_a.handle_input(&expect_sent_packet!(socket_z.poll_event()));
        socket_z.handle_input(&data2);
        assert_eq!(socket_z.get_next_message().unwrap().ppid, PpId(53));
        socket_z.handle_input(&data3);
        assert_eq!(socket_z.get_next_message().unwrap().ppid, PpId(54));
        // A <- SACK <- Z
        socket_a.handle_input(&expect_sent_packet!(socket_z.poll_event()));

        // Z sent "in progress", which will make A buffer packets until it's sure that the
        // reconfiguration has been applied. A will retry - wait for that.
        socket_a.advance_time(SocketTime::from(options.rto_initial));

        let packet = expect_sent_packet!(socket_a.poll_event());
        assert!(matches!(
            SctpPacket::from_bytes(&packet, &options).unwrap().chunks[0],
            Chunk::ReConfig(_)
        ));
        socket_z.handle_input(&packet);

        expect_on_incoming_stream_reset!(socket_z.poll_event());

        let packet = expect_sent_packet!(socket_z.poll_event());
        assert!(matches!(
            SctpPacket::from_bytes(&packet, &options).unwrap().chunks[0],
            Chunk::ReConfig(_)
        ));
        socket_a.handle_input(&packet);

        expect_on_streams_reset_performed!(socket_a.poll_event());

        // Send a new message after the stream has been reset.
        socket_a.send(Message::new(StreamId(1), PpId(55), vec![0; 100]), &SendOptions::default());
        exchange_packets(&mut socket_a, &mut socket_z);

        assert_eq!(socket_z.get_next_message().unwrap().ppid, PpId(55));
        assert!(socket_z.get_next_message().is_none());
    }

    #[test]
    fn reset_streams_with_paused_sender_resumes_when_performed() {
        let options = default_options();
        let mut socket_a = Socket::new("A", &options);
        let mut socket_z = Socket::new("Z", &options);
        connect_sockets(&mut socket_a, &mut socket_z);

        // Guaranteed to be fragmented into two fragments.
        socket_a.send(
            Message::new(StreamId(1), PpId(51), vec![0; options.mtu + 10]),
            &SendOptions::default(),
        );
        socket_a.reset_streams(&[StreamId(1)]);

        // Will be queued, as the stream has an outstanding reset operation.
        socket_a.send(Message::new(StreamId(1), PpId(52), vec![0; 10]), &SendOptions::default());

        let (mut events_a, mut events_z) = exchange_packets(&mut socket_a, &mut socket_z);

        assert_eq!(socket_z.get_next_message().unwrap().ppid, PpId(51));
        expect_on_streams_reset_performed!(events_a.pop_front());
        expect_on_incoming_stream_reset!(events_z.pop_front());
        assert_eq!(socket_z.get_next_message().unwrap().ppid, PpId(52));
    }

    #[test]
    fn zero_checksum_metrics_are_set() {
        for (a_enable, z_enable) in [(false, false), (false, true), (true, false), (true, true)] {
            let options_a = Options {
                zero_checksum_alternate_error_detection_method: match a_enable {
                    true => ZERO_CHECKSUM_ALTERNATE_ERROR_DETECTION_METHOD_LOWER_LAYER_DTLS,
                    false => ZERO_CHECKSUM_ALTERNATE_ERROR_DETECTION_METHOD_NONE,
                },
                ..default_options()
            };
            let options_z = Options {
                zero_checksum_alternate_error_detection_method: match z_enable {
                    true => ZERO_CHECKSUM_ALTERNATE_ERROR_DETECTION_METHOD_LOWER_LAYER_DTLS,
                    false => ZERO_CHECKSUM_ALTERNATE_ERROR_DETECTION_METHOD_NONE,
                },
                ..default_options()
            };

            let mut socket_a = Socket::new("A", &options_a);
            let mut socket_z = Socket::new("Z", &options_z);
            connect_sockets(&mut socket_a, &mut socket_z);

            let metrics = socket_a.get_metrics().unwrap();
            assert_eq!(metrics.uses_zero_checksum, a_enable && z_enable);

            let metrics = socket_z.get_metrics().unwrap();
            assert_eq!(metrics.uses_zero_checksum, a_enable && z_enable);
        }
    }

    #[test]
    fn always_sends_init_with_non_zero_checksum() {
        let options = Options {
            zero_checksum_alternate_error_detection_method:
                ZERO_CHECKSUM_ALTERNATE_ERROR_DETECTION_METHOD_LOWER_LAYER_DTLS,
            ..default_options()
        };
        let mut socket_a = Socket::new("A", &options);
        socket_a.connect();
        // A -> INIT -> Z
        let packet = expect_sent_packet!(socket_a.poll_event());
        let packet = SctpPacket::from_bytes(&packet, &options).unwrap();
        assert_ne!(packet.common_header.checksum, 0);
    }

    #[test]
    fn may_send_init_ack_with_zero_checksum() {
        let options = Options {
            zero_checksum_alternate_error_detection_method:
                ZERO_CHECKSUM_ALTERNATE_ERROR_DETECTION_METHOD_LOWER_LAYER_DTLS,
            ..default_options()
        };
        let mut socket_a = Socket::new("A", &options);
        let mut socket_z = Socket::new("Z", &options);
        socket_a.connect();
        // A -> INIT -> Z
        socket_z.handle_input(&expect_sent_packet!(socket_a.poll_event()));

        // A <- INIT_ACK <- Z
        let packet = expect_sent_packet!(socket_z.poll_event());
        let packet = SctpPacket::from_bytes(&packet, &options).unwrap();
        assert_eq!(packet.common_header.checksum, 0);
    }

    #[test]
    fn always_sends_cookie_echo_with_non_zero_checksum() {
        let options = Options {
            zero_checksum_alternate_error_detection_method:
                ZERO_CHECKSUM_ALTERNATE_ERROR_DETECTION_METHOD_LOWER_LAYER_DTLS,
            ..default_options()
        };
        let mut socket_a = Socket::new("A", &options);
        let mut socket_z = Socket::new("Z", &options);
        socket_a.connect();
        // A -> INIT -> Z
        socket_z.handle_input(&expect_sent_packet!(socket_a.poll_event()));
        // A <- INIT_ACK <- Z
        socket_a.handle_input(&expect_sent_packet!(socket_z.poll_event()));

        // A -> COOKIE_ECHO -> Z
        let packet = expect_sent_packet!(socket_a.poll_event());
        let packet = SctpPacket::from_bytes(&packet, &options).unwrap();
        assert_ne!(packet.common_header.checksum, 0);
    }

    #[test]
    fn sends_cookie_ack_with_zero_checksum() {
        let options = Options {
            zero_checksum_alternate_error_detection_method:
                ZERO_CHECKSUM_ALTERNATE_ERROR_DETECTION_METHOD_LOWER_LAYER_DTLS,
            ..default_options()
        };
        let mut socket_a = Socket::new("A", &options);
        let mut socket_z = Socket::new("Z", &options);
        socket_a.connect();
        // A -> INIT -> Z
        socket_z.handle_input(&expect_sent_packet!(socket_a.poll_event()));
        // A <- INIT_ACK <- Z
        socket_a.handle_input(&expect_sent_packet!(socket_z.poll_event()));
        // A -> COOKIE_ECHO -> Z
        socket_z.handle_input(&expect_sent_packet!(socket_a.poll_event()));
        expect_on_connected!(socket_z.poll_event());

        // A <- COOOKIE_ACK <- Z
        let packet = expect_sent_packet!(socket_z.poll_event());
        let packet = SctpPacket::from_bytes(&packet, &options).unwrap();
        assert_eq!(packet.common_header.checksum, 0);
    }

    #[test]
    fn sends_data_with_zero_checksum() {
        let options = Options {
            zero_checksum_alternate_error_detection_method:
                ZERO_CHECKSUM_ALTERNATE_ERROR_DETECTION_METHOD_LOWER_LAYER_DTLS,
            ..default_options()
        };
        let mut socket_a = Socket::new("A", &options);
        let mut socket_z = Socket::new("Z", &options);
        connect_sockets(&mut socket_a, &mut socket_z);

        socket_a.send(Message::new(StreamId(1), PpId(53), vec![1, 2]), &SendOptions::default());

        let packet = expect_sent_packet!(socket_a.poll_event());
        let packet = SctpPacket::from_bytes(&packet, &options).unwrap();
        assert_eq!(packet.common_header.checksum, 0);
    }

    #[test]
    fn all_packets_after_connect_have_zero_checksum() {
        let options = Options {
            zero_checksum_alternate_error_detection_method:
                ZERO_CHECKSUM_ALTERNATE_ERROR_DETECTION_METHOD_LOWER_LAYER_DTLS,
            ..default_options()
        };
        let mut socket_a = Socket::new("A", &options);
        let mut socket_z = Socket::new("Z", &options);
        connect_sockets(&mut socket_a, &mut socket_z);

        socket_a.send(
            Message::new(StreamId(1), PpId(53), vec![0; options.mtu * 10]),
            &SendOptions::default(),
        );
        socket_z.send(
            Message::new(StreamId(1), PpId(53), vec![0; options.mtu * 10]),
            &SendOptions::default(),
        );

        loop {
            if let Some(e) = socket_a.poll_event() {
                if let SocketEvent::SendPacket(ref send) = e {
                    let packet = SctpPacket::from_bytes(send, &options).unwrap();
                    assert_eq!(packet.common_header.checksum, 0);
                    socket_z.handle_input(send);
                }
                continue;
            }
            if let Some(e) = socket_z.poll_event() {
                if let SocketEvent::SendPacket(ref send) = e {
                    let packet = SctpPacket::from_bytes(send, &options).unwrap();
                    assert_eq!(packet.common_header.checksum, 0);
                    socket_a.handle_input(send);
                }
                continue;
            }
            break;
        }
    }

    #[test]
    fn handles_forward_tsn_out_of_order_with_stream_resetting() {
        let options = default_options();
        let mut now = SocketTime::zero();
        let mut socket_a = Socket::new("A", &options);
        let mut socket_z = Socket::new("Z", &options);
        connect_sockets(&mut socket_a, &mut socket_z);

        socket_a.send(
            Message::new(StreamId(1), PpId(51), vec![0; 10]),
            &SendOptions { max_retransmissions: Some(0), ..SendOptions::default() },
        );

        // Packet is lost.
        expect_sent_packet!(socket_a.poll_event());

        now = now + options.rto_initial;
        socket_a.advance_time(now);
        socket_z.advance_time(now);

        let fwd_tsn_packet = expect_sent_packet!(socket_a.poll_event());
        assert!(matches!(
            SctpPacket::from_bytes(&fwd_tsn_packet, &options).unwrap().chunks[0],
            Chunk::ForwardTsn(_)
        ));

        // Reset stream 1
        socket_a.reset_streams(&[StreamId(1)]);
        let reconfig_packet = expect_sent_packet!(socket_a.poll_event());
        assert!(matches!(
            SctpPacket::from_bytes(&reconfig_packet, &options).unwrap().chunks[0],
            Chunk::ReConfig(_)
        ));

        // These two packets are received in the wrong order.
        socket_z.handle_input(&reconfig_packet);
        socket_z.handle_input(&fwd_tsn_packet);
        exchange_packets(&mut socket_a, &mut socket_z);

        // Send two more messages.
        socket_a.send(Message::new(StreamId(1), PpId(52), vec![0; 10]), &SendOptions::default());
        socket_a.send(Message::new(StreamId(1), PpId(53), vec![0; 10]), &SendOptions::default());

        let data_packet = expect_sent_packet!(socket_a.poll_event());
        socket_z.handle_input(&data_packet);
        let data_packet = SctpPacket::from_bytes(&data_packet, &options).unwrap();
        let Chunk::Data(c) = &data_packet.chunks[0] else {
            panic!();
        };
        assert_eq!(c.data.ssn, Ssn(0));
        assert_eq!(c.data.ppid, PpId(52));

        let data_packet = expect_sent_packet!(socket_a.poll_event());
        socket_z.handle_input(&data_packet);
        let data_packet = SctpPacket::from_bytes(&data_packet, &options).unwrap();
        let Chunk::Data(c) = &data_packet.chunks[0] else {
            panic!();
        };
        assert_eq!(c.data.ssn, Ssn(1));
        assert_eq!(c.data.ppid, PpId(53));

        exchange_packets(&mut socket_a, &mut socket_z);

        assert_eq!(socket_z.messages_ready_count(), 2);
        assert_eq!(socket_z.get_next_message().unwrap().ppid, PpId(52));
        assert_eq!(socket_z.get_next_message().unwrap().ppid, PpId(53));
    }

    #[test]
    fn resent_init_has_same_parameters() {
        let options = default_options();
        let mut socket_a = Socket::new("A", &options);

        socket_a.connect();
        // A -> INIT -> Z
        let packet1 = expect_sent_packet!(socket_a.poll_event());
        expect_no_event!(socket_a.poll_event());

        let now = socket_a.poll_timeout();
        socket_a.advance_time(now);

        let packet2 = expect_sent_packet!(socket_a.poll_event());
        expect_no_event!(socket_a.poll_event());

        let packet1 = SctpPacket::from_bytes(&packet1, &options).unwrap();
        let packet2 = SctpPacket::from_bytes(&packet2, &options).unwrap();

        let Chunk::Init(init1) = &packet1.chunks[0] else { unreachable!() };
        let Chunk::Init(init2) = &packet2.chunks[0] else { unreachable!() };
        assert_eq!(init1.initial_tsn, init2.initial_tsn);
        assert_eq!(init1.initiate_tag, init2.initiate_tag);
    }

    #[test]
    fn resent_init_ack_has_different_parameters() {
        let options = default_options();

        let mut socket_a = Socket::new("A", &options);
        let mut socket_z = Socket::new("Z", &options);

        socket_a.connect();
        // A -> INIT -> Z
        let first_packet = expect_sent_packet!(socket_a.poll_event());
        socket_z.handle_input(&first_packet);
        // A <- INIT_ACK <- Z
        let init_ack_packet1 = expect_sent_packet!(socket_z.poll_event());
        expect_no_event!(socket_z.poll_event());

        // Get another INIT_ACK;
        socket_z.handle_input(&first_packet);
        let init_ack_packet2 = expect_sent_packet!(socket_z.poll_event());
        expect_no_event!(socket_z.poll_event());

        let packet1 = SctpPacket::from_bytes(&init_ack_packet1, &options).unwrap();
        let packet2 = SctpPacket::from_bytes(&init_ack_packet2, &options).unwrap();

        let Chunk::InitAck(init_ack1) = &packet1.chunks[0] else { unreachable!() };
        let Chunk::InitAck(init_ack2) = &packet2.chunks[0] else { unreachable!() };
        assert_ne!(init_ack1.initial_tsn, init_ack2.initial_tsn);
        assert_ne!(init_ack1.initiate_tag, init_ack2.initiate_tag);
    }

    #[test]
    fn connection_can_continue_from_first_init_ack() {
        let options = default_options();

        let mut socket_a = Socket::new("A", &options);
        let mut socket_z = Socket::new("Z", &options);

        let payload: Vec<u8> = vec![0; options.mtu + 20];
        socket_a
            .send(Message::new(StreamId(1), PpId(53), payload.clone()), &SendOptions::default());

        socket_a.connect();
        // A -> INIT -> Z
        let init_packet = expect_sent_packet!(socket_a.poll_event());
        // Extract two INIT-ACKs.
        socket_z.handle_input(&init_packet);
        let init_ack_packet1 = expect_sent_packet!(socket_z.poll_event());
        socket_z.handle_input(&init_packet);
        let init_ack_packet2 = expect_sent_packet!(socket_z.poll_event());
        assert_ne!(init_ack_packet1, init_ack_packet2);

        // A <- INIT_ACK <- Z
        socket_a.handle_input(&init_ack_packet1);

        let (events_a, events_z) = exchange_packets(&mut socket_a, &mut socket_z);
        assert!(events_a.iter().any(|e| matches!(e, SocketEvent::OnConnected(..))));
        assert!(events_z.iter().any(|e| matches!(e, SocketEvent::OnConnected(..))));

        let message = socket_z.get_next_message().unwrap();
        assert_eq!(message.stream_id, StreamId(1));
        assert_eq!(message.payload, payload);
    }

    #[test]
    fn connection_can_continue_from_second_init_ack() {
        let options = default_options();

        let mut socket_a = Socket::new("A", &options);
        let mut socket_z = Socket::new("Z", &options);

        let payload: Vec<u8> = vec![0; options.mtu + 20];
        socket_a
            .send(Message::new(StreamId(1), PpId(53), payload.clone()), &SendOptions::default());

        socket_a.connect();
        // A -> INIT -> Z
        let init_packet = expect_sent_packet!(socket_a.poll_event());
        // Extract two INIT-ACKs.
        socket_z.handle_input(&init_packet);
        let init_ack_packet1 = expect_sent_packet!(socket_z.poll_event());
        socket_z.handle_input(&init_packet);
        let init_ack_packet2 = expect_sent_packet!(socket_z.poll_event());
        assert_ne!(init_ack_packet1, init_ack_packet2);

        // A <- INIT_ACK <- Z
        socket_a.handle_input(&init_ack_packet2);

        let (events_a, events_z) = exchange_packets(&mut socket_a, &mut socket_z);
        assert!(events_a.iter().any(|e| matches!(e, SocketEvent::OnConnected(..))));
        assert!(events_z.iter().any(|e| matches!(e, SocketEvent::OnConnected(..))));

        let message = socket_z.get_next_message().unwrap();
        assert_eq!(message.stream_id, StreamId(1));
        assert_eq!(message.payload, payload);
        assert!(socket_z.get_next_message().is_none());
    }

    #[test]
    fn handover_preserves_stream_reset_state() {
        let options = default_options();
        let mut socket_a1 = Socket::new("A1", &options);
        let mut socket_z = Socket::new("Z", &options);
        connect_sockets(&mut socket_a1, &mut socket_z);

        // 1. Z resets stream 1. A1 processes it.
        socket_z.reset_streams(&[StreamId(1)]);
        // Z -> RECONFIG -> A1
        socket_a1.handle_input(&expect_sent_packet!(socket_z.poll_event()));
        let streams = expect_on_incoming_stream_reset!(socket_a1.poll_event());
        assert_eq!(streams, &[StreamId(1)]);
        // Z <- RECONFIG (Response) <- A1
        socket_z.handle_input(&expect_sent_packet!(socket_a1.poll_event()));
        let streams = expect_on_streams_reset_performed!(socket_z.poll_event());
        assert_eq!(streams, &[StreamId(1)]);

        // 2. A1 resets stream 1. Z processes it.
        socket_a1.reset_streams(&[StreamId(1)]);
        // A1 -> RECONFIG -> Z
        socket_z.handle_input(&expect_sent_packet!(socket_a1.poll_event()));
        let streams = expect_on_incoming_stream_reset!(socket_z.poll_event());
        assert_eq!(streams, &[StreamId(1)]);
        // A1 <- RECONFIG (Response) <- Z
        socket_a1.handle_input(&expect_sent_packet!(socket_z.poll_event()));
        let streams = expect_on_streams_reset_performed!(socket_a1.poll_event());
        assert_eq!(streams, &[StreamId(1)]);

        // Handover A1 -> A2
        let mut socket_a2 = Socket::new("A2", &options);
        handover_socket(&mut socket_a1, &mut socket_a2);

        // 3. Verify A2 has correct next outgoing sequence number.
        // A2 resets stream 2.
        // If A2 lost state, it would reuse the old sequence number, which Z would treat as a
        // retransmission (and thus NOT trigger on_incoming_stream_reset).
        socket_a2.reset_streams(&[StreamId(2)]);
        // A2 -> RECONFIG -> Z
        socket_z.handle_input(&expect_sent_packet!(socket_a2.poll_event()));
        let streams = expect_on_incoming_stream_reset!(socket_z.poll_event());
        assert_eq!(streams, &[StreamId(2)]);
        // A2 <- RECONFIG (Response) <- Z
        socket_a2.handle_input(&expect_sent_packet!(socket_z.poll_event()));
        let streams = expect_on_streams_reset_performed!(socket_a2.poll_event());
        assert_eq!(streams, &[StreamId(2)]);

        // 4. Verify A2 has correct last processed sequence number.
        // Z resets stream 2.
        // If A2 lost state, it would see a gap in sequence numbers (expecting initial, getting
        // initial+1), and would return an error.
        socket_z.reset_streams(&[StreamId(2)]);
        // Z -> RECONFIG -> A2
        socket_a2.handle_input(&expect_sent_packet!(socket_z.poll_event()));
        let streams = expect_on_incoming_stream_reset!(socket_a2.poll_event());
        assert_eq!(streams, &[StreamId(2)]);
        // Z <- RECONFIG (Response) <- A2
        socket_z.handle_input(&expect_sent_packet!(socket_a2.poll_event()));
        let streams = expect_on_streams_reset_performed!(socket_z.poll_event());
        assert_eq!(streams, &[StreamId(2)]);
    }

    #[test]
    fn establish_simultaneous_connection_with_lost_data() {
        let options = default_options();
        let mut socket_a = Socket::new("A", &options);
        let mut socket_z = Socket::new("Z", &options);

        // Queue data on A
        socket_a
            .send(Message::new(StreamId(1), PpId(1), b"hello".to_vec()), &SendOptions::default());

        socket_a.connect();
        socket_z.connect();

        // A -> INIT -> Z
        let packet_a_init = expect_sent_packet!(socket_a.poll_event());
        // Z -> INIT -> A
        let packet_z_init = expect_sent_packet!(socket_z.poll_event());

        // A <- INIT
        socket_a.handle_input(&packet_z_init);
        // A -> INIT_ACK
        let packet_a_init_ack = expect_sent_packet!(socket_a.poll_event());

        // Z <- INIT
        socket_z.handle_input(&packet_a_init);
        // Z -> INIT_ACK
        let packet_z_init_ack = expect_sent_packet!(socket_z.poll_event());

        // A <- INIT_ACK
        socket_a.handle_input(&packet_z_init_ack);
        // A -> COOKIE_ECHO + DATA.
        let packet_a_cookie_echo = expect_sent_packet!(socket_a.poll_event());
        // Verify it contains DATA
        let packet = SctpPacket::from_bytes(&packet_a_cookie_echo, &options).unwrap();
        assert!(packet.chunks.iter().any(|c| matches!(c, Chunk::Data(_))));

        // DROP packet_a_cookie_echo. Z does not receive it.

        // Z <- INIT_ACK
        socket_z.handle_input(&packet_a_init_ack);
        // Z -> COOKIE_ECHO
        let packet_z_cookie_echo = expect_sent_packet!(socket_z.poll_event());

        // A <- COOKIE_ECHO. A should enter Established.
        socket_a.handle_input(&packet_z_cookie_echo);
        expect_on_connected!(socket_a.poll_event());
        // A -> COOKIE_ACK
        let packet_a_cookie_ack = expect_sent_packet!(socket_a.poll_event());

        // Z <- COOKIE_ACK. Z should enter Established.
        socket_z.handle_input(&packet_a_cookie_ack);
        expect_on_connected!(socket_z.poll_event());

        // Now A should retransmit the lost DATA after RTO.
        let timeout = socket_a.poll_timeout();
        assert_ne!(timeout, SocketTime::infinite_future());
        socket_a.advance_time(timeout);

        // A -> DATA (Retransmission)
        let packet_retransmit = expect_sent_packet!(socket_a.poll_event());
        let packet = SctpPacket::from_bytes(&packet_retransmit, &options).unwrap();
        assert!(packet.chunks.iter().any(|c| matches!(c, Chunk::Data(_))));

        // Z <- DATA
        socket_z.handle_input(&packet_retransmit);

        // Z should have received the message
        let msg = socket_z.get_next_message().unwrap();
        assert_eq!(msg.payload, b"hello");
    }
}
