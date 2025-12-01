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

#include "dcsctp.h"

#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>

// Polls for the next event and expects it to be a SendPacket.
// Returns the packet payload. Throws a runtime_error if the event is not a
// SendPacket.
rust::Vec<uint8_t> expect_send_packet(dcsctp_cxx::DcSctpSocket& socket,
                                      const std::string& socket_name) {
  dcsctp_cxx::Event event = dcsctp_cxx::poll_event(socket);
  if (event.event_type != dcsctp_cxx::EventType::SendPacket) {
    throw std::runtime_error("Expected SendPacket from " + socket_name +
                             ", but got something else.");
  }
  std::cout << "Polled SendPacket from " << socket_name
            << " (size: " << event.packet.size() << ")" << std::endl;
  return event.packet;
}

// Polls for the next event and expects it to be OnConnected.
// Throws a runtime_error if the event is not OnConnected.
void expect_on_connected(dcsctp_cxx::DcSctpSocket& socket,
                         const std::string& socket_name) {
  dcsctp_cxx::Event event = dcsctp_cxx::poll_event(socket);
  if (event.event_type != dcsctp_cxx::EventType::OnConnected) {
    throw std::runtime_error("Expected OnConnected from " + socket_name +
                             ", but got something else.");
  }
  std::cout << "Polled OnConnected from " << socket_name << std::endl;
}

// Polls for the next event and expects it to be Nothing.
void expect_no_event(dcsctp_cxx::DcSctpSocket& socket,
                     const std::string& socket_name) {
  dcsctp_cxx::Event event = dcsctp_cxx::poll_event(socket);
  if (event.event_type != dcsctp_cxx::EventType::Nothing) {
    throw std::runtime_error("Expected Nothing from " + socket_name +
                             ", but got something else.");
  }
}

int main() {
  std::cout << "dcsctp version: " << dcsctp_cxx::version().c_str() << std::endl;

  dcsctp_cxx::DcSctpSocket* socket_a = dcsctp_cxx::new_socket();
  dcsctp_cxx::DcSctpSocket* socket_z = dcsctp_cxx::new_socket();
  std::cout << "Created two sockets: A and Z" << std::endl;

  try {
    dcsctp_cxx::connect(*socket_a);

    // A -> INIT -> Z
    rust::Vec<uint8_t> init_packet = expect_send_packet(*socket_a, "A");
    dcsctp_cxx::handle_input(*socket_z,
                             {init_packet.data(), init_packet.size()});

    // A <- INIT_ACK <- Z
    rust::Vec<uint8_t> init_ack_packet = expect_send_packet(*socket_z, "Z");
    dcsctp_cxx::handle_input(*socket_a, {init_ack_packet.data(),
                                         init_ack_packet.size()});

    // A -> COOKIE_ECHO -> Z
    rust::Vec<uint8_t> cookie_echo_packet = expect_send_packet(*socket_a, "A");
    dcsctp_cxx::handle_input(
        *socket_z, {cookie_echo_packet.data(), cookie_echo_packet.size()});

    // Z becomes connected
    expect_on_connected(*socket_z, "Z");

    // A <- COOKIE_ACK <- Z
    rust::Vec<uint8_t> cookie_ack_packet = expect_send_packet(*socket_z, "Z");
    dcsctp_cxx::handle_input(
        *socket_a, {cookie_ack_packet.data(), cookie_ack_packet.size()});

    // A becomes connected
    expect_on_connected(*socket_a, "A");

    expect_no_event(*socket_a, "A");
    expect_no_event(*socket_z, "Z");

    if (dcsctp_cxx::state(*socket_a) == dcsctp_cxx::SocketState::Connected &&
        dcsctp_cxx::state(*socket_z) == dcsctp_cxx::SocketState::Connected) {
      std::cout << "Both sockets connected successfully!" << std::endl;
    } else {
      std::cout << "Connection failed: sockets are not in Connected state."
                << std::endl;
      return 1;
    }

  } catch (const std::runtime_error& e) {
    std::cerr << "Caught an exception: " << e.what() << std::endl;
    return 1;
  }

  std::cout << "Sockets are about to be deleted." << std::endl;
  dcsctp_cxx::delete_socket(socket_a);
  dcsctp_cxx::delete_socket(socket_z);
  return 0;
}
