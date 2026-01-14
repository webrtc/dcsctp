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

#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "../../target/cxxbridge/dcsctp/src/ffi.rs.h"

// Exchanges all packets between two sockets until there are no more packets to
// exchange. All other events are collected and returned.
std::pair<std::vector<dcsctp_cxx::Event>, std::vector<dcsctp_cxx::Event>>
exchange_packets(dcsctp_cxx::DcSctpSocket& socket_a,
                 dcsctp_cxx::DcSctpSocket& socket_z) {
  std::vector<dcsctp_cxx::Event> events_a;
  std::vector<dcsctp_cxx::Event> events_z;

  while (true) {
    bool again = false;

    while (true) {
      dcsctp_cxx::Event ev_a = dcsctp_cxx::poll_event(socket_a);
      if (ev_a.event_type == dcsctp_cxx::EventType::Nothing) {
        break;
      }
      again = true;
      if (ev_a.event_type == dcsctp_cxx::EventType::SendPacket) {
        std::cout << "A -> Z (size: " << ev_a.packet.size() << ")" << std::endl;
        dcsctp_cxx::handle_input(socket_z,
                                 {ev_a.packet.data(), ev_a.packet.size()});
      } else {
        events_a.push_back(std::move(ev_a));
      }
    }

    while (true) {
      dcsctp_cxx::Event ev_z = dcsctp_cxx::poll_event(socket_z);
      if (ev_z.event_type == dcsctp_cxx::EventType::Nothing) {
        break;
      }
      again = true;
      if (ev_z.event_type == dcsctp_cxx::EventType::SendPacket) {
        std::cout << "Z -> A (size: " << ev_z.packet.size() << ")" << std::endl;
        dcsctp_cxx::handle_input(socket_a,
                                 {ev_z.packet.data(), ev_z.packet.size()});
      } else {
        events_z.push_back(std::move(ev_z));
      }
    }

    if (!again) {
      break;
    }
  }
  return {std::move(events_a), std::move(events_z)};
}

int main() {
  std::cout << "dcsctp version: " << dcsctp_cxx::version().c_str() << std::endl;

  dcsctp_cxx::Options options = dcsctp_cxx::default_options();
  options.heartbeat_interval = 0;

  dcsctp_cxx::SendOptions default_send_options = dcsctp_cxx::new_send_options();

  dcsctp_cxx::DcSctpSocket* socket_a = dcsctp_cxx::new_socket("a", options);
  dcsctp_cxx::DcSctpSocket* socket_z = dcsctp_cxx::new_socket("z", options);
  std::cout << "Created two sockets: A and Z" << std::endl;

  try {
    dcsctp_cxx::connect(*socket_a);

    exchange_packets(*socket_a, *socket_z);

    if (dcsctp_cxx::state(*socket_a) == dcsctp_cxx::SocketState::Connected &&
        dcsctp_cxx::state(*socket_z) == dcsctp_cxx::SocketState::Connected) {
      std::cout << "Both sockets connected successfully!" << std::endl;
    } else {
      std::cout << "Connection failed: sockets are not in Connected state."
                << std::endl;
      return 1;
    }

    // A -> "Hello Z" -> Z
    std::cout << "A: sending 'Hello Z'" << std::endl;
    std::string msg_a_to_z_str = "Hello Z";
    dcsctp_cxx::Message msg_a_to_z = dcsctp_cxx::create_message(
        /*stream_id=*/0, /*ppid=*/53, msg_a_to_z_str.length());
    std::copy(msg_a_to_z_str.begin(), msg_a_to_z_str.end(),
              msg_a_to_z.payload.begin());

    dcsctp_cxx::SendStatus send_status = dcsctp_cxx::send(
        *socket_a, std::move(msg_a_to_z), default_send_options);
    if (send_status != dcsctp_cxx::SendStatus::Success) {
      throw std::runtime_error("Failed to send message from A to Z");
    }

    exchange_packets(*socket_a, *socket_z);

    if (dcsctp_cxx::message_ready_count(*socket_z) != 1) {
      throw std::runtime_error("Z did not receive the message from A");
    }

    dcsctp_cxx::Message received_msg_z =
        dcsctp_cxx::get_next_message(*socket_z);
    std::string received_payload_z(
        reinterpret_cast<const char*>(received_msg_z.payload.data()),
        received_msg_z.payload.size());

    std::cout << "Z: received message '" << received_payload_z << "' on stream "
              << received_msg_z.stream_id << " with ppid "
              << received_msg_z.ppid << std::endl;

    if (received_payload_z != msg_a_to_z_str) {
      throw std::runtime_error("Z received wrong message from A");
    }

    // Z -> "Hello A" -> A
    std::cout << "Z: sending 'Hello A'" << std::endl;
    std::string msg_z_to_a_str = "Hello A";
    auto msg_z_to_a =
        dcsctp_cxx::create_message(1, 53, msg_z_to_a_str.length());
    std::copy(msg_z_to_a_str.begin(), msg_z_to_a_str.end(),
              msg_z_to_a.payload.begin());

    send_status = dcsctp_cxx::send(*socket_z, std::move(msg_z_to_a),
                                   default_send_options);
    if (send_status != dcsctp_cxx::SendStatus::Success) {
      throw std::runtime_error("Failed to send message from Z to A");
    }

    exchange_packets(*socket_a, *socket_z);

    if (dcsctp_cxx::message_ready_count(*socket_a) != 1) {
      throw std::runtime_error("A did not receive the message from Z");
    }

    dcsctp_cxx::Message received_msg_a =
        dcsctp_cxx::get_next_message(*socket_a);
    std::string received_payload_a(
        reinterpret_cast<const char*>(received_msg_a.payload.data()),
        received_msg_a.payload.size());

    std::cout << "A: received message '" << received_payload_a << "' on stream "
              << received_msg_a.stream_id << " with ppid "
              << received_msg_a.ppid << std::endl;

    if (received_payload_a != msg_z_to_a_str) {
      throw std::runtime_error("A received wrong message from Z");
    }

    // Handover Z -> Z2
    std::cout << "Performing handover of Z to Z2..." << std::endl;
    dcsctp_cxx::DcSctpSocket* socket_z2 = dcsctp_cxx::new_socket("z2", options);

    uint32_t readiness = dcsctp_cxx::get_handover_readiness(*socket_z);
    if (readiness != 0) {
      throw std::runtime_error("Socket Z is not ready for handover");
    }

    dcsctp_cxx::SocketHandoverState state =
        dcsctp_cxx::get_handover_state_and_close(*socket_z);
    if (!state.has_value) {
      throw std::runtime_error("Failed to get handover state from Z");
    }

    dcsctp_cxx::restore_from_state(*socket_z2, state);

    if (dcsctp_cxx::state(*socket_z2) == dcsctp_cxx::SocketState::Connected) {
      std::cout << "Socket Z2 restored and connected!" << std::endl;
    } else {
      throw std::runtime_error(
          "Socket Z2 failed to restore to Connected state");
    }

    // A -> "Hello Z2" -> Z2
    std::cout << "A: sending 'Hello Z2'" << std::endl;
    std::string msg_a_to_z2_str = "Hello Z2";
    auto msg_a_to_z2 =
        dcsctp_cxx::create_message(1, 53, msg_a_to_z2_str.length());
    std::copy(msg_a_to_z2_str.begin(), msg_a_to_z2_str.end(),
              msg_a_to_z2.payload.begin());

    send_status = dcsctp_cxx::send(*socket_a, std::move(msg_a_to_z2),
                                   default_send_options);
    if (send_status != dcsctp_cxx::SendStatus::Success) {
      throw std::runtime_error("Failed to send message from A to Z2");
    }

    exchange_packets(*socket_a, *socket_z2);

    if (dcsctp_cxx::message_ready_count(*socket_z2) != 1) {
      throw std::runtime_error("Z2 did not receive the message from A");
    }

    dcsctp_cxx::Message received_msg_z2 =
        dcsctp_cxx::get_next_message(*socket_z2);
    std::string received_payload_z2(
        reinterpret_cast<const char*>(received_msg_z2.payload.data()),
        received_msg_z2.payload.size());

    std::cout << "Z2: received message '" << received_payload_z2
              << "' on stream " << received_msg_z2.stream_id << " with ppid "
              << received_msg_z2.ppid << std::endl;

    if (received_payload_z2 != msg_a_to_z2_str) {
      throw std::runtime_error("Z2 received wrong message from A");
    }

    dcsctp_cxx::delete_socket(socket_z2);

  } catch (const std::runtime_error& e) {
    std::cerr << "Caught an exception: " << e.what() << std::endl;
    return 1;
  }

  std::cout << "Sockets are about to be deleted." << std::endl;
  dcsctp_cxx::delete_socket(socket_a);
  dcsctp_cxx::delete_socket(socket_z);
  return 0;
}
