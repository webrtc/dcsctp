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
#include <utility>
#include <vector>

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

  dcsctp_cxx::DcSctpSocket* socket_a = dcsctp_cxx::new_socket();
  dcsctp_cxx::DcSctpSocket* socket_z = dcsctp_cxx::new_socket();
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

  } catch (const std::runtime_error& e) {
    std::cerr << "Caught an exception: " << e.what() << std::endl;
    return 1;
  }

  std::cout << "Sockets are about to be deleted." << std::endl;
  dcsctp_cxx::delete_socket(socket_a);
  dcsctp_cxx::delete_socket(socket_z);
  return 0;
}
