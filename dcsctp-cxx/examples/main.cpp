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
#include <iostream>

int main() {
  std::cout << "dcsctp version: " << dcsctp_cxx::version().c_str() << std::endl;

  dcsctp_cxx::DcSctpSocket *socket = dcsctp_cxx::new_socket();

  if (socket) {
    std::cout << "Successfully created a socket." << std::endl;
  } else {
    std::cout << "Failed to create a socket." << std::endl;
    return 1;
  }

  if (dcsctp_cxx::state(*socket) == dcsctp_cxx::SocketState::Closed) {
    std::cout << "Socket is initially closed" << std::endl;
  } else {
    std::cout << "Socket is in an unexpected state" << std::endl;
    return 1;
  }

  std::cout << "Socket is about to be deleted." << std::endl;
  dcsctp_cxx::delete_socket(socket);
  return 0;
}
