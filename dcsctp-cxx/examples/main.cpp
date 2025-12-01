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
