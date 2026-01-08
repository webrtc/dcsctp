# Copyright 2025 The dcSCTP Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

.PHONY: all clean

CC = $(CXX)
CXX = c++
CXXFLAGS = -std=c++14

GEN_DIR := ../../target
GEN_HEADER := $(GEN_DIR)/cxxbridge/dcsctp/src/ffi.rs.h
GEN_LIB := $(GEN_DIR)/debug/libdcsctp.a
GEN_FILES := \
	$(GEN_DIR)/cxxbridge/dcsctp/src/ffi.rs.cc \
	$(GEN_HEADER) \
	$(GEN_LIB)

all: main

$(GEN_FILES): ../../src/ffi.rs ../../Cargo.toml
	cargo build --features cxx

main.o: main.cc $(GEN_HEADER)

main: main.o $(GEN_LIB)

clean:
	cargo clean
	rm -f *.o main
