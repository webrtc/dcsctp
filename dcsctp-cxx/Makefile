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

.PHONY: all clean run

all: examples/main

examples/main: examples/main.cpp Cargo.toml src/lib.rs src/lib.cpp include/dcsctp.h
	@echo "Building rust library..."
	@cargo build
	@echo "Building C++ example..."
	@CXX_INCLUDE_PATH=$$(find ../target/debug/build/dcsctp-cxx-*/out/cxxbridge/include -print -quit) && \
	c++ -std=c++14 \
		-Iinclude \
		-I$${CXX_INCLUDE_PATH} \
		examples/main.cpp \
		-o examples/main \
		../target/debug/libdcsctp_cxx.a

run: examples/main
	./examples/main

clean:
	@cargo clean
	@rm -f examples/main
