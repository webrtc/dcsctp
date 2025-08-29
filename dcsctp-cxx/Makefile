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
