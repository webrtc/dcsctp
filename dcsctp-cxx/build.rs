fn main() {
    cxx_build::bridge("src/lib.rs").file("src/lib.cpp").std("c++14").compile("dcsctp-cxx");

    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=src/lib.cpp");
    println!("cargo:rerun-if-changed=include/dcsctp.h");
}
