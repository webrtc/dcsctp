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

use crate::api::DcSctpSocket;
use crate::api::Options;

pub mod api;

pub(crate) mod events;
pub(crate) mod packet;
pub(crate) mod rx;
pub(crate) mod socket;
pub(crate) mod timer;
pub(crate) mod tx;
pub(crate) mod types;

trait EventSink {
    fn add(&mut self, event: api::SocketEvent);
    fn next_event(&mut self) -> Option<api::SocketEvent>;
}

#[cfg(test)]
pub(crate) mod testing;

/// Returns the version of this crate.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Creates a new `Socket`.
///
/// The provided `name` is only used for logging to identify this socket.
pub fn new_socket(name: &str, options: &Options) -> Box<dyn DcSctpSocket> {
    Box::new(socket::Socket::new(name, options))
}

// Fuzzers, who are defined in a separate crate, need to access internal (non-public) functions that
// they will fuzz. Expose these only for the fuzzing configuration.
#[cfg(feature = "fuzz-internals")]
pub mod fuzzer;

#[cfg(feature = "cxx")]
pub mod ffi;

pub(crate) mod logging {
    #[cfg(not(test))]
    use log::info;
    use std::fmt::Write;
    #[cfg(test)]
    use std::println as info;
    use std::string::String;
    use std::time::Duration;

    pub fn log_packet(name: &str, ts: Duration, sent: bool, data: &[u8]) {
        let s = data.iter().fold(String::new(), |mut output, c| {
            let _ = write!(output, " {c:02x}");
            output
        });
        let prefix = if sent { "O" } else { "I" };
        let mut remaining = (ts.as_millis() % (24 * 60 * 60 * 1000)) as u64;
        let hours = remaining / (60 * 60 * 1000);
        remaining %= 60 * 60 * 1000;
        let minutes = remaining / (60 * 1000);
        remaining %= 60 * 1000;
        let seconds = remaining / 1000;
        let ms = remaining % 1000;
        info!(
            "{} {:02}:{:02}:{:02}.{:03} 0000{} # SCTP_PACKET {}",
            prefix, hours, minutes, seconds, ms, s, name
        );
    }
}

pub(crate) mod math {
    macro_rules! round_up_to_4 {
        ($a: expr) => {
            ($a + 3) & !3
        };
    }

    macro_rules! round_down_to_4 {
        ($a: expr) => {
            $a & !3
        };
    }

    macro_rules! is_divisible_by_4 {
        ($a: expr) => {
            ($a % 4) == 0
        };
    }

    pub(crate) use is_divisible_by_4;
    pub(crate) use round_down_to_4;
    pub(crate) use round_up_to_4;
}

#[cfg(test)]
#[allow(clippy::assertions_on_constants)]
mod tests {
    use crate::math::*;

    #[test]
    fn can_round_up_to_4() {
        // Signed numbers.
        assert_eq!(round_up_to_4!(-5_i32), -4);
        assert_eq!(round_up_to_4!(-4_i32), -4);
        assert_eq!(round_up_to_4!(-3_i32), 0);
        assert_eq!(round_up_to_4!(-2_i32), 0);
        assert_eq!(round_up_to_4!(-1_i32), 0);
        assert_eq!(round_up_to_4!(0_i32), 0);
        assert_eq!(round_up_to_4!(1_i32), 4);
        assert_eq!(round_up_to_4!(2_i32), 4);
        assert_eq!(round_up_to_4!(3_i32), 4);
        assert_eq!(round_up_to_4!(4_i32), 4);
        assert_eq!(round_up_to_4!(5_i32), 8);
        assert_eq!(round_up_to_4!(6_i32), 8);
        assert_eq!(round_up_to_4!(7_i32), 8);
        assert_eq!(round_up_to_4!(8_i32), 8);
        assert_eq!(round_up_to_4!(10000000000_i64), 10000000000);
        assert_eq!(round_up_to_4!(10000000001_i64), 10000000004);

        // Unsigned numbers.
        assert_eq!(round_up_to_4!(0_u32), 0);
        assert_eq!(round_up_to_4!(1_u32), 4);
        assert_eq!(round_up_to_4!(2_u32), 4);
        assert_eq!(round_up_to_4!(3_u32), 4);
        assert_eq!(round_up_to_4!(4_u32), 4);
        assert_eq!(round_up_to_4!(5_u32), 8);
        assert_eq!(round_up_to_4!(6_u32), 8);
        assert_eq!(round_up_to_4!(7_u32), 8);
        assert_eq!(round_up_to_4!(8_u32), 8);
        assert_eq!(round_up_to_4!(10000000000_u64), 10000000000);
        assert_eq!(round_up_to_4!(10000000001_u64), 10000000004);
    }

    #[test]
    fn can_round_down_to_4() {
        // Signed numbers.
        assert_eq!(round_down_to_4!(-5_i32), -8);
        assert_eq!(round_down_to_4!(-4_i32), -4);
        assert_eq!(round_down_to_4!(-3_i32), -4);
        assert_eq!(round_down_to_4!(-2_i32), -4);
        assert_eq!(round_down_to_4!(-1_i32), -4);
        assert_eq!(round_down_to_4!(0_i32), 0);
        assert_eq!(round_down_to_4!(1_i32), 0);
        assert_eq!(round_down_to_4!(2_i32), 0);
        assert_eq!(round_down_to_4!(3_i32), 0);
        assert_eq!(round_down_to_4!(4_i32), 4);
        assert_eq!(round_down_to_4!(5_i32), 4);
        assert_eq!(round_down_to_4!(6_i32), 4);
        assert_eq!(round_down_to_4!(7_i32), 4);
        assert_eq!(round_down_to_4!(8_i32), 8);
        assert_eq!(round_down_to_4!(10000000000_i64), 10000000000);
        assert_eq!(round_down_to_4!(10000000001_i64), 10000000000);

        // Unsigned numbers.
        assert_eq!(round_down_to_4!(0_u32), 0);
        assert_eq!(round_down_to_4!(1_u32), 0);
        assert_eq!(round_down_to_4!(2_u32), 0);
        assert_eq!(round_down_to_4!(3_u32), 0);
        assert_eq!(round_down_to_4!(4_u32), 4);
        assert_eq!(round_down_to_4!(5_u32), 4);
        assert_eq!(round_down_to_4!(6_u32), 4);
        assert_eq!(round_down_to_4!(7_u32), 4);
        assert_eq!(round_down_to_4!(8_u32), 8);
        assert_eq!(round_down_to_4!(10000000000_u64), 10000000000);
        assert_eq!(round_down_to_4!(10000000001_u64), 10000000000);
    }

    #[test]
    fn is_divisible_by_4() {
        // Signed numbers.
        assert!(is_divisible_by_4!(-4_i32));
        assert!(!is_divisible_by_4!(-3_i32));
        assert!(!is_divisible_by_4!(-2_i32));
        assert!(!is_divisible_by_4!(1_i32));
        assert!(is_divisible_by_4!(0_i32));
        assert!(!is_divisible_by_4!(1_i32));
        assert!(!is_divisible_by_4!(2_i32));
        assert!(!is_divisible_by_4!(3_i32));
        assert!(is_divisible_by_4!(4_i32));
        assert!(!is_divisible_by_4!(5_i32));
        assert!(!is_divisible_by_4!(6_i32));
        assert!(!is_divisible_by_4!(7_i32));
        assert!(is_divisible_by_4!(8_i32));
        assert!(is_divisible_by_4!(10000000000_i64));
        assert!(!is_divisible_by_4!(10000000001_i64));

        // Unsigned numbers.
        assert!(is_divisible_by_4!(0_u32));
        assert!(!is_divisible_by_4!(1_u32));
        assert!(!is_divisible_by_4!(2_u32));
        assert!(!is_divisible_by_4!(3_u32));
        assert!(is_divisible_by_4!(4_u32));
        assert!(!is_divisible_by_4!(5_u32));
        assert!(!is_divisible_by_4!(6_u32));
        assert!(!is_divisible_by_4!(7_u32));
        assert!(is_divisible_by_4!(8_u32));
        assert!(is_divisible_by_4!(10000000000_u64));
        assert!(!is_divisible_by_4!(10000000001_u64));
    }
}
