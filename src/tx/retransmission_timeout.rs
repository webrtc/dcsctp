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

use crate::api::Options;
use std::time::Duration;

const RTO_ALPHA: f64 = 0.125;
const RTO_BETA: f64 = 0.25;

/// A factor that [`RetransmissionTimeout::min_rtt_variance`] will be divided by (before later
/// multiplied with K, which is 4 according to RFC 6298).
///
/// When this value was introduced, it was unintentionally divided by 8 since that code worked with
/// scaled numbers (to avoid floating point math). That behavior is kept as downstream users have
/// measured good values for their use-cases.
const HEURISTIC_VARIANCE_ADJUSTMENT: f64 = 8.0;

pub struct RetransmissionTimeout {
    min_rto: f64,
    max_rto: f64,
    max_rtt: Duration,
    min_rtt_variance: f64,
    first_measurement: bool,
    srtt: f64,
    rtt_var: f64,
    rto: Duration,
}

impl RetransmissionTimeout {
    pub fn new(options: &Options) -> Self {
        Self {
            min_rto: options.rto_min.as_secs_f64(),
            max_rto: options.rto_max.as_secs_f64(),
            max_rtt: options.rtt_max,
            min_rtt_variance: options.min_rtt_variance.as_secs_f64()
                / HEURISTIC_VARIANCE_ADJUSTMENT,
            first_measurement: true,
            srtt: options.rto_initial.as_secs_f64(),
            rtt_var: 0.0,
            rto: options.rto_initial,
        }
    }

    pub fn rto(&self) -> Duration {
        self.rto
    }

    pub fn srtt(&self) -> Duration {
        Duration::from_secs_f64(self.srtt)
    }

    pub fn observe_rto(&mut self, measured_rtt: Duration) {
        // Unrealistic values will be skipped. If a wrongly measured (or otherwise corrupt) value
        // was processed, it could change the state in a way that would take a very long time to
        // recover.
        if measured_rtt > self.max_rtt {
            return;
        }
        let rtt = measured_rtt.as_secs_f64();

        // See <https://datatracker.ietf.org/doc/html/rfc9260#section-6.3.1>.
        if self.first_measurement {
            self.srtt = rtt;
            self.rtt_var = rtt / 2.0;
            self.first_measurement = false;
        } else {
            self.rtt_var = (1.0 - RTO_BETA) * self.rtt_var + RTO_BETA * (self.srtt - rtt).abs();
            self.srtt = (1.0 - RTO_ALPHA) * self.srtt + RTO_ALPHA * rtt;
        }

        if self.rtt_var < self.min_rtt_variance {
            self.rtt_var = self.min_rtt_variance;
        }

        // Clamp RTO between min and max.
        let rto = (self.srtt + 4.0 * self.rtt_var).clamp(self.min_rto, self.max_rto);
        self.rto = Duration::from_secs_f64(rto);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const INITIAL_RTO: Duration = Duration::from_millis(200);
    const MAX_RTT: Duration = Duration::from_millis(8_000);
    const MAX_RTO: Duration = Duration::from_millis(800);
    const MIN_RTO: Duration = Duration::from_millis(120);

    fn make_options() -> Options {
        Options {
            rtt_max: MAX_RTT,
            rto_initial: INITIAL_RTO,
            rto_max: MAX_RTO,
            rto_min: MIN_RTO,
            min_rtt_variance: Duration::from_millis(220),
            ..Options::default()
        }
    }

    fn is_near(lhs: Duration, rhs: Duration) -> bool {
        let diff = match lhs > rhs {
            true => lhs - rhs,
            false => rhs - lhs,
        };
        if diff > Duration::from_millis(1) {
            println!("left: {:#?}, right: {:#?}", lhs, rhs);
            return false;
        }
        true
    }

    #[test]
    fn has_valid_initial_rto() {
        let rto = RetransmissionTimeout::new(&make_options());
        assert_eq!(rto.rto(), INITIAL_RTO);
    }

    #[test]
    fn has_valid_initial_srtt() {
        let rto = RetransmissionTimeout::new(&make_options());
        assert_eq!(rto.srtt(), INITIAL_RTO);
    }

    #[test]
    #[ignore]
    fn negative_values_do_not_affect_rto() {
        // Not converted - there are no negative durations in Rust.
    }

    #[test]
    fn too_large_values_do_not_affect_rto() {
        let mut rto = RetransmissionTimeout::new(&make_options());
        // Initial too large value.
        rto.observe_rto(MAX_RTT + Duration::from_millis(100));
        assert_eq!(rto.rto(), INITIAL_RTO);

        rto.observe_rto(Duration::from_millis(124));
        assert_eq!(rto.rto().as_millis(), 372);

        // Subsequent too large value,
        rto.observe_rto(MAX_RTT + Duration::from_millis(100));
        assert_eq!(rto.rto().as_millis(), 372);
    }

    #[test]
    fn will_never_go_below_minimum_rto() {
        let mut rto = RetransmissionTimeout::new(&make_options());

        for _ in 0..1000 {
            rto.observe_rto(Duration::from_millis(1));
        }
        assert_eq!(rto.rto(), MIN_RTO);
    }

    #[test]
    fn will_never_go_above_maximum_rto() {
        let mut rto = RetransmissionTimeout::new(&make_options());

        for _ in 0..1000 {
            rto.observe_rto(MAX_RTT - Duration::from_millis(100));
        }
        assert_eq!(rto.rto(), MAX_RTO);
    }

    #[test]
    fn calculates_rto_for_stable_rtt() {
        let mut rto = RetransmissionTimeout::new(&make_options());

        rto.observe_rto(Duration::from_millis(124));
        assert_eq!(rto.rto().as_millis(), 372);
        rto.observe_rto(Duration::from_millis(128));
        assert_eq!(rto.rto().as_millis(), 314);
        rto.observe_rto(Duration::from_millis(123));
        assert_eq!(rto.rto().as_millis(), 268);
        rto.observe_rto(Duration::from_millis(125));
        assert_eq!(rto.rto().as_millis(), 234);
        rto.observe_rto(Duration::from_millis(127));
        assert_eq!(rto.rto().as_millis(), 234);
    }

    #[test]
    fn calculates_rto_for_unstable_rtt() {
        let mut rto = RetransmissionTimeout::new(&make_options());

        rto.observe_rto(Duration::from_millis(124));
        assert_eq!(rto.rto().as_millis(), 372);
        rto.observe_rto(Duration::from_millis(402));
        assert_eq!(rto.rto().as_millis(), 622);
        rto.observe_rto(Duration::from_millis(728));
        assert_eq!(rto.rto().as_millis(), 800);
        rto.observe_rto(Duration::from_millis(89));
        assert_eq!(rto.rto().as_millis(), 800);
        rto.observe_rto(Duration::from_millis(126));
        assert_eq!(rto.rto().as_millis(), 800);
    }

    #[test]
    fn will_stabilize_after_a_while() {
        let mut rto = RetransmissionTimeout::new(&make_options());

        rto.observe_rto(Duration::from_millis(124));
        rto.observe_rto(Duration::from_millis(402));
        rto.observe_rto(Duration::from_millis(728));
        rto.observe_rto(Duration::from_millis(89));
        rto.observe_rto(Duration::from_millis(126));
        assert_eq!(rto.rto().as_millis(), 800);
        rto.observe_rto(Duration::from_millis(124));
        assert_eq!(rto.rto().as_millis(), 800);
        rto.observe_rto(Duration::from_millis(122));
        assert_eq!(rto.rto().as_millis(), 709);
        rto.observe_rto(Duration::from_millis(123));
        assert_eq!(rto.rto().as_millis(), 630);
        rto.observe_rto(Duration::from_millis(124));
        assert_eq!(rto.rto().as_millis(), 561);
        rto.observe_rto(Duration::from_millis(122));
        assert_eq!(rto.rto().as_millis(), 504);
        rto.observe_rto(Duration::from_millis(124));
        assert_eq!(rto.rto().as_millis(), 453);
        rto.observe_rto(Duration::from_millis(124));
        assert_eq!(rto.rto().as_millis(), 409);
        rto.observe_rto(Duration::from_millis(124));
        assert_eq!(rto.rto().as_millis(), 372);
        rto.observe_rto(Duration::from_millis(124));
        assert_eq!(rto.rto().as_millis(), 339);
    }

    #[test]
    fn will_always_stay_above_rtt() {
        // In simulations, it's quite common to have a very stable RTT, and having an RTO at the
        // same value will cause issues as expiry timers will be scheduled to be expire exactly when
        // a packet is supposed to arrive. The RTO must be larger than the RTT. In non-simulated
        // environments, this is a non-issue as any jitter will increase the RTO.
        let mut rto = RetransmissionTimeout::new(&make_options());

        for _ in 0..1000 {
            rto.observe_rto(Duration::from_millis(124));
        }

        assert_eq!(rto.rto().as_millis(), 234);
    }

    #[test]
    fn can_specify_smaller_minimum_rtt_variance() {
        let mut options = make_options();
        options.min_rtt_variance = Duration::from_millis(100);
        let mut rto = RetransmissionTimeout::new(&options);

        for _ in 0..1000 {
            rto.observe_rto(Duration::from_millis(124));
        }

        assert_eq!(rto.rto().as_millis(), 174);
    }

    #[test]
    fn can_specify_larger_minimum_rtt_variance() {
        let mut options = make_options();
        options.min_rtt_variance = Duration::from_millis(320);
        let mut rto = RetransmissionTimeout::new(&options);

        for _ in 0..1000 {
            rto.observe_rto(Duration::from_millis(124));
        }

        assert_eq!(rto.rto().as_millis(), 284);
    }
}
