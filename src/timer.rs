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

use crate::api::SocketTime;
use std::cmp::min;
use std::time::Duration;

/// An unreasonable long time, for SCTP purposes. Mainly used as upper bound.
pub const MAX_DURATION: Duration = Duration::from_secs(24 * 3600);

/// Maximum number of timer restarts, when not set.
pub const MAX_RESTARTS: u32 = u32::MAX;

// The upper limit for the exponential backoff, to avoid overflow.
const MAX_BACKOFF_COUNT: u32 = 10;

pub enum BackoffAlgorithm {
    Fixed,
    Exponential,
}

/// A very simple timer implementation
///
/// Timers are started and can be stopped or restarted. When a timer expires, A timer is
/// automatically restarted when it expires, as long as the number of restarts is below the
/// configurable `max_restarts` parameter. The `is_running` property can be queried to know if it's
/// still running after having expired.
///
/// When a timer is restarted, it will use a configurable `backoff_algorithm` to possibly adjust the
/// duration of the next expiry.
pub struct Timer {
    base_duration: Duration,
    expiration_count: u32,
    backoff_algorithm: BackoffAlgorithm,
    max_restarts: u32,
    max_backoff_duration: Duration,
    next_expiry: Option<SocketTime>,
}

impl Timer {
    /// Creates a new timer with the provided base duration and other properties.
    pub fn new(
        duration: Duration,
        backoff_algorithm: BackoffAlgorithm,
        max_restarts: Option<u32>,
        max_backoff_duration: Option<Duration>,
    ) -> Self {
        Self {
            base_duration: duration,
            backoff_algorithm,
            expiration_count: 0,
            max_restarts: max_restarts.unwrap_or(MAX_RESTARTS),
            max_backoff_duration: min(max_backoff_duration.unwrap_or(MAX_DURATION), MAX_DURATION),
            next_expiry: None,
        }
    }

    /// Returns the relative backoff duration from previous iteration.
    fn get_backoff_duration(&self) -> Duration {
        let duration = match self.backoff_algorithm {
            BackoffAlgorithm::Fixed => self.base_duration,
            BackoffAlgorithm::Exponential => {
                let backoff_count = self.expiration_count.saturating_sub(1).min(MAX_BACKOFF_COUNT);
                self.base_duration.saturating_mul(1 << backoff_count)
            }
        };
        min(duration, self.max_backoff_duration)
    }

    fn compute_expiry(&self, from_time: SocketTime) -> Option<SocketTime> {
        if self.base_duration == Duration::ZERO {
            None
        } else {
            Some(from_time + self.get_backoff_duration())
        }
    }

    /// Returns true if a timer has expired. This method is not idempotent - calling it changes its
    /// state.
    ///
    /// If expired, it will calculate the next expiration time and update the timer. If the timer
    /// has reached its max restart limit (if any), it will be stopped, otherwise, it will keep
    /// running.
    pub fn expire(&mut self, now: SocketTime) -> bool {
        let Some(current_expiry) = self.next_expiry else {
            return false;
        };

        if current_expiry > now {
            return false;
        }

        let restarts_remaining = self.expiration_count < self.max_restarts;
        self.expiration_count = self.expiration_count.saturating_add(1);

        self.next_expiry =
            restarts_remaining.then(|| self.compute_expiry(current_expiry)).flatten();

        true
    }

    pub fn next_expiry(&self) -> Option<SocketTime> {
        self.next_expiry
    }

    pub fn is_running(&self) -> bool {
        self.next_expiry.is_some()
    }

    pub fn stop(&mut self) {
        self.next_expiry = None;
    }

    /// Starts a timer. If it's already started, it will be restarted to its original expiration
    /// delay and its expiration count will be reset.
    pub fn start(&mut self, now: SocketTime) {
        self.expiration_count = 0;
        self.next_expiry = self.compute_expiry(now);
    }

    /// Updates the timer's base duration. This doesn't change the timer's current expiration time
    /// in case it's running.
    pub fn set_duration(&mut self, duration: Duration) {
        self.base_duration = duration;
    }

    /// Returns the timer's base duration, which may be shorter than the timer's actual expiration
    /// time in case it's running, due to the backoff algorithm.
    pub fn duration(&self) -> Duration {
        self.base_duration
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const START_TIME: SocketTime = SocketTime::zero();

    #[test]
    fn new_timer_is_not_running() {
        let t = Timer::new(
            Duration::from_millis(1000),
            BackoffAlgorithm::Fixed,
            /* max_restarts */ None,
            /* max_backoff_algorithm */ None,
        );
        assert_eq!(t.duration(), Duration::from_millis(1000));
        assert!(!t.is_running());
        assert!(t.next_expiry().is_none());
    }

    #[test]
    fn stopped_timer_does_not_expire() {
        let mut t = Timer::new(
            Duration::from_millis(1000),
            BackoffAlgorithm::Fixed,
            /* max_restarts */ None,
            /* max_backoff_algorithm */ None,
        );
        assert_eq!(t.duration(), Duration::from_millis(1000));
        let now = START_TIME;
        t.start(now);
        t.stop();
        assert!(!t.expire(now + Duration::from_millis(1000)));
    }

    #[test]
    fn timer_expires_after_duration() {
        let mut t = Timer::new(
            Duration::from_millis(1000),
            BackoffAlgorithm::Fixed,
            /* max_restarts */ None,
            /* max_backoff_algorithm */ None,
        );

        let now = START_TIME;
        t.start(now);
        assert!(t.is_running());
        assert!(!t.expire(now + Duration::from_millis(999)));
        assert!(t.expire(now + Duration::from_millis(1000)));
        assert!(t.is_running());
    }

    #[test]
    fn timer_restarts_after_expired() {
        let mut t = Timer::new(
            Duration::from_millis(1000),
            BackoffAlgorithm::Fixed,
            /* max_restarts */ None,
            /* max_backoff_algorithm */ None,
        );

        let now = START_TIME;
        t.start(now);
        assert!(t.is_running());
        assert!(t.expire(now + Duration::from_millis(1000)));
        assert_eq!(t.next_expiry, Some(now + Duration::from_millis(2000)));
        assert!(!t.expire(now + Duration::from_millis(1001)));
        assert!(t.expire(now + Duration::from_millis(2000)));
        assert_eq!(t.next_expiry, Some(now + Duration::from_millis(3000)));
        assert!(t.is_running());
    }

    #[test]
    fn timer_stops_when_exhausted() {
        let mut t = Timer::new(
            Duration::from_millis(1000),
            BackoffAlgorithm::Fixed,
            /* max_restarts */ Some(0),
            /* max_backoff_algorithm */ None,
        );

        let now = START_TIME;
        t.start(now);
        assert!(t.is_running());
        assert!(t.expire(now + Duration::from_millis(1000)));
        assert!(!t.is_running());
        assert!(t.next_expiry.is_none());
    }

    #[test]
    fn can_be_restarted_limited_number_times() {
        let mut t = Timer::new(
            Duration::from_millis(1000),
            BackoffAlgorithm::Fixed,
            /* max_restarts */ Some(2),
            /* max_backoff_algorithm */ None,
        );

        let now = START_TIME;
        t.start(now);
        assert!(t.is_running());
        assert!(t.expire(now + Duration::from_millis(1000)));
        assert!(t.expire(now + Duration::from_millis(2000)));
        assert!(t.expire(now + Duration::from_millis(3000)));
        assert!(!t.is_running());
    }

    #[test]
    fn timer_restart_does_not_drift() {
        let mut t = Timer::new(
            Duration::from_millis(1000),
            BackoffAlgorithm::Fixed,
            /* max_restarts */ None,
            /* max_backoff_algorithm */ None,
        );

        let now = START_TIME;
        t.start(now);
        assert!(t.is_running());
        assert!(t.expire(now + Duration::from_millis(1050)));
        assert_eq!(t.next_expiry, Some(now + Duration::from_millis(2000)));
    }

    #[test]
    fn can_do_exponential_backoff() {
        let mut t = Timer::new(
            Duration::from_millis(1000),
            BackoffAlgorithm::Exponential,
            /* max_restarts */ None,
            /* max_backoff_algorithm */ None,
        );

        let now = START_TIME;
        t.start(now);
        assert!(t.is_running());
        assert!(t.expire(now + Duration::from_millis(1050)));
        assert_eq!(t.next_expiry, Some(now + Duration::from_millis(2000)));
        assert!(t.expire(now + Duration::from_millis(2100)));
        assert_eq!(t.next_expiry, Some(now + Duration::from_millis(4000)));
        assert!(t.expire(now + Duration::from_millis(4400)));
        assert_eq!(t.next_expiry, Some(now + Duration::from_millis(8000)));
    }

    #[test]
    fn does_not_overflow_when_expired_many_times() {
        let mut t = Timer::new(
            Duration::from_millis(1000),
            BackoffAlgorithm::Exponential,
            /* max_restarts */ None,
            /* max_backoff_algorithm */ None,
        );

        // Exponential backoff would make the duration extremely long, with risk of overflow.
        // Validate that the test passes without issues.
        let now = START_TIME;
        t.start(now);
        assert!(t.is_running());
        for _ in 0..1000 {
            let now = t.next_expiry().unwrap();
            t.expire(now);
        }
    }
}
