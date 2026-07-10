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

use crate::api::StreamId;
use std::fmt;

/// Ordered/Unordered stream identifiers.
///
/// Ordered and unordered streams are actually separate in many parts of SCTP even though the API
/// exposes both stream types as a single one. When necessary to separate the two, this enum is used
/// internally. Called `StreamKey` to differentiate itself with [`StreamId`].
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum StreamKey {
    Ordered(StreamId),
    Unordered(StreamId),
}

impl StreamKey {
    pub fn new(is_unordered: bool, id: StreamId) -> Self {
        if is_unordered { Self::Unordered(id) } else { Self::Ordered(id) }
    }

    pub fn id(&self) -> StreamId {
        match *self {
            StreamKey::Ordered(id) | StreamKey::Unordered(id) => id,
        }
    }

    pub fn is_ordered(&self) -> bool {
        matches!(self, Self::Ordered(_))
    }

    pub fn is_unordered(&self) -> bool {
        matches!(self, Self::Unordered(_))
    }
}

pub trait SerialNumber: Sized + Copy + Eq {
    type DistanceType;

    /// Calculates the absolute distance `|self - other|` between two sequence numbers,
    /// properly accounting for sequence space wrapping.
    fn distance_to(self, other: Self) -> Self::DistanceType;

    /// Returns true if this sequence number is strictly greater than `base`.
    /// This corresponds to the strictly "greater than" half of the sequence space,
    /// excluding equality and the exact half-space ambiguity point.
    fn greater_than(&self, base: Self) -> bool;

    /// Returns true if this sequence number is strictly less than `other`
    /// (i.e. `other` is strictly greater than `self`).
    fn less_than(&self, other: Self) -> bool {
        other.greater_than(*self)
    }

    /// Returns true if this sequence number is less than or equal to `other`.
    fn less_than_or_equal(&self, other: Self) -> bool {
        *self == other || other.greater_than(*self)
    }

    /// Returns true if this sequence number is greater than or equal to `other`.
    fn greater_than_or_equal(&self, other: Self) -> bool {
        *self == other || self.greater_than(other)
    }
}

macro_rules! define_rfc1982_serial {
    ($name:ident, $int_type:ident, $half_space:expr, $doc:expr) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Eq, Hash, PartialEq)]
        pub struct $name(pub $int_type);

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                std::fmt::Display::fmt(self, f)
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        impl std::ops::Add<$int_type> for $name {
            type Output = $name;

            #[inline]
            fn add(self, rhs: $int_type) -> $name {
                $name(self.0.wrapping_add(rhs))
            }
        }

        impl std::ops::Sub<$int_type> for $name {
            type Output = $name;

            #[inline]
            fn sub(self, rhs: $int_type) -> $name {
                $name(self.0.wrapping_sub(rhs))
            }
        }

        impl std::ops::AddAssign<$int_type> for $name {
            fn add_assign(&mut self, rhs: $int_type) {
                self.0 = self.0.wrapping_add(rhs);
            }
        }

        impl std::ops::SubAssign<$int_type> for $name {
            fn sub_assign(&mut self, rhs: $int_type) {
                self.0 = self.0.wrapping_sub(rhs);
            }
        }

        impl SerialNumber for $name {
            type DistanceType = $int_type;

            fn distance_to(self, other: Self) -> $int_type {
                if self.greater_than(other) {
                    self.0.wrapping_sub(other.0)
                } else {
                    other.0.wrapping_sub(self.0)
                }
            }

            fn greater_than(&self, base: Self) -> bool {
                let diff = self.0.wrapping_sub(base.0);
                diff > 0 && diff < $half_space
            }
        }

        impl $name {
            pub fn add_to(self, other: $int_type) -> Self {
                $name(self.0.wrapping_add(other))
            }
        }
    };
}

define_rfc1982_serial!(Ssn, u16, 1 << 15, "Stream Sequence Number (SSN)");
define_rfc1982_serial!(Mid, u32, 1 << 31, "Message Identifier (MID)");
define_rfc1982_serial!(Fsn, u32, 1 << 31, "Fragment Sequence Number (FSN)");
define_rfc1982_serial!(Tsn, u32, 1 << 31, "Transmission Sequence Number (TSN)");

/// An ID for every outgoing message, to correlate outgoing data chunks with the message it was
/// carved from. It can only be compared by equality - there is no defined ordering.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct OutgoingMessageId(pub u32);

impl fmt::Debug for OutgoingMessageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for OutgoingMessageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::ops::AddAssign<u32> for OutgoingMessageId {
    fn add_assign(&mut self, rhs: u32) {
        self.0 = self.0.wrapping_add(rhs);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LARGE_TSN_OFFSET: u32 = 1_000_000;
    const MAX_U32: u32 = 4_294_967_295;
    const MAX_U16: u16 = 65_535;

    #[test]
    fn tsn_cmp() {
        assert!(Tsn(42) == Tsn(42));
        assert!(Tsn(1).greater_than(Tsn(0)));
        assert!(Tsn(0).less_than(Tsn(1)));
        assert!(Tsn(44).greater_than(Tsn(0)));
        assert!(Tsn(0).less_than(Tsn(44)));
        assert!(Tsn(100).greater_than(Tsn(0)));
        assert!(Tsn(0).less_than(Tsn(100)));
        assert!(Tsn(100).greater_than(Tsn(44)));
        assert!(Tsn(44).less_than(Tsn(100)));
        assert!(Tsn(200).greater_than(Tsn(100)));
        assert!(Tsn(100).less_than(Tsn(200)));
        assert!(Tsn(255).greater_than(Tsn(200)));
        assert!(Tsn(200).less_than(Tsn(255)));
        assert!(Tsn(0).greater_than(Tsn(MAX_U32)));
        assert!(Tsn(MAX_U32).less_than(Tsn(0)));
        assert!(Tsn(100).greater_than(Tsn(MAX_U32)));
        assert!(Tsn(MAX_U32).less_than(Tsn(100)));
        assert!(Tsn(0).greater_than(Tsn(MAX_U32)));
        assert!(Tsn(MAX_U32).less_than(Tsn(0)));
        assert!(Tsn(44).greater_than(Tsn(MAX_U32)));
        assert!(Tsn(MAX_U32).less_than(Tsn(44)));
    }

    #[test]
    fn tsn_next_and_prev_value() {
        let tsn1 = Tsn(MAX_U32 - 1);
        let tsn2 = Tsn(MAX_U32);
        let tsn3 = Tsn(0);
        let tsn4 = Tsn(1);

        assert_eq!(tsn1 + 1, tsn2);
        assert_eq!(tsn2 + 1, tsn3);
        assert_eq!(tsn3 + 1, tsn4);

        assert_eq!(tsn4 - 1, tsn3);
        assert_eq!(tsn3 - 1, tsn2);
        assert_eq!(tsn2 - 1, tsn1);
    }

    #[test]
    fn tsn_increment() {
        let mut tsn1 = Tsn(MAX_U32 - 1);
        let tsn2 = Tsn(MAX_U32);
        let tsn3 = Tsn(0);
        let tsn4 = Tsn(1);

        tsn1 += 1;
        assert_eq!(tsn1, tsn2);

        tsn1 += 1;
        assert_eq!(tsn1, tsn3);

        tsn1 += 1;
        assert_eq!(tsn1, tsn4);
    }

    #[test]
    fn tsn_distance_to() {
        let tsn1 = Tsn(MAX_U32 - LARGE_TSN_OFFSET);
        let tsn2 = Tsn(MAX_U32 - 1);
        let tsn3 = Tsn(MAX_U32);
        let tsn4 = Tsn(0);
        let tsn5 = Tsn(1);
        let tsn6 = Tsn(LARGE_TSN_OFFSET);

        assert_eq!(tsn1.distance_to(tsn2), LARGE_TSN_OFFSET - 1);
        assert_eq!(tsn1.distance_to(tsn3), LARGE_TSN_OFFSET);
        assert_eq!(tsn1.distance_to(tsn4), LARGE_TSN_OFFSET + 1);
        assert_eq!(tsn1.distance_to(tsn5), LARGE_TSN_OFFSET + 2);
        assert_eq!(tsn1.distance_to(tsn6), LARGE_TSN_OFFSET + 1 + LARGE_TSN_OFFSET);

        assert_eq!(tsn2.distance_to(tsn1), LARGE_TSN_OFFSET - 1);
        assert_eq!(tsn2.distance_to(tsn3), 1);
        assert_eq!(tsn2.distance_to(tsn4), 2);
        assert_eq!(tsn2.distance_to(tsn5), 3);
        assert_eq!(tsn2.distance_to(tsn6), 2 + LARGE_TSN_OFFSET);

        assert_eq!(tsn3.distance_to(tsn1), LARGE_TSN_OFFSET);
        assert_eq!(tsn3.distance_to(tsn2), 1);
        assert_eq!(tsn3.distance_to(tsn4), 1);
        assert_eq!(tsn3.distance_to(tsn5), 2);
        assert_eq!(tsn3.distance_to(tsn6), 1 + LARGE_TSN_OFFSET);

        assert_eq!(tsn4.distance_to(tsn1), 1 + LARGE_TSN_OFFSET);
        assert_eq!(tsn4.distance_to(tsn2), 2);
        assert_eq!(tsn4.distance_to(tsn3), 1);
        assert_eq!(tsn4.distance_to(tsn5), 1);
        assert_eq!(tsn4.distance_to(tsn6), LARGE_TSN_OFFSET);

        assert_eq!(tsn5.distance_to(tsn1), 2 + LARGE_TSN_OFFSET);
        assert_eq!(tsn5.distance_to(tsn2), 3);
        assert_eq!(tsn5.distance_to(tsn3), 2);
        assert_eq!(tsn5.distance_to(tsn4), 1);
        assert_eq!(tsn5.distance_to(tsn6), LARGE_TSN_OFFSET - 1);

        assert_eq!(tsn6.distance_to(tsn1), LARGE_TSN_OFFSET + 1 + LARGE_TSN_OFFSET);
        assert_eq!(tsn6.distance_to(tsn2), LARGE_TSN_OFFSET + 2);
        assert_eq!(tsn6.distance_to(tsn3), LARGE_TSN_OFFSET + 1);
        assert_eq!(tsn6.distance_to(tsn4), LARGE_TSN_OFFSET);
        assert_eq!(tsn6.distance_to(tsn5), LARGE_TSN_OFFSET - 1);
    }

    #[test]
    fn ssn_cmp() {
        assert!(Ssn(42) == Ssn(42));
        assert!(Ssn(1).greater_than(Ssn(0)));
        assert!(Ssn(0).less_than(Ssn(1)));
        assert!(Ssn(44).greater_than(Ssn(0)));
        assert!(Ssn(0).less_than(Ssn(44)));
        assert!(Ssn(100).greater_than(Ssn(0)));
        assert!(Ssn(0).less_than(Ssn(100)));
        assert!(Ssn(100).greater_than(Ssn(44)));
        assert!(Ssn(44).less_than(Ssn(100)));
        assert!(Ssn(200).greater_than(Ssn(100)));
        assert!(Ssn(100).less_than(Ssn(200)));
        assert!(Ssn(255).greater_than(Ssn(200)));
        assert!(Ssn(200).less_than(Ssn(255)));
        assert!(Ssn(0).greater_than(Ssn(MAX_U16)));
        assert!(Ssn(MAX_U16).less_than(Ssn(0)));
        assert!(Ssn(100).greater_than(Ssn(MAX_U16)));
        assert!(Ssn(MAX_U16).less_than(Ssn(100)));
        assert!(Ssn(0).greater_than(Ssn(MAX_U16)));
        assert!(Ssn(MAX_U16).less_than(Ssn(0)));
        assert!(Ssn(44).greater_than(Ssn(MAX_U16)));
        assert!(Ssn(MAX_U16).less_than(Ssn(44)));
    }

    #[test]
    fn ssn_next_and_prev_value() {
        let ssn1 = Ssn(MAX_U16 - 1);
        let ssn2 = Ssn(MAX_U16);
        let ssn3 = Ssn(0);
        let ssn4 = Ssn(1);

        assert_eq!(ssn1 + 1, ssn2);
        assert_eq!(ssn2 + 1, ssn3);
        assert_eq!(ssn3 + 1, ssn4);

        assert_eq!(ssn4 - 1, ssn3);
        assert_eq!(ssn3 - 1, ssn2);
        assert_eq!(ssn2 - 1, ssn1);
    }

    #[test]
    fn ssn_increment() {
        let mut ssn1 = Ssn(MAX_U16 - 1);
        let ssn2 = Ssn(MAX_U16);
        let ssn3 = Ssn(0);
        let ssn4 = Ssn(1);

        ssn1 += 1;
        assert_eq!(ssn1, ssn2);

        ssn1 += 1;
        assert_eq!(ssn1, ssn3);

        ssn1 += 1;
        assert_eq!(ssn1, ssn4);
    }

    #[test]
    fn mid_cmp() {
        assert!(Mid(42) == Mid(42));
        assert!(Mid(1).greater_than(Mid(0)));
        assert!(Mid(0).less_than(Mid(1)));
        assert!(Mid(44).greater_than(Mid(0)));
        assert!(Mid(0).less_than(Mid(44)));
        assert!(Mid(100).greater_than(Mid(0)));
        assert!(Mid(0).less_than(Mid(100)));
        assert!(Mid(100).greater_than(Mid(44)));
        assert!(Mid(44).less_than(Mid(100)));
        assert!(Mid(200).greater_than(Mid(100)));
        assert!(Mid(100).less_than(Mid(200)));
        assert!(Mid(255).greater_than(Mid(200)));
        assert!(Mid(200).less_than(Mid(255)));
        assert!(Mid(0).greater_than(Mid(MAX_U32)));
        assert!(Mid(MAX_U32).less_than(Mid(0)));
        assert!(Mid(100).greater_than(Mid(MAX_U32)));
        assert!(Mid(MAX_U32).less_than(Mid(100)));
        assert!(Mid(0).greater_than(Mid(MAX_U32)));
        assert!(Mid(MAX_U32).less_than(Mid(0)));
        assert!(Mid(44).greater_than(Mid(MAX_U32)));
        assert!(Mid(MAX_U32).less_than(Mid(44)));
    }

    #[test]
    fn fsn_cmp() {
        assert!(Fsn(42) == Fsn(42));
        assert!(Fsn(1).greater_than(Fsn(0)));
        assert!(Fsn(0).less_than(Fsn(1)));
        assert!(Fsn(1).greater_than(Fsn(0)));
        assert!(Fsn(0).less_than(Fsn(1)));
        assert!(Fsn(44).greater_than(Fsn(0)));
        assert!(Fsn(0).less_than(Fsn(44)));
        assert!(Fsn(100).greater_than(Fsn(0)));
        assert!(Fsn(0).less_than(Fsn(100)));
        assert!(Fsn(100).greater_than(Fsn(44)));
        assert!(Fsn(44).less_than(Fsn(100)));
        assert!(Fsn(200).greater_than(Fsn(100)));
        assert!(Fsn(100).less_than(Fsn(200)));
        assert!(Fsn(255).greater_than(Fsn(200)));
        assert!(Fsn(200).less_than(Fsn(255)));
        assert!(Fsn(0).greater_than(Fsn(MAX_U32)));
        assert!(Fsn(MAX_U32).less_than(Fsn(0)));
        assert!(Fsn(100).greater_than(Fsn(MAX_U32)));
        assert!(Fsn(MAX_U32).less_than(Fsn(100)));
        assert!(Fsn(0).greater_than(Fsn(MAX_U32)));
        assert!(Fsn(MAX_U32).less_than(Fsn(0)));
        assert!(Fsn(44).greater_than(Fsn(MAX_U32)));
        assert!(Fsn(MAX_U32).less_than(Fsn(44)));
    }
}
