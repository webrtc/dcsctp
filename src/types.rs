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
use std::cmp::Ordering;
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
    pub fn from(is_unordered: bool, id: StreamId) -> Self {
        if is_unordered {
            Self::Unordered(id)
        } else {
            Self::Ordered(id)
        }
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

/// See <https://datatracker.ietf.org/doc/html/rfc1982#section-3.2>.
fn cmp_rfc1982_u32(a: u32, b: u32) -> Ordering {
    if a == b {
        Ordering::Equal
    } else if (a < b && (b - a) < (1 << 31)) || (a > b && (a - b) > (1 << 31)) {
        Ordering::Less
    } else {
        Ordering::Greater
    }
}

fn cmp_rfc1982_u16(a: u16, b: u16) -> Ordering {
    if a == b {
        Ordering::Equal
    } else if (a < b && (b - a) < (1 << 15)) || (a > b && (a - b) > (1 << 15)) {
        Ordering::Less
    } else {
        Ordering::Greater
    }
}

/// Stream Sequence Number (SSN)
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct Ssn(pub u16);

impl fmt::Debug for Ssn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for Ssn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::cmp::PartialOrd for Ssn {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl std::cmp::Ord for Ssn {
    fn cmp(&self, other: &Self) -> Ordering {
        // From <https://datatracker.ietf.org/doc/html/rfc9260#section-1.6>:
        //
        //   Any arithmetic done on Stream Sequence Numbers SHOULD use Serial Number Arithmetic, as
        //   defined in [RFC1982] [...]
        cmp_rfc1982_u16(self.0, other.0)
    }
}

impl std::ops::Add<u16> for Ssn {
    type Output = Ssn;

    #[inline]
    fn add(self, rhs: u16) -> Ssn {
        Ssn(self.0.wrapping_add(rhs))
    }
}

impl std::ops::Sub<u16> for Ssn {
    type Output = Ssn;

    #[inline]
    fn sub(self, rhs: u16) -> Ssn {
        Ssn(self.0.wrapping_sub(rhs))
    }
}

impl std::ops::AddAssign<u16> for Ssn {
    fn add_assign(&mut self, rhs: u16) {
        self.0 = self.0.wrapping_add(rhs);
    }
}

impl std::ops::SubAssign<u16> for Ssn {
    fn sub_assign(&mut self, rhs: u16) {
        self.0 = self.0.wrapping_sub(rhs);
    }
}

/// Message Identifier (MID)
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct Mid(pub u32);

impl fmt::Debug for Mid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for Mid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::cmp::PartialOrd for Mid {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl std::cmp::Ord for Mid {
    fn cmp(&self, other: &Self) -> Ordering {
        // From <https://datatracker.ietf.org/doc/html/rfc8260#section-2.1>:
        //
        //   Please note that the serial number arithmetic defined in [RFC1982] [...] applies.
        cmp_rfc1982_u32(self.0, other.0)
    }
}

impl std::ops::AddAssign<u32> for Mid {
    fn add_assign(&mut self, rhs: u32) {
        self.0 = self.0.wrapping_add(rhs);
    }
}

impl std::ops::Add<u32> for Mid {
    type Output = Mid;

    #[inline]
    fn add(self, rhs: u32) -> Mid {
        Mid(self.0.wrapping_add(rhs))
    }
}

/// Fragment Sequence Number (FSN)
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct Fsn(pub u32);

impl fmt::Debug for Fsn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for Fsn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::cmp::PartialOrd for Fsn {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl std::cmp::Ord for Fsn {
    fn cmp(&self, other: &Self) -> Ordering {
        // From <https://datatracker.ietf.org/doc/html/rfc8260#section-2.1>:
        //
        //   For the FSN, the serial number arithmetic defined in [RFC1982] applies [...]
        cmp_rfc1982_u32(self.0, other.0)
    }
}

impl std::ops::AddAssign<u32> for Fsn {
    fn add_assign(&mut self, rhs: u32) {
        self.0 = self.0.wrapping_add(rhs);
    }
}

impl Fsn {
    pub fn distance_to(self, other: Fsn) -> u32 {
        if self > other {
            self.0.wrapping_sub(other.0)
        } else {
            other.0.wrapping_sub(self.0)
        }
    }
}

/// Transmission Sequence Number (TSN)
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct Tsn(pub u32);

impl fmt::Debug for Tsn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for Tsn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::cmp::PartialOrd for Tsn {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl std::cmp::Ord for Tsn {
    fn cmp(&self, other: &Self) -> Ordering {
        // From <https://datatracker.ietf.org/doc/html/rfc9260#section-1.6-2>:
        //
        //   Comparisons and arithmetic on TSNs in this document SHOULD use Serial Number
        //   Arithmetic, as defined in [RFC1982] [...]
        cmp_rfc1982_u32(self.0, other.0)
    }
}

impl std::ops::Add<u32> for Tsn {
    type Output = Tsn;

    #[inline]
    fn add(self, rhs: u32) -> Tsn {
        Tsn(self.0.wrapping_add(rhs))
    }
}

impl std::ops::Sub<u32> for Tsn {
    type Output = Tsn;

    #[inline]
    fn sub(self, rhs: u32) -> Tsn {
        Tsn(self.0.wrapping_sub(rhs))
    }
}

impl std::ops::AddAssign<u32> for Tsn {
    fn add_assign(&mut self, rhs: u32) {
        self.0 = self.0.wrapping_add(rhs);
    }
}

impl std::ops::SubAssign<u32> for Tsn {
    fn sub_assign(&mut self, rhs: u32) {
        self.0 = self.0.wrapping_sub(rhs);
    }
}

impl Tsn {
    pub fn add_to(self, other: u32) -> Tsn {
        Tsn(self.0.wrapping_add(other))
    }

    pub fn distance_to(self, other: Tsn) -> u32 {
        if self > other {
            self.0.wrapping_sub(other.0)
        } else {
            other.0.wrapping_sub(self.0)
        }
    }
}

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
        assert!(Tsn(1) > Tsn(0));
        assert!(Tsn(0) < Tsn(1));
        assert!(Tsn(44) > Tsn(0));
        assert!(Tsn(0) < Tsn(44));
        assert!(Tsn(100) > Tsn(0));
        assert!(Tsn(0) < Tsn(100));
        assert!(Tsn(100) > Tsn(44));
        assert!(Tsn(44) < Tsn(100));
        assert!(Tsn(200) > Tsn(100));
        assert!(Tsn(100) < Tsn(200));
        assert!(Tsn(255) > Tsn(200));
        assert!(Tsn(200) < Tsn(255));
        assert!(Tsn(0) > Tsn(MAX_U32));
        assert!(Tsn(MAX_U32) < Tsn(0));
        assert!(Tsn(100) > Tsn(MAX_U32));
        assert!(Tsn(MAX_U32) < Tsn(100));
        assert!(Tsn(0) > Tsn(MAX_U32));
        assert!(Tsn(MAX_U32) < Tsn(0));
        assert!(Tsn(44) > Tsn(MAX_U32));
        assert!(Tsn(MAX_U32) < Tsn(44));
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
        assert!(Ssn(1) > Ssn(0));
        assert!(Ssn(0) < Ssn(1));
        assert!(Ssn(44) > Ssn(0));
        assert!(Ssn(0) < Ssn(44));
        assert!(Ssn(100) > Ssn(0));
        assert!(Ssn(0) < Ssn(100));
        assert!(Ssn(100) > Ssn(44));
        assert!(Ssn(44) < Ssn(100));
        assert!(Ssn(200) > Ssn(100));
        assert!(Ssn(100) < Ssn(200));
        assert!(Ssn(255) > Ssn(200));
        assert!(Ssn(200) < Ssn(255));
        assert!(Ssn(0) > Ssn(MAX_U16));
        assert!(Ssn(MAX_U16) < Ssn(0));
        assert!(Ssn(100) > Ssn(MAX_U16));
        assert!(Ssn(MAX_U16) < Ssn(100));
        assert!(Ssn(0) > Ssn(MAX_U16));
        assert!(Ssn(MAX_U16) < Ssn(0));
        assert!(Ssn(44) > Ssn(MAX_U16));
        assert!(Ssn(MAX_U16) < Ssn(44));
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
        assert!(Mid(1) > Mid(0));
        assert!(Mid(0) < Mid(1));
        assert!(Mid(44) > Mid(0));
        assert!(Mid(0) < Mid(44));
        assert!(Mid(100) > Mid(0));
        assert!(Mid(0) < Mid(100));
        assert!(Mid(100) > Mid(44));
        assert!(Mid(44) < Mid(100));
        assert!(Mid(200) > Mid(100));
        assert!(Mid(100) < Mid(200));
        assert!(Mid(255) > Mid(200));
        assert!(Mid(200) < Mid(255));
        assert!(Mid(0) > Mid(MAX_U32));
        assert!(Mid(MAX_U32) < Mid(0));
        assert!(Mid(100) > Mid(MAX_U32));
        assert!(Mid(MAX_U32) < Mid(100));
        assert!(Mid(0) > Mid(MAX_U32));
        assert!(Mid(MAX_U32) < Mid(0));
        assert!(Mid(44) > Mid(MAX_U32));
        assert!(Mid(MAX_U32) < Mid(44));
    }

    #[test]
    fn fsn_cmp() {
        assert!(Fsn(42) == Fsn(42));
        assert!(Fsn(1) > Fsn(0));
        assert!(Fsn(0) < Fsn(1));
        assert!(Fsn(1) > Fsn(0));
        assert!(Fsn(0) < Fsn(1));
        assert!(Fsn(44) > Fsn(0));
        assert!(Fsn(0) < Fsn(44));
        assert!(Fsn(100) > Fsn(0));
        assert!(Fsn(0) < Fsn(100));
        assert!(Fsn(100) > Fsn(44));
        assert!(Fsn(44) < Fsn(100));
        assert!(Fsn(200) > Fsn(100));
        assert!(Fsn(100) < Fsn(200));
        assert!(Fsn(255) > Fsn(200));
        assert!(Fsn(200) < Fsn(255));
        assert!(Fsn(0) > Fsn(MAX_U32));
        assert!(Fsn(MAX_U32) < Fsn(0));
        assert!(Fsn(100) > Fsn(MAX_U32));
        assert!(Fsn(MAX_U32) < Fsn(100));
        assert!(Fsn(0) > Fsn(MAX_U32));
        assert!(Fsn(MAX_U32) < Fsn(0));
        assert!(Fsn(44) > Fsn(MAX_U32));
        assert!(Fsn(MAX_U32) < Fsn(44));
    }
}
