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

use thiserror::Error;

pub(crate) mod abort_chunk;
pub(crate) mod chunk;
pub(crate) mod chunk_validators;
pub(crate) mod cookie_ack_chunk;
pub(crate) mod cookie_echo_chunk;
pub(crate) mod cookie_received_while_shutting_down;
pub(crate) mod data;
pub(crate) mod data_chunk;
pub(crate) mod error_causes;
pub(crate) mod error_chunk;
pub(crate) mod forward_tsn_chunk;
pub(crate) mod forward_tsn_supported_parameter;
pub(crate) mod heartbeat_ack_chunk;
pub(crate) mod heartbeat_info_parameter;
pub(crate) mod heartbeat_request_chunk;
pub(crate) mod idata_chunk;
pub(crate) mod iforward_tsn_chunk;
pub(crate) mod incoming_ssn_reset_request_parameter;
pub(crate) mod init_ack_chunk;
pub(crate) mod init_chunk;
pub(crate) mod no_user_data_error_cause;
pub(crate) mod outgoing_ssn_reset_request_parameter;
pub(crate) mod parameter;
pub(crate) mod protocol_violation_error_cause;
pub(crate) mod re_config_chunk;
pub(crate) mod reconfiguration_response_parameter;
pub(crate) mod sack_chunk;
pub(crate) mod sctp_packet;
pub(crate) mod shutdown_ack_chunk;
pub(crate) mod shutdown_chunk;
pub(crate) mod shutdown_complete_chunk;
pub(crate) mod state_cookie_parameter;
pub(crate) mod supported_extensions_parameter;
pub(crate) mod unknown_chunk;
pub(crate) mod unknown_parameter;
pub(crate) mod unrecognized_chunk_error_cause;
pub(crate) mod user_initiated_abort_error_cause;
pub(crate) mod zero_checksum_acceptable_parameter;

/// Size of the Type-Length-Value header, used by chunks, parameters and error causes.
pub(crate) const TLV_HEADER_SIZE: usize = 4;

macro_rules! read_u16_be {
    ($buf: expr) => {
        u16::from_be_bytes($buf[..2].try_into().unwrap())
    };
}

macro_rules! read_u32_be {
    ($buf: expr) => {
        u32::from_be_bytes($buf[..4].try_into().unwrap())
    };
}

macro_rules! read_u64_be {
    ($buf: expr) => {
        u64::from_be_bytes($buf[..8].try_into().unwrap())
    };
}

macro_rules! write_u16_be {
    ($buf: expr, $n: expr) => {
        $buf[..2].copy_from_slice(&($n as u16).to_be_bytes());
    };
}

macro_rules! write_u32_be {
    ($buf: expr, $n: expr) => {
        $buf[..4].copy_from_slice(&($n as u32).to_be_bytes());
    };
}

macro_rules! write_u64_be {
    ($buf: expr, $n: expr) => {
        $buf[..8].copy_from_slice(&($n as u64).to_be_bytes());
    };
}

use crate::api::StreamId;
use crate::types::Mid;
use crate::types::Ssn;
use crate::types::StreamKey;
pub(crate) use read_u16_be;
pub(crate) use read_u32_be;
pub(crate) use read_u64_be;
pub(crate) use write_u16_be;
pub(crate) use write_u32_be;
pub(crate) use write_u64_be;

#[derive(Debug, PartialEq)]
pub(crate) enum SkippedStream {
    ForwardTsn(StreamId, Ssn),
    IForwardTsn(StreamKey, Mid),
}

/// Trait for serialization/deserialization methods on TLV data types (chunks, parameters, error
/// causes) that have the same framing, but handle metadata (type, flags etc) differently.
pub(crate) trait SerializableTlv {
    /// Serializes this TLV object to a byte array. Callers are expected to call
    /// [`Self::serialized_size`] prior to calling this method, to ensure that `output` is large
    /// enough.
    fn serialize_to(&self, output: &mut [u8]);

    /// Returns how many bytes of value payload this TLV object has, which together with the TLV
    /// header size becomes the full serialized size.
    fn value_size(&self) -> usize;

    /// Returns the number of bytes this TLV object serializes to.
    fn serialized_size(&self) -> usize {
        TLV_HEADER_SIZE + self.value_size()
    }
}

/// Trait for enums that carry objects that implement [`SerializableTlv`].
pub trait AsSerializableTlv {
    fn as_serializable(&self) -> &dyn SerializableTlv;
}

#[allow(clippy::enum_variant_names)]
#[derive(Debug, Error, PartialEq)]
#[non_exhaustive]
pub enum ChunkParseError {
    #[error("The TLV data has an invalid length field, or payload size")]
    InvalidLength,

    #[error("Unexpected TLV type")]
    InvalidType,

    #[error("Incorrect number of padding bytes")]
    InvalidPadding,

    #[error("Invalid value")]
    InvalidValue,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_big_endian() {
        let a = &[1, 2, 3, 4, 5, 6, 7, 8];
        assert_eq!(read_u16_be!(a), 0x0102);
        assert_eq!(read_u32_be!(a), 0x01020304);
        assert_eq!(read_u64_be!(a), 0x0102030405060708);
    }

    #[test]
    fn write_big_endian() {
        let mut a: Vec<u8> = vec![0; 8];
        write_u16_be!(&mut a, 0xcafe);
        assert_eq!(a, &[0xca, 0xfe, 0, 0, 0, 0, 0, 0]);
        write_u32_be!(&mut a, 0xdeadbeef);
        assert_eq!(a, &[0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0]);
        write_u64_be!(&mut a, 0xdeadbeefbaadf00d);
        assert_eq!(a, &[0xde, 0xad, 0xbe, 0xef, 0xba, 0xad, 0xf0, 0x0d]);
    }
}
