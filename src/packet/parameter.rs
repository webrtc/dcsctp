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

use crate::math::round_up_to_4;
use crate::packet::forward_tsn_supported_parameter::ForwardTsnSupportedParameter;
use crate::packet::forward_tsn_supported_parameter::{self};
use crate::packet::heartbeat_info_parameter::HeartbeatInfoParameter;
use crate::packet::heartbeat_info_parameter::{self};
use crate::packet::incoming_ssn_reset_request_parameter::IncomingSsnResetRequestParameter;
use crate::packet::incoming_ssn_reset_request_parameter::{self};
use crate::packet::outgoing_ssn_reset_request_parameter::OutgoingSsnResetRequestParameter;
use crate::packet::outgoing_ssn_reset_request_parameter::{self};
use crate::packet::read_u16_be;
use crate::packet::reconfiguration_response_parameter::ReconfigurationResponseParameter;
use crate::packet::reconfiguration_response_parameter::{self};
use crate::packet::state_cookie_parameter::StateCookieParameter;
use crate::packet::state_cookie_parameter::{self};
use crate::packet::supported_extensions_parameter::SupportedExtensionsParameter;
use crate::packet::supported_extensions_parameter::{self};
use crate::packet::unknown_parameter::UnknownParameter;
use crate::packet::write_u16_be;
use crate::packet::zero_checksum_acceptable_parameter::ZeroChecksumAcceptableParameter;
use crate::packet::zero_checksum_acceptable_parameter::{self};
use crate::packet::AsSerializableTlv;
use crate::packet::ChunkParseError;
use crate::packet::SerializableTlv;
use crate::packet::TLV_HEADER_SIZE;
use anyhow::ensure;
use anyhow::Error;
use std::cmp;

pub(crate) const PARAMETER_HEADER_SIZE: usize = 4;

/// Represents the raw optional/variable-length parameter format, as defined in
/// <https://datatracker.ietf.org/doc/html/rfc9260#section-3.2.1>.
///
/// ```txt
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |        Parameter Type         |       Parameter Length        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// \                                                               \
/// /                        Parameter Value                        /
/// \                                                               \
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug)]
pub(crate) struct RawParameter<'a> {
    pub(crate) typ: u16,
    pub(crate) value: &'a [u8],
}

impl<'a> RawParameter<'a> {
    pub(crate) fn from_bytes(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), Error> {
        ensure!(bytes.len() >= PARAMETER_HEADER_SIZE, ChunkParseError::InvalidLength);
        let typ = read_u16_be!(&bytes[0..2]);
        let length = read_u16_be!(&bytes[2..4]) as usize;
        ensure!(length >= TLV_HEADER_SIZE && length <= bytes.len(), ChunkParseError::InvalidLength);
        let padded_length = round_up_to_4!(length);
        let end_offset = cmp::min(padded_length, bytes.len());

        Ok((Self { typ, value: &bytes[PARAMETER_HEADER_SIZE..length] }, &bytes[end_offset..]))
    }
}

/// Writes a parameter header with the provided arguments and returns the remaining part of the
/// parameter (its value) that may be filled in by the caller with additional data.
#[inline]
pub fn write_parameter_header(typ: u16, value_size: usize, output: &mut [u8]) -> &mut [u8] {
    let serialized_size = PARAMETER_HEADER_SIZE + value_size;
    assert!(output.len() >= serialized_size);
    write_u16_be!(&mut output[0..2], typ);
    write_u16_be!(&mut output[2..4], serialized_size as u16);
    &mut output[PARAMETER_HEADER_SIZE..serialized_size]
}

// Unhandled, but known types, from <https://datatracker.ietf.org/doc/html/rfc6525#section-4>. These
// are "known by type", but their payload is mapped to [`UnknownParameter`].
pub const PARAMETER_TYPE_SSN_TSN_RESET_REQUEST: u16 = 15;
pub const PARAMETER_TYPE_ADD_OUTGOING_STREAMS_REQUEST: u16 = 17;
pub const PARAMETER_TYPE_ADD_INCOMING_STREAMS_REQUEST: u16 = 18;

#[derive(Debug)]
pub enum Parameter {
    HeartbeatInfo(HeartbeatInfoParameter),
    StateCookie(StateCookieParameter),
    OutgoingSsnResetRequest(OutgoingSsnResetRequestParameter),
    IncomingSsnResetRequest(IncomingSsnResetRequestParameter),
    SsnTsnResetRequest(UnknownParameter),
    ReconfigurationResponse(ReconfigurationResponseParameter),
    AddOutgoingStreamsRequest(UnknownParameter),
    AddIncomingStreamsRequest(UnknownParameter),
    SupportedExtensions(SupportedExtensionsParameter),
    ForwardTsnSupported(ForwardTsnSupportedParameter),
    ZeroChecksumAcceptable(ZeroChecksumAcceptableParameter),
    Unknown(UnknownParameter),
}

impl TryFrom<RawParameter<'_>> for Parameter {
    type Error = Error;

    fn try_from(raw: RawParameter<'_>) -> Result<Self, Error> {
        match raw.typ {
            heartbeat_info_parameter::PARAMETER_TYPE => {
                HeartbeatInfoParameter::try_from(raw).map(Parameter::HeartbeatInfo)
            }
            state_cookie_parameter::PARAMETER_TYPE => {
                StateCookieParameter::try_from(raw).map(Parameter::StateCookie)
            }
            supported_extensions_parameter::PARAMETER_TYPE => {
                SupportedExtensionsParameter::try_from(raw).map(Parameter::SupportedExtensions)
            }
            zero_checksum_acceptable_parameter::PARAMETER_TYPE => {
                ZeroChecksumAcceptableParameter::try_from(raw)
                    .map(Parameter::ZeroChecksumAcceptable)
            }
            forward_tsn_supported_parameter::PARAMETER_TYPE => {
                ForwardTsnSupportedParameter::try_from(raw).map(Parameter::ForwardTsnSupported)
            }
            outgoing_ssn_reset_request_parameter::PARAMETER_TYPE => {
                OutgoingSsnResetRequestParameter::try_from(raw)
                    .map(Parameter::OutgoingSsnResetRequest)
            }
            incoming_ssn_reset_request_parameter::PARAMETER_TYPE => {
                IncomingSsnResetRequestParameter::try_from(raw)
                    .map(Parameter::IncomingSsnResetRequest)
            }
            PARAMETER_TYPE_SSN_TSN_RESET_REQUEST => {
                UnknownParameter::try_from(raw).map(Parameter::SsnTsnResetRequest)
            }
            reconfiguration_response_parameter::PARAMETER_TYPE => {
                ReconfigurationResponseParameter::try_from(raw)
                    .map(Parameter::ReconfigurationResponse)
            }
            PARAMETER_TYPE_ADD_OUTGOING_STREAMS_REQUEST => {
                UnknownParameter::try_from(raw).map(Parameter::SsnTsnResetRequest)
            }
            PARAMETER_TYPE_ADD_INCOMING_STREAMS_REQUEST => {
                UnknownParameter::try_from(raw).map(Parameter::SsnTsnResetRequest)
            }
            _ => UnknownParameter::try_from(raw).map(Parameter::Unknown),
        }
    }
}

impl AsSerializableTlv for Parameter {
    fn as_serializable(&self) -> &dyn SerializableTlv {
        match self {
            Parameter::HeartbeatInfo(p) => p,
            Parameter::StateCookie(p) => p,
            Parameter::OutgoingSsnResetRequest(p) => p,
            Parameter::IncomingSsnResetRequest(p) => p,
            Parameter::SsnTsnResetRequest(p) => p,
            Parameter::ReconfigurationResponse(p) => p,
            Parameter::AddOutgoingStreamsRequest(p) => p,
            Parameter::AddIncomingStreamsRequest(p) => p,
            Parameter::SupportedExtensions(p) => p,
            Parameter::ForwardTsnSupported(p) => p,
            Parameter::ZeroChecksumAcceptable(p) => p,
            Parameter::Unknown(p) => p,
        }
    }
}

pub fn parameters_from_bytes(data: &[u8]) -> Result<Vec<Parameter>, Error> {
    let mut result = Vec::<Parameter>::with_capacity(2);
    let mut remaining = data;

    while !remaining.is_empty() {
        let (raw, next_remaining) = RawParameter::from_bytes(remaining)?;
        let error_cause = Parameter::try_from(raw)?;
        result.push(error_cause);

        remaining = next_remaining;
    }
    Ok(result)
}

pub fn parameters_serialized_size<T: AsSerializableTlv>(params: &[T]) -> usize {
    let mut size: usize = 0;
    for (idx, p) in params.iter().enumerate() {
        size += p.as_serializable().serialized_size();
        if idx != params.len() - 1 {
            size = round_up_to_4!(size);
        }
    }
    size
}

pub fn parameters_serialize_to<T: AsSerializableTlv>(params: &[T], out: &mut [u8]) {
    let mut offset: usize = 0;
    for p in params {
        let serializable = p.as_serializable();
        let size = serializable.serialized_size();
        serializable.serialize_to(&mut out[offset..offset + size]);
        offset += round_up_to_4!(size);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fuzz() {
        const DATA: &[u8] = &[0, 16, 0, 8, 0, 0, 0, 0];
        let _ = parameters_from_bytes(DATA);
    }
}
