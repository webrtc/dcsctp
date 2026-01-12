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

use crate::packet::AsSerializableTlv;
use crate::packet::SerializableTlv;
use crate::packet::cookie_received_while_shutting_down::CookieReceivedWhileShuttingDownErrorCause;
use crate::packet::cookie_received_while_shutting_down::{self};
use crate::packet::no_user_data_error_cause::NoUserDataErrorCause;
use crate::packet::no_user_data_error_cause::{self};
use crate::packet::parameter::RawParameter;
use crate::packet::protocol_violation_error_cause::ProtocolViolationErrorCause;
use crate::packet::protocol_violation_error_cause::{self};
use crate::packet::unknown_parameter::UnknownParameter;
use crate::packet::unrecognized_chunk_error_cause::UnrecognizedChunkErrorCause;
use crate::packet::unrecognized_chunk_error_cause::{self};
use crate::packet::user_initiated_abort_error_cause::UserInitiatedAbortErrorCause;
use crate::packet::user_initiated_abort_error_cause::{self};
use anyhow::Error;
use std::fmt;

#[derive(Debug)]
pub enum ErrorCause {
    UnrecognizedChunk(UnrecognizedChunkErrorCause),
    NoUserData(NoUserDataErrorCause),
    CookieReceivedWhileShuttingDown(CookieReceivedWhileShuttingDownErrorCause),
    UserInitiatedAbort(UserInitiatedAbortErrorCause),
    ProtocolViolation(ProtocolViolationErrorCause),
    Unknown(UnknownParameter),
}

impl fmt::Display for ErrorCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let c: &dyn fmt::Display = match self {
            ErrorCause::UnrecognizedChunk(c) => c,
            ErrorCause::NoUserData(c) => c,
            ErrorCause::CookieReceivedWhileShuttingDown(c) => c,
            ErrorCause::UserInitiatedAbort(c) => c,
            ErrorCause::ProtocolViolation(c) => c,
            ErrorCause::Unknown(c) => c,
        };
        fmt::Display::fmt(c, f)
    }
}

impl TryFrom<RawParameter<'_>> for ErrorCause {
    type Error = Error;

    fn try_from(raw: RawParameter<'_>) -> Result<Self, Error> {
        match raw.typ {
            unrecognized_chunk_error_cause::CAUSE_CODE => {
                UnrecognizedChunkErrorCause::try_from(raw).map(ErrorCause::UnrecognizedChunk)
            }
            no_user_data_error_cause::CAUSE_CODE => {
                NoUserDataErrorCause::try_from(raw).map(ErrorCause::NoUserData)
            }
            cookie_received_while_shutting_down::CAUSE_CODE => {
                CookieReceivedWhileShuttingDownErrorCause::try_from(raw)
                    .map(ErrorCause::CookieReceivedWhileShuttingDown)
            }
            user_initiated_abort_error_cause::CAUSE_CODE => {
                UserInitiatedAbortErrorCause::try_from(raw).map(ErrorCause::UserInitiatedAbort)
            }
            protocol_violation_error_cause::CAUSE_CODE => {
                ProtocolViolationErrorCause::try_from(raw).map(ErrorCause::ProtocolViolation)
            }
            _ => UnknownParameter::try_from(raw).map(ErrorCause::Unknown),
        }
    }
}

impl AsSerializableTlv for ErrorCause {
    fn as_serializable(&self) -> &dyn SerializableTlv {
        match self {
            ErrorCause::UnrecognizedChunk(c) => c,
            ErrorCause::NoUserData(c) => c,
            ErrorCause::CookieReceivedWhileShuttingDown(c) => c,
            ErrorCause::UserInitiatedAbort(c) => c,
            ErrorCause::ProtocolViolation(c) => c,
            ErrorCause::Unknown(c) => c,
        }
    }
}

pub fn error_cause_from_bytes(data: &[u8]) -> Result<Vec<ErrorCause>, Error> {
    let mut result = Vec::<ErrorCause>::with_capacity(2);
    let mut remaining = data;

    while !remaining.is_empty() {
        let (raw, next_remaining) = RawParameter::from_bytes(remaining)?;
        let error_cause = ErrorCause::try_from(raw)?;
        result.push(error_cause);

        remaining = next_remaining;
    }
    Ok(result)
}
