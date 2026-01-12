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

use crate::packet::SerializableTlv;
use crate::packet::parameter::RawParameter;
use crate::packet::parameter::write_parameter_header;
use anyhow::Error;
use core::fmt;

#[derive(Debug)]
pub(crate) struct UnknownParameter {
    typ: u16,
    value: Vec<u8>,
}

impl TryFrom<RawParameter<'_>> for UnknownParameter {
    type Error = Error;

    fn try_from(raw: RawParameter<'_>) -> Result<Self, Error> {
        Ok(Self { typ: raw.typ, value: raw.value.to_vec() })
    }
}

impl SerializableTlv for UnknownParameter {
    fn serialize_to(&self, output: &mut [u8]) {
        let value = write_parameter_header(self.typ, self.value_size(), output);
        value.copy_from_slice(&self.value)
    }

    fn value_size(&self) -> usize {
        self.value.len()
    }
}

impl fmt::Display for UnknownParameter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Unknown parameter, type={}", self.typ)
    }
}
