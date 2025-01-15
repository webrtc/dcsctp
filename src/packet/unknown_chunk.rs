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

use crate::packet::chunk::write_chunk_header;
use crate::packet::chunk::RawChunk;
use crate::packet::SerializableTlv;
use anyhow::Error;
use core::fmt;

#[derive(Debug)]
pub(crate) struct UnknownChunk {
    pub(crate) typ: u8,
    pub(crate) flags: u8,
    pub(crate) value: Vec<u8>,
}

impl TryFrom<RawChunk<'_>> for UnknownChunk {
    type Error = Error;

    fn try_from(raw: RawChunk<'_>) -> Result<Self, Error> {
        Ok(Self { typ: raw.typ, flags: raw.flags, value: raw.value.to_vec() })
    }
}

impl SerializableTlv for UnknownChunk {
    fn serialize_to(&self, output: &mut [u8]) {
        let value = write_chunk_header(self.typ, self.flags, self.value_size(), output);
        value.copy_from_slice(&self.value)
    }

    fn value_size(&self) -> usize {
        self.value.len()
    }
}

impl fmt::Display for UnknownChunk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Unknown chunk, type={}", self.typ)
    }
}
