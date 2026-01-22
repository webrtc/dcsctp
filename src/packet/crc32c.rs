// Copyright 2026 The dcSCTP Authors
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

// CRC-32C polynomial in reversed bit order.
const CRC32C_POLY: u32 = 0x82F63B78;

const fn generate_tables() -> [[u32; 256]; 8] {
    let mut tables = [[0u32; 256]; 8];
    let mut i = 0;

    // Generate the first table (for single byte processing).
    while i < 256 {
        let mut crc = i as u32;
        let mut j = 0;
        while j < 8 {
            if (crc & 1) != 0 {
                crc = (crc >> 1) ^ CRC32C_POLY;
            } else {
                crc >>= 1;
            }
            j += 1;
        }
        tables[0][i] = crc;
        i += 1;
    }

    // Generate subsequent tables (for 8 bytes at a time).
    let mut k = 1;
    while k < 8 {
        let mut i = 0;
        while i < 256 {
            let prev = tables[k - 1][i];
            tables[k][i] = (prev >> 8) ^ tables[0][(prev & 0xff) as usize];
            i += 1;
        }
        k += 1;
    }
    tables
}

const CRC32C_LOOKUP_TABLE: [[u32; 256]; 8] = generate_tables();

/// CRC-32C (Castagnoli) checksum algorithm.
///
/// This implementation uses the **Castagnoli** polynomial, which is distinct from the standard
/// CRC-32 (ISO 3309).
pub struct Crc32c(u32);

impl Crc32c {
    pub fn new() -> Self {
        Self(0xffffffff)
    }

    pub fn digest(&mut self, data: &[u8]) {
        let mut crc = self.0;
        let mut iter = data.chunks_exact(8);

        // Process 8 bytes at a time.
        for chunk in iter.by_ref() {
            let current_chunk = u64::from_le_bytes(chunk.try_into().unwrap());
            let idx = (crc as u64) ^ current_chunk;

            crc = CRC32C_LOOKUP_TABLE[7][(idx as u8) as usize]
                ^ CRC32C_LOOKUP_TABLE[6][((idx >> 8) as u8) as usize]
                ^ CRC32C_LOOKUP_TABLE[5][((idx >> 16) as u8) as usize]
                ^ CRC32C_LOOKUP_TABLE[4][((idx >> 24) as u8) as usize]
                ^ CRC32C_LOOKUP_TABLE[3][((idx >> 32) as u8) as usize]
                ^ CRC32C_LOOKUP_TABLE[2][((idx >> 40) as u8) as usize]
                ^ CRC32C_LOOKUP_TABLE[1][((idx >> 48) as u8) as usize]
                ^ CRC32C_LOOKUP_TABLE[0][((idx >> 56) as u8) as usize];
        }

        // Process remaining bytes.
        for &byte in iter.remainder() {
            crc = (crc >> 8) ^ CRC32C_LOOKUP_TABLE[0][((crc ^ byte as u32) & 0xff) as usize];
        }

        self.0 = crc;
    }

    pub fn value(&self) -> u32 {
        !self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crc32c_empty() {
        let mut crc = Crc32c::new();
        crc.digest(&[]);
        assert_eq!(crc.value(), 0x00000000);
    }

    #[test]
    fn test_table_0() {
        // See the table at <https://datatracker.ietf.org/doc/html/rfc9260#appendix-A>.
        assert_eq!(CRC32C_LOOKUP_TABLE[0][0], 0x00000000);
        assert_eq!(CRC32C_LOOKUP_TABLE[0][1], 0xf26b8303);
        assert_eq!(CRC32C_LOOKUP_TABLE[0][255], 0xad7d5351);
    }

    #[test]
    fn test_crc32c_vectors() {
        // Standard test vectors for CRC32c (Castagnoli)
        // Check "123456789"
        let mut crc = Crc32c::new();
        crc.digest(b"123456789");
        assert_eq!(crc.value(), 0xe3069283);

        // 4 bytes (less than 8)
        let mut crc = Crc32c::new();
        crc.digest(b"1234");
        assert_eq!(crc.value(), 0xf63af4ee);

        // 8 bytes (exactly one chunk)
        let mut crc = Crc32c::new();
        crc.digest(b"12345678");
        assert_eq!(crc.value(), 0x6087809a);
    }

    #[test]
    fn test_vs_reference() {
        // See <https://datatracker.ietf.org/doc/html/rfc9260#appendix-A>.
        fn reference_crc32c(data: &[u8]) -> u32 {
            let mut crc: u32 = 0xffffffff;
            for &byte in data {
                crc = (crc >> 8) ^ CRC32C_LOOKUP_TABLE[0][((crc ^ byte as u32) & 0xff) as usize];
            }
            !crc
        }

        // Test various lengths from 0 to 100
        for len in 0..100 {
            // Create determinstic "random" data
            let data: Vec<u8> = (0..len).map(|i| (i * 17) as u8).collect();

            let mut crc = Crc32c::new();
            crc.digest(&data);

            let ref_val = reference_crc32c(&data);
            assert_eq!(crc.value(), ref_val, "Failed for length {}", len);
        }

        // Test a larger buffer to ensure no issues with multiple chunks
        let data: Vec<u8> = (0..1024).map(|i| (i * 13) as u8).collect();
        let mut crc = Crc32c::new();
        crc.digest(&data);
        assert_eq!(crc.value(), reference_crc32c(&data));
    }
}
