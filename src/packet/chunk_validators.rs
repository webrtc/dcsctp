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

use crate::packet::sack_chunk::SackChunk;
use std::cmp::max;

pub fn validate_sack(sack: &SackChunk) -> bool {
    if sack.gap_ack_blocks.is_empty() {
        return true;
    }

    // Ensure that gap-ack-blocks are sorted, has an "end" that is not before "start" and are
    // non-overlapping and non-adjacent.
    let mut prev_end = 0;
    for gap_ack_block in &sack.gap_ack_blocks {
        if gap_ack_block.end < gap_ack_block.start
            || (gap_ack_block.start as u32) <= (prev_end as u32 + 1)
        {
            return false;
        }
        prev_end = gap_ack_block.end;
    }
    true
}

pub fn clean_sack(sack: SackChunk) -> SackChunk {
    if validate_sack(&sack) {
        return sack;
    }

    // First, filter out invalid ranges.
    let mut gap_ack_blocks: Vec<_> =
        sack.gap_ack_blocks.into_iter().filter(|block| block.end >= block.start).collect();

    if gap_ack_blocks.len() <= 1 {
        return SackChunk {
            cumulative_tsn_ack: sack.cumulative_tsn_ack,
            a_rwnd: sack.a_rwnd,
            gap_ack_blocks,
            duplicate_tsns: sack.duplicate_tsns,
        };
    }

    // Sort the intervals by their start value, to aid in the merging below.
    gap_ack_blocks.sort_by_key(|block| block.start);

    let mut merged = Vec::with_capacity(gap_ack_blocks.len());
    merged.push(gap_ack_blocks[0].clone());

    for block in gap_ack_blocks.iter().skip(1) {
        if (merged.last().unwrap().end as u32) + 1 >= block.start as u32 {
            merged.last_mut().unwrap().end = max(merged.last().unwrap().end, block.end);
        } else {
            merged.push(block.clone());
        }
    }

    SackChunk {
        cumulative_tsn_ack: sack.cumulative_tsn_ack,
        a_rwnd: sack.a_rwnd,
        gap_ack_blocks: merged,
        duplicate_tsns: sack.duplicate_tsns,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::sack_chunk::GapAckBlock;
    use crate::types::Tsn;

    #[test]
    fn no_gap_ack_blocks_are_valid() {
        let sack = SackChunk {
            cumulative_tsn_ack: Tsn(123),
            a_rwnd: 456,
            gap_ack_blocks: vec![],
            duplicate_tsns: vec![],
        };

        assert!(validate_sack(&sack));
    }

    #[test]
    fn one_valid_ack_block() {
        let sack = SackChunk {
            cumulative_tsn_ack: Tsn(123),
            a_rwnd: 456,
            gap_ack_blocks: vec![GapAckBlock { start: 2, end: 3 }],
            duplicate_tsns: vec![],
        };

        assert!(validate_sack(&sack));
    }

    #[test]
    fn two_valid_ack_blocks() {
        let sack = SackChunk {
            cumulative_tsn_ack: Tsn(123),
            a_rwnd: 456,
            gap_ack_blocks: vec![
                GapAckBlock { start: 2, end: 3 },
                GapAckBlock { start: 5, end: 6 },
            ],
            duplicate_tsns: vec![],
        };

        assert!(validate_sack(&sack));
    }

    #[test]
    fn one_invalid_ack_block() {
        let sack = SackChunk {
            cumulative_tsn_ack: Tsn(123),
            a_rwnd: 456,
            gap_ack_blocks: vec![GapAckBlock { start: 1, end: 2 }],
            duplicate_tsns: vec![],
        };

        assert!(!validate_sack(&sack));

        // It's not strictly valid, but due to the renegable nature of gap ack blocks, the
        // cum_ack_tsn can't simply be moved.

        let sack = clean_sack(sack);
        assert_eq!(sack.gap_ack_blocks, vec![GapAckBlock { start: 1, end: 2 }]);
    }

    #[test]
    fn removes_invalid_gap_ack_block_from_sack() {
        let sack = SackChunk {
            cumulative_tsn_ack: Tsn(123),
            a_rwnd: 456,
            gap_ack_blocks: vec![
                GapAckBlock { start: 2, end: 3 },
                GapAckBlock { start: 6, end: 4 },
            ],
            duplicate_tsns: vec![],
        };

        assert!(!validate_sack(&sack));

        let sack = clean_sack(sack);
        assert_eq!(sack.gap_ack_blocks, vec![GapAckBlock { start: 2, end: 3 }]);
    }

    #[test]
    fn sorts_gap_ack_blocks_in_order() {
        let sack = SackChunk {
            cumulative_tsn_ack: Tsn(123),
            a_rwnd: 456,
            gap_ack_blocks: vec![
                GapAckBlock { start: 6, end: 7 },
                GapAckBlock { start: 3, end: 4 },
            ],
            duplicate_tsns: vec![],
        };

        assert!(!validate_sack(&sack));

        let sack = clean_sack(sack);
        assert_eq!(
            sack.gap_ack_blocks,
            vec![GapAckBlock { start: 3, end: 4 }, GapAckBlock { start: 6, end: 7 },]
        );
    }

    #[test]
    fn merges_adjacent_blocks() {
        let sack = SackChunk {
            cumulative_tsn_ack: Tsn(123),
            a_rwnd: 456,
            gap_ack_blocks: vec![
                GapAckBlock { start: 3, end: 4 },
                GapAckBlock { start: 5, end: 6 },
            ],
            duplicate_tsns: vec![],
        };

        assert!(!validate_sack(&sack));

        let sack = clean_sack(sack);
        assert_eq!(sack.gap_ack_blocks, vec![GapAckBlock { start: 3, end: 6 },]);
    }

    #[test]
    fn merges_overlapping_by_one() {
        let sack = SackChunk {
            cumulative_tsn_ack: Tsn(123),
            a_rwnd: 456,
            gap_ack_blocks: vec![
                GapAckBlock { start: 3, end: 4 },
                GapAckBlock { start: 4, end: 5 },
            ],
            duplicate_tsns: vec![],
        };

        assert!(!validate_sack(&sack));

        let sack = clean_sack(sack);
        assert_eq!(sack.gap_ack_blocks, vec![GapAckBlock { start: 3, end: 5 },]);
    }

    #[test]
    fn merges_overlapping_by_more() {
        let sack = SackChunk {
            cumulative_tsn_ack: Tsn(123),
            a_rwnd: 456,
            gap_ack_blocks: vec![
                GapAckBlock { start: 3, end: 10 },
                GapAckBlock { start: 4, end: 5 },
            ],
            duplicate_tsns: vec![],
        };

        assert!(!validate_sack(&sack));

        let sack = clean_sack(sack);
        assert_eq!(sack.gap_ack_blocks, vec![GapAckBlock { start: 3, end: 10 },]);
    }

    #[test]
    fn merges_blocks_starting_with_same_start_offset() {
        let sack = SackChunk {
            cumulative_tsn_ack: Tsn(123),
            a_rwnd: 456,
            gap_ack_blocks: vec![
                GapAckBlock { start: 3, end: 7 },
                GapAckBlock { start: 3, end: 5 },
                GapAckBlock { start: 3, end: 9 },
            ],
            duplicate_tsns: vec![],
        };

        assert!(!validate_sack(&sack));

        let sack = clean_sack(sack);
        assert_eq!(sack.gap_ack_blocks, vec![GapAckBlock { start: 3, end: 9 },]);
    }

    #[test]
    fn merges_blocks_partially_overlapping() {
        let sack = SackChunk {
            cumulative_tsn_ack: Tsn(123),
            a_rwnd: 456,
            gap_ack_blocks: vec![
                GapAckBlock { start: 3, end: 7 },
                GapAckBlock { start: 5, end: 9 },
            ],
            duplicate_tsns: vec![],
        };

        assert!(!validate_sack(&sack));

        let sack = clean_sack(sack);
        assert_eq!(sack.gap_ack_blocks, vec![GapAckBlock { start: 3, end: 9 },]);
    }

    #[test]
    fn validate_sack_overflow() {
        let sack = SackChunk {
            cumulative_tsn_ack: Tsn(123),
            a_rwnd: 456,
            gap_ack_blocks: vec![
                GapAckBlock { start: 65534, end: 65535 },
                GapAckBlock { start: 2, end: 3 },
            ],
            duplicate_tsns: vec![],
        };

        assert!(!validate_sack(&sack));
    }

    #[test]
    fn clean_sack_merges_with_overflow() {
        let sack = SackChunk {
            cumulative_tsn_ack: Tsn(123),
            a_rwnd: 456,
            gap_ack_blocks: vec![
                GapAckBlock { start: 2, end: 65535 },
                GapAckBlock { start: 10, end: 11 },
            ],
            duplicate_tsns: vec![],
        };

        let cleaned = clean_sack(sack);
        assert_eq!(cleaned.gap_ack_blocks.len(), 1);
        assert_eq!(cleaned.gap_ack_blocks[0].start, 2);
        assert_eq!(cleaned.gap_ack_blocks[0].end, 65535);
    }

    #[test]
    fn clean_sack_preserves_single_tsn_blocks() {
        let sack = SackChunk {
            cumulative_tsn_ack: Tsn(100),
            a_rwnd: 200,
            gap_ack_blocks: vec![
                GapAckBlock { start: 10, end: 10 },
                GapAckBlock { start: 5, end: 5 },
            ],
            duplicate_tsns: vec![],
        };

        // Validate fails because they are unsorted
        assert!(!validate_sack(&sack));

        let cleaned = clean_sack(sack);
        // Should sort and keep them
        assert_eq!(
            cleaned.gap_ack_blocks,
            vec![GapAckBlock { start: 5, end: 5 }, GapAckBlock { start: 10, end: 10 }]
        );
    }
}
