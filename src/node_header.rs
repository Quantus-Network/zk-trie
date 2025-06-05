// This file is part of Substrate.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! The node header.

use codec::{Decode, Encode, Input, Output};
use core::iter::once;

/// A node header
#[derive(Copy, Clone, PartialEq, Eq, sp_core::RuntimeDebug)]
pub(crate) enum NodeHeader {
    Null,
    // contains wether there is a value and nibble count
    Branch(bool, usize),
    // contains nibble count
    Leaf(usize),
    // contains nibble count.
    HashedValueBranch(usize),
    // contains nibble count.
    HashedValueLeaf(usize),
}

impl NodeHeader {
    pub(crate) fn contains_hash_of_value(&self) -> bool {
        matches!(
            self,
            NodeHeader::HashedValueBranch(_) | NodeHeader::HashedValueLeaf(_)
        )
    }
}

/// NodeHeader without content
pub(crate) enum NodeKind {
    Leaf,
    BranchNoValue,
    BranchWithValue,
    HashedValueLeaf,
    HashedValueBranch,
}

impl Encode for NodeHeader {
    fn encode_to<T: Output + ?Sized>(&self, output: &mut T) {
        let value: u64 = match self {
            NodeHeader::Null => 0x00000000_00000000, // Type 0
            NodeHeader::Branch(true, nibble_count) => {
                (1u64 << 60) | (*nibble_count as u64) // Type 1
            }
            NodeHeader::Branch(false, nibble_count) => {
                (2u64 << 60) | (*nibble_count as u64) // Type 2
            }
            NodeHeader::Leaf(nibble_count) => {
                (3u64 << 60) | (*nibble_count as u64) // Type 3
            }
            NodeHeader::HashedValueBranch(nibble_count) => {
                (4u64 << 60) | (*nibble_count as u64) // Type 4
            }
            NodeHeader::HashedValueLeaf(nibble_count) => {
                (5u64 << 60) | (*nibble_count as u64) // Type 5
            }
        };
        output.write(&value.to_le_bytes());
    }
}

impl codec::EncodeLike for NodeHeader {}

impl Decode for NodeHeader {
    fn decode<I: Input>(input: &mut I) -> Result<Self, codec::Error> {
        let mut bytes = [0u8; 8];
        input.read(&mut bytes)?;
        let value = u64::from_le_bytes(bytes);
        let type_code = (value >> 60) & 0xF; // Extract bits 63–60
        let nibble_count = (value & 0xFFFFFFFF) as usize; // Extract bits 31–0
        match type_code {
            0 => Ok(NodeHeader::Null),
            1 => Ok(NodeHeader::Branch(true, nibble_count)),
            2 => Ok(NodeHeader::Branch(false, nibble_count)),
            3 => Ok(NodeHeader::Leaf(nibble_count)),
            4 => Ok(NodeHeader::HashedValueBranch(nibble_count)),
            5 => Ok(NodeHeader::HashedValueLeaf(nibble_count)),
            _ => Err(codec::Error::from("Invalid NodeHeader type")),
        }
    }
}

/// Returns an iterator over encoded bytes for node header and size.
/// Size encoding allows unlimited, length inefficient, representation, but
/// is bounded to 16 bit maximum value to avoid possible DOS.
pub(crate) fn size_and_prefix_iterator(
    size: usize,
    prefix: u8,
    prefix_mask: usize,
) -> impl Iterator<Item = u8> {
    let max_value = 255u8 >> prefix_mask;
    let l1 = core::cmp::min((max_value as usize).saturating_sub(1), size);
    let (first_byte, mut rem) = if size == l1 {
        (once(prefix + l1 as u8), 0)
    } else {
        (once(prefix + max_value as u8), size - l1)
    };
    let next_bytes = move || {
        if rem > 0 {
            if rem < 256 {
                let result = rem - 1;
                rem = 0;
                Some(result as u8)
            } else {
                rem = rem.saturating_sub(255);
                Some(255)
            }
        } else {
            None
        }
    };
    first_byte.chain(core::iter::from_fn(next_bytes))
}

/// Encodes size and prefix to a stream output.
fn encode_size_and_prefix<W>(size: usize, prefix: u8, prefix_mask: usize, out: &mut W)
where
    W: Output + ?Sized,
{
    for b in size_and_prefix_iterator(size, prefix, prefix_mask) {
        out.push_byte(b)
    }
}

/// Decode size only from stream input and header byte.
fn decode_size(
    first: u8,
    input: &mut impl Input,
    prefix_mask: usize,
) -> Result<usize, codec::Error> {
    let max_value = 255u8 >> prefix_mask;
    let mut result = (first & max_value) as usize;
    if result < max_value as usize {
        return Ok(result);
    }
    result -= 1;
    loop {
        let n = input.read_byte()? as usize;
        if n < 255 {
            return Ok(result + n + 1);
        }
        result += 255;
    }
}
