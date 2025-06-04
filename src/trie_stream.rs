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

//! `TrieStream` implementation for Substrate's trie format.

use crate::{
	node_header::{size_and_prefix_iterator, NodeKind},
	trie_constants,
};
use alloc::vec::Vec;
use codec::{Compact, Encode};
use hash_db::Hasher;
use trie_root;

/// Codec-flavored TrieStream.
#[derive(Default, Clone)]
pub struct TrieStream {
	/// Current node buffer.
	buffer: Vec<u8>,
}

impl TrieStream {
	// useful for debugging but not used otherwise
	pub fn as_raw(&self) -> &[u8] {
		&self.buffer
	}
}

fn branch_node_bit_mask(has_children: impl Iterator<Item = bool>) -> [u8; 8] {
	let mut bitmap: u64 = 0;
	let mut cursor: u64 = 1;
	for v in has_children {
		if v {
			bitmap |= cursor
		}
		cursor <<= 1;
	}
	bitmap.to_le_bytes()
}

/// Create a leaf/branch node, encoding a number of nibbles.
fn fuse_nibbles_node(nibbles: &[u8], kind: NodeKind) -> Vec<u8> {
	use crate::node_header::NodeHeader;
	use codec::Encode;
	
	let size = nibbles.len();
	
	// Create the appropriate NodeHeader and encode it to 8 bytes
	let header = match kind {
		NodeKind::Leaf => NodeHeader::Leaf(size),
		NodeKind::BranchNoValue => NodeHeader::Branch(false, size),
		NodeKind::BranchWithValue => NodeHeader::Branch(true, size),
		NodeKind::HashedValueLeaf => NodeHeader::HashedValueLeaf(size),
		NodeKind::HashedValueBranch => NodeHeader::HashedValueBranch(size),
	};
	
	let mut result = header.encode();
	
	// Calculate nibble bytes needed and felt-align to 8-byte boundary
	let nibble_bytes = (size + 1) / 2; // Round up for odd nibble counts
	let felt_aligned_bytes = ((nibble_bytes + 7) / 8) * 8;
	
	// Encode nibbles into bytes
	let mut partial_bytes = Vec::new();
	if size % 2 == 1 {
		partial_bytes.push(nibbles[0]);
	}
	for chunk in nibbles[size % 2..].chunks(2) {
		partial_bytes.push(chunk[0] << 4 | chunk[1]);
	}
	
	// Add the partial bytes
	result.extend_from_slice(&partial_bytes);
	
	// Pad with zeros to reach felt-aligned length
	while result.len() - 8 < felt_aligned_bytes {
		result.push(0);
	}
	
	result
}

use trie_root::Value as TrieStreamValue;
impl trie_root::TrieStream for TrieStream {
	fn new() -> Self {
		Self { buffer: Vec::new() }
	}

	fn append_empty_data(&mut self) {
		self.buffer.extend_from_slice(&trie_constants::EMPTY_TRIE);
	}

	fn append_leaf(&mut self, key: &[u8], value: TrieStreamValue) {
		let kind = match &value {
			TrieStreamValue::Inline(..) => NodeKind::Leaf,
			TrieStreamValue::Node(..) => NodeKind::HashedValueLeaf,
		};
		self.buffer.extend_from_slice(&fuse_nibbles_node(key, kind));
		match &value {
			TrieStreamValue::Inline(value) => {
				Compact(value.len() as u32).encode_to(&mut self.buffer);
				self.buffer.extend_from_slice(value);
			},
			TrieStreamValue::Node(hash) => {
				self.buffer.extend_from_slice(hash.as_slice());
			},
		};
	}

	fn begin_branch(
		&mut self,
		maybe_partial: Option<&[u8]>,
		maybe_value: Option<TrieStreamValue>,
		has_children: impl Iterator<Item = bool>,
	) {
		if let Some(partial) = maybe_partial {
			let kind = match &maybe_value {
				None => NodeKind::BranchNoValue,
				Some(TrieStreamValue::Inline(..)) => NodeKind::BranchWithValue,
				Some(TrieStreamValue::Node(..)) => NodeKind::HashedValueBranch,
			};

			self.buffer.extend_from_slice(&fuse_nibbles_node(partial, kind));
			let bm = branch_node_bit_mask(has_children);
			self.buffer.extend_from_slice(&bm);
		} else {
			unreachable!("trie stream codec only for no extension trie");
		}
		match maybe_value {
			None => (),
			Some(TrieStreamValue::Inline(value)) => {
				Compact(value.len() as u32).encode_to(&mut self.buffer);
				self.buffer.extend_from_slice(value);
			},
			Some(TrieStreamValue::Node(hash)) => {
				self.buffer.extend_from_slice(hash.as_slice());
			},
		}
	}

	fn append_extension(&mut self, _key: &[u8]) {
		debug_assert!(false, "trie stream codec only for no extension trie");
	}

	fn append_substream<H: Hasher>(&mut self, other: Self) {
		let data = other.out();
		match data.len() {
			0..=31 => data.encode_to(&mut self.buffer),
			_ => H::hash(&data).as_ref().encode_to(&mut self.buffer),
		}
	}

	fn out(self) -> Vec<u8> {
		self.buffer
	}
}
