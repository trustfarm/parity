// Copyright 2015, 2016 Ethcore (UK) Ltd.
// This file is part of Parity.

// Parity is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Parity is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Parity.  If not, see <http://www.gnu.org/licenses/>.

//! Inserts all account code sizes into the database.

use rlp::{Rlp, View};

use util::kvdb::Database;
use util::migration::{Batch, Config, Error, Migration, Progress};
use util::hash::{FixedHash, H256};
use util::trie::{TrieDB, Trie};
use util::journaldb;

use views::HeaderView;

use std::sync::Arc;

// constants reproduced here for backwards compatibility.
const COL_STATE: Option<u32> = Some(0);
const COL_HEADERS: Option<u32> = Some(1);
const COL_EXTRA: Option<u32> = Some(3);
const NUM_COLUMNS: Option<u32> = Some(5);

const CODE_SIZE_KEY: H256 = H256([
	b'c', b'o', b'n', b't', b'r', b'a', b'c', b't', b'c', b'o', b'd', b'e',
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
]);

// same as accountdb mangle at the time of writing -- reproduced for backwards
// compatibility.
#[inline]
fn combine_key(addr_hash: &H256, key: &H256) -> H256 {
	let mut dst = key.clone();
	{
		let last_src: &[u8] = &*addr_hash;
		let last_dst: &mut [u8] = &mut *dst;

		for (k, a) in last_dst[12..].iter_mut().zip(&last_src[12..]) {
			*k ^= *a
		}
	}

	dst
}

/// Inserts all account code sizes into the database.
pub struct ToV10 {
	pruning: journaldb::Algorithm,
	progress: Progress,
}

impl ToV10 {
	/// Create a new `ToV10` migration for a given pruning algorithm.
	pub fn new(pruning: journaldb::Algorithm) -> Self {
		ToV10 {
			pruning: pruning,
			progress: Progress::default(),
		}
	}

}

impl Migration for ToV10 {
	fn columns(&self) -> Option<u32> { NUM_COLUMNS }

	fn version(&self) -> u32 { 10 }

	fn migrate(&mut self, source: Arc<Database>, config: &Config, dest: &mut Database, col: Option<u32>) -> Result<(), Error> {
		let mut batch = Batch::new(config, col);

		// first, copy over all the existing column data.
		for (key, value) in source.iter(col) {
			self.progress.tick();
			try!(batch.insert(key.to_vec(), value.to_vec(), dest))
		}
		try!(batch.commit(dest));

		// only do the next bits once -- and only for the state column.
		if col != COL_STATE { return Ok(()) }

		// next, try and find the best block hash.
		let best = match try!(source.get(COL_EXTRA, b"best")) {
			Some(b) => H256::from_slice(&b),
			None => return Ok(()), // no best block? no state to migrate!
		};

		let best_header_raw = match try!(source.get(COL_HEADERS, &best)) {
			Some(raw) => raw.to_vec(),
			None => return Err(Error::Custom("Corrupted database: missing best block header".into())),
		};

		let state_root = HeaderView::new(&best_header_raw).state_root();

		let db = journaldb::new(source.clone(), self.pruning, col);

		let trie_err = "Corrupted database: missing trie nodes.".to_owned();

		// iterate over all accounts (addr_hash -> account RLP) in the trie.
		let trie = try!(TrieDB::new(db.as_hashdb(), &state_root)
			.map_err(|_| Error::Custom(trie_err.clone())));

		for item in try!(trie.iter().map_err(|_| Error::Custom(trie_err.clone()))) {
			self.progress.tick();

			let (addr_hash, raw_acc) = try!(item.map_err(|_| Error::Custom(trie_err.clone())));

			let addr_hash: H256 = H256::from_slice(&addr_hash);
			let code_hash: H256 = Rlp::new(&raw_acc).val_at(3);

			if code_hash == ::util::sha3::SHA3_EMPTY { continue }
			let code_key = combine_key(&addr_hash, &code_hash);

			// fetch the code size if it's got code.
			let size = match db.get(&code_key) {
				Some(code) => code.len(),
				None => return Err(Error::Custom("Corrupted database: code lookup failed.".into())),
			};

			// and insert that into the database.
			let size_key = combine_key(&addr_hash, &CODE_SIZE_KEY);

			try!(batch.insert(size_key.to_vec(), ::rlp::encode(&size).to_vec(), dest));

			self.progress.tick();
		}

		batch.commit(dest)
	}
}