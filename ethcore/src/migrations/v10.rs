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


//! This migration adds account bloom for state database

use util::kvdb::{Database, DBTransaction};
use util::journaldb;
use util::migration::{Batch, Config, Error, Migration, Progress};
use util::{H128k, FixedHash, BytesConvertable, H256	};
use client::{DB_COL_EXTRA, DB_COL_HEADERS};
use state_db::{ACCOUNT_BLOOM_HASHCOUNT, ACCOUNT_BLOOM_COLUMN_NAME};
use util::trie::TrieDB;
use views::HeaderView;

/// Adding account bloom for state database
pub struct ToV10;

impl Migration for ToV10 {

	fn columns(&self) -> Option<u32> { Some(5) }

	fn version(&self) -> u32 { 10 }

	fn migrate(&mut self, source: &Database, config: &Config, dest: &mut Database, _col: Option<u32>) -> Result<(), Error> {
		let best_block_hash = match try!(source.get(DB_COL_EXTRA, b"best")) {
			// no migration needed
			None => { return Ok(()); }
			Some(hash) => hash,
		};
		let best_block_header = try!(source.get(DB_COL_HEADERS, &best_block_hash))
			.expect("No migration possible: no best block header data");

		let state_root = HeaderView::new(&best_block_header).state_root();

		let mut bloom = H128k::zero();
		// no difference what algorithm is passed, since there will be no writes
		let state_db = journaldb::new(
			::std::sync::Arc::new(source),
			journaldb::Algorithm::OverlayRecent,
			self.columns());
		let account_trie = try!(TrieDB::new(state_db.as_hashdb(), &state_root).map_err(|e| Error::Custom(format!("Cannot open trie: {:?}", e))));
		for (ref account_key, _) in account_trie.iter() {
			let account_key_hash = H256::from_slice(&account_key);
			bloom.shift_bloomed(ACCOUNT_BLOOM_HASHCOUNT, &account_key_hash);
		}

		let batch = DBTransaction::new(dest);
		batch.put(None, ACCOUNT_BLOOM_COLUMN_NAME, bloom.as_slice());
		dest.write(batch);

		Ok(())
	}
}
