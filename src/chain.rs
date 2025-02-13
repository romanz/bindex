use crate::index;

use bitcoin::{hashes::Hash, BlockHash};
use log::*;

pub struct Chain {
    rows: Vec<index::Header>,
}

impl Chain {
    pub fn new(rows: Vec<index::Header>) -> Self {
        info!("loaded {} headers", rows.len());
        let mut block_hash = bitcoin::BlockHash::all_zeros();
        for row in &rows {
            assert_eq!(row.header().prev_blockhash, block_hash);
            block_hash = row.hash();
        }
        debug!("verified {} headers, tip={}", rows.len(), block_hash);
        Self { rows }
    }

    pub fn tip_hash(&self) -> Option<bitcoin::BlockHash> {
        self.rows.last().map(index::Header::hash)
    }

    pub fn tip_height(&self) -> Option<usize> {
        self.rows.len().checked_sub(1)
    }

    pub fn next_txpos(&self) -> index::TxPos {
        self.rows
            .last()
            .map_or_else(index::TxPos::default, index::Header::next_txpos)
    }

    pub fn add(&mut self, row: index::Header) {
        assert_eq!(
            row.header().prev_blockhash,
            self.tip_hash().unwrap_or_else(BlockHash::all_zeros)
        );
        self.rows.push(row)
    }

    pub fn pop(&mut self) -> Option<index::Header> {
        self.rows.pop()
    }

    pub fn get_by_height(&self, height: usize) -> Option<&index::Header> {
        self.rows.get(height)
    }

    pub fn find_by_txpos(&self, txpos: &index::TxPos) -> Option<crate::Location> {
        let height = match self
            .rows
            .binary_search_by_key(txpos, index::Header::next_txpos)
        {
            Ok(i) => i + 1, // hitting exactly a block boundary txpos -> next block
            Err(i) => i,
        };

        let indexed_header = self.rows.get(height)?;
        let prev_pos = self
            .rows
            .get(height - 1)
            .map_or_else(index::TxPos::default, index::Header::next_txpos);

        assert!(
            txpos >= &prev_pos,
            "binary search failed to find the correct position"
        );
        let offset = txpos.offset_from(prev_pos).unwrap();
        Some(crate::Location {
            height,
            offset,
            indexed_header,
        })
    }
}
