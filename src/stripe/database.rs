//! Database module for storing quote-to-payment mappings
//!
//! Uses redb to store mappings between quotes and payment requests

use anyhow::Result;
use redb::{Database, TableDefinition};
use std::path::Path;
use std::sync::Arc;
use crate::stripe::types::PayoutQuote;

/// Table for storing payout quotes
/// Key: Encoded payment request string
/// Value: Serialized PayoutQuote JSON
const PAYOUT_QUOTES_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("payout_quotes");

/// Database wrapper for quote storage
#[derive(Clone)]
pub struct StripeDatabase {
    db: Arc<Database>,
}

impl StripeDatabase {
    /// Create a new database instance or open an existing one
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        // Ensure parent directory exists
        if let Some(parent) = path.as_ref().parent() {
            std::fs::create_dir_all(parent)?;
        }

        let db = Database::create(path)?;

        // Create tables if they don't exist
        let write_txn = db.begin_write()?;
        {
            let _table = write_txn.open_table(PAYOUT_QUOTES_TABLE)?;
        }
        write_txn.commit()?;

        tracing::info!("Database initialized with payout_quotes table");

        Ok(Self { db: Arc::new(db) })
    }

    /// Store a payout quote
    pub fn insert_payout_quote(&self, encoded_request: &str, quote: &PayoutQuote) -> Result<()> {
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(PAYOUT_QUOTES_TABLE)?;
            let value = serde_json::to_vec(quote)?;
            table.insert(encoded_request, value.as_slice())?;
        }
        write_txn.commit()?;
        tracing::debug!(
            "Inserted payout quote for request: {}",
            // Log truncated request for sanity
            if encoded_request.len() > 20 { &encoded_request[..20] } else { encoded_request }
        );
        Ok(())
    }

    /// Get a payout quote by encoded request
    pub fn get_payout_quote(&self, encoded_request: &str) -> Result<Option<PayoutQuote>> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(PAYOUT_QUOTES_TABLE)?;

        let result = table.get(encoded_request)?;
        match result {
            Some(curr) => {
                let quote: PayoutQuote = serde_json::from_slice(curr.value())?;
                Ok(Some(quote))
            }
            None => Ok(None),
        }
    }
}
