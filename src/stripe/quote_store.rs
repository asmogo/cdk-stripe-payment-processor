// Quote storage for two-step payout flow

use anyhow::Result;
use std::sync::Arc;
use tracing::debug;

use crate::stripe::database::StripeDatabase;
use crate::stripe::payment_request::StripePayoutRequest;
use crate::stripe::types::PayoutQuote;

/// Database-backed quote storage
pub struct QuoteStore {
    db: Arc<StripeDatabase>,
}

impl QuoteStore {
    pub fn new(db: Arc<StripeDatabase>) -> Self {
        Self { db }
    }
    
    /// Create a new quote from a payment request
    pub async fn create_quote(
        &self,
        payment_request: StripePayoutRequest,
        encoded_request: String,
    ) -> Result<PayoutQuote> {
        let quote = PayoutQuote::new(payment_request);
        let quote_id = quote.quote_id.clone();
        
        debug!(
            quote_id = %quote_id,
            amount_cents = quote.payment_request.amount_cents,
            fee_cents = quote.fee_cents,
            method = ?quote.payment_request.method,
            "Created new payout quote"
        );
        
        // Persist to database
        self.db.insert_payout_quote(&encoded_request, &quote)?;
        
        Ok(quote)
    }

    /// Retrieve a quote by encoded request
    pub async fn get_quote(&self, encoded_request: &str) -> Result<Option<PayoutQuote>> {
        self.db.get_payout_quote(encoded_request)
    }
}