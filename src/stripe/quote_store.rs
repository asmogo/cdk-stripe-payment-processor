// Quote storage for two-step payout flow

use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::debug;
use uuid::Uuid;

use crate::stripe::payment_request::StripePayoutRequest;

/// Stored quote information
#[derive(Debug, Clone)]
pub struct PayoutQuote {
    /// Unique quote ID (UUID v4)
    pub quote_id: String,
    
    /// Parsed payment request
    pub payment_request: StripePayoutRequest,
    
    /// Calculated fee in cents
    pub fee_cents: i64,
}

impl PayoutQuote {
    fn new(
        payment_request: StripePayoutRequest,
    ) -> Self {
        let quote_id = Uuid::new_v4().to_string();
        let fee_cents = payment_request.calculate_fee();
        
        Self {
            quote_id,
            payment_request,
            fee_cents,
        }
    }
}

/// In-memory quote storage
pub struct QuoteStore {
    quotes: Arc<RwLock<HashMap<String, PayoutQuote>>>,
}

impl QuoteStore {
    pub fn new() -> Self {
        Self {
            quotes: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    /// Create a new quote from a payment request
    pub async fn create_quote(
        &self,
        payment_request: StripePayoutRequest,
        encoded_request: String,
    ) -> Result<PayoutQuote> {
        let mut quotes = self.quotes.write().await;
        
        let quote = PayoutQuote::new(payment_request);
        let quote_id = quote.quote_id.clone();
        
        debug!(
            quote_id = %quote_id,
            amount_cents = quote.payment_request.amount_cents,
            fee_cents = quote.fee_cents,
            method = ?quote.payment_request.method,
            "Created new payout quote"
        );
        
        quotes.insert(encoded_request, quote.clone());
        Ok(quote)
    }
}

impl Default for QuoteStore {
    fn default() -> Self {
        Self::new()
    }
}