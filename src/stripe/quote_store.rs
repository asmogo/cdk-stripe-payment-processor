// Quote storage for two-step payout flow

use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::debug;
use uuid::Uuid;

use crate::stripe::payment_request::StripePayoutRequest;

const DEFAULT_QUOTE_TTL: Duration = Duration::from_secs(1800); // 30 minutes

/// Stored quote information
#[derive(Debug, Clone)]
pub struct PayoutQuote {
    /// Unique quote ID (UUID v4)
    pub quote_id: String,
    
    /// Parsed payment request
    pub payment_request: StripePayoutRequest,
    
    /// Original encoded request string (for verification)
    pub encoded_request: String,
    
    /// Calculated fee in cents
    pub fee_cents: i64,
    
    /// Quote state
    pub state: QuoteState,
    
    /// When the quote was created
    created_at: Instant,
    
    /// When the quote expires (for cleanup)
    expires_at: Instant,
    
    /// Transfer ID for execution (set when executed)
    pub transfer_id: Option<String>,
    
    /// Execution timestamp
    pub executed_at: Option<Instant>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuoteState {
    /// Quote is valid and ready for execution
    Issued,
    /// Quote has been used to create a payout (terminal state)
    Executed,
    /// Quote expired without being executed (terminal state)
    Expired,
}

impl PayoutQuote {
    fn new(
        payment_request: StripePayoutRequest,
        encoded_request: String,
        ttl: Duration,
    ) -> Self {
        let quote_id = Uuid::new_v4().to_string();
        let fee_cents = payment_request.calculate_fee();
        let now = Instant::now();
        
        Self {
            quote_id,
            payment_request,
            encoded_request,
            fee_cents,
            state: QuoteState::Issued,
            created_at: now,
            expires_at: now + ttl,
            transfer_id: None,
            executed_at: None,
        }
    }
    
    fn is_expired(&self) -> bool {
        Instant::now() > self.expires_at
    }
}

/// In-memory quote storage with TTL and cleanup
pub struct QuoteStore {
    quotes: Arc<RwLock<HashMap<String, PayoutQuote>>>,
    default_ttl: Duration,
}

impl QuoteStore {
    pub fn new() -> Self {
        Self {
            quotes: Arc::new(RwLock::new(HashMap::new())),
            default_ttl: DEFAULT_QUOTE_TTL,
        }
    }
    
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.default_ttl = ttl;
        self
    }
    
    /// Create a new quote from a payment request
    pub async fn create_quote(
        &self,
        payment_request: StripePayoutRequest,
        encoded_request: String,
    ) -> Result<PayoutQuote> {
        let mut quotes = self.quotes.write().await;
        
        // Opportunistic cleanup
        self.cleanup_expired_quotes(&mut quotes);
        
        let quote = PayoutQuote::new(payment_request, encoded_request.clone(), self.default_ttl);
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
    
    /// Retrieve a quote by ID
    pub async fn get_quote(&self, quote_id: &str) -> Option<PayoutQuote> {
        let quotes = self.quotes.read().await;
        quotes.get(quote_id).cloned()
    }
    
    /// Mark a quote as executed and store transfer ID
    pub async fn mark_executed(&self, quote_id: &str, transfer_id: String) -> Result<()> {
        let mut quotes = self.quotes.write().await;
        
        if let Some(quote) = quotes.get_mut(quote_id) {
            quote.state = QuoteState::Executed;
            quote.transfer_id = Some(transfer_id.clone());
            quote.executed_at = Some(Instant::now());
            
            debug!(
                quote_id = %quote_id,
                transfer_id = %transfer_id,
                "Marked quote as executed"
            );
            
            Ok(())
        } else {
            Err(anyhow::anyhow!("Quote not found: {}", quote_id))
        }
    }
    
    /// Validate a quote for execution
    pub async fn validate_for_execution(&self, quote_id: &str) -> Result<PayoutQuote, QuoteExecutionError> {
        let quotes = self.quotes.read().await;
        
        let quote = quotes.get(quote_id)
            .ok_or(QuoteExecutionError::NotFound)?;
        
        // Check expiration
        if quote.is_expired() {
            return Err(QuoteExecutionError::Expired);
        }
        
        // Check state
        match quote.state {
            QuoteState::Issued => Ok(quote.clone()),
            QuoteState::Executed => Err(QuoteExecutionError::AlreadyExecuted {
                transfer_id: quote.transfer_id.clone(),
            }),
            QuoteState::Expired => Err(QuoteExecutionError::Expired),
        }
    }
    
    /// Clean up expired quotes
    fn cleanup_expired_quotes(&self, quotes: &mut HashMap<String, PayoutQuote>) {
        let expired: Vec<String> = quotes
            .iter()
            .filter(|(_, quote)| quote.is_expired() && quote.state == QuoteState::Issued)
            .map(|(id, _)| id.clone())
            .collect();
        
        for id in expired {
            if let Some(quote) = quotes.get_mut(&id) {
                quote.state = QuoteState::Expired;
            }
            debug!(quote_id = %id, "Marked expired quote");
        }
    }
    
    /// Manual cleanup trigger
    pub async fn cleanup(&self) {
        let mut quotes = self.quotes.write().await;
        self.cleanup_expired_quotes(&mut quotes);
        
        // Remove terminal quotes older than 1 hour
        let cutoff = Instant::now() - Duration::from_secs(3600);
        quotes.retain(|id, quote| {
            if matches!(quote.state, QuoteState::Executed | QuoteState::Expired) 
                && quote.created_at < cutoff {
                debug!(quote_id = %id, state = ?quote.state, "Removed old terminal quote");
                false
            } else {
                true
            }
        });
    }
}

impl Default for QuoteStore {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum QuoteExecutionError {
    #[error("Quote not found")]
    NotFound,
    
    #[error("Quote has expired")]
    Expired,
    
    #[error("Quote already executed (transfer ID: {transfer_id:?})")]
    AlreadyExecuted { transfer_id: Option<String> },
}