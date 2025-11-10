// Payment request schema for two-step payout flow

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

/// JSON-encoded payment request for Stripe payouts
/// This is what gets stored in PaymentQuoteRequest.request field
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StripePayoutRequest {
    /// Schema version for future compatibility
    pub version: u8,
    
    pub payment_id: String,
    /// Target bank account or external account ID
    /// Format: "ba_..." (bank account) or "card_..." (debit card)
    pub destination: String,
    /// Target bank account or external account ID
    /// Format: "ba_..." (bank account) or "card_..." (debit card)
    /// Payment amount in smallest currency unit (cents for USD)
    pub amount_cents: i64,
    
    /// Currency code (must be USD for this implementation)
    pub currency: String,
    
    /// Payout method: "standard" or "instant"
    pub method: PayoutMethod,
    
    /// Optional description (max 1000 chars per Stripe limits)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    
    /// Optional statement descriptor (max 22 chars for instant, 10 for standard)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub statement_descriptor: Option<String>,
    
    /// Custom metadata key-value pairs (max 50 pairs, each key/value max 500 chars)
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub metadata: HashMap<String, String>,
    
    /// Request creation timestamp (Unix seconds) for validation
    pub created_at: i64,
    
    /// Optional expiration timestamp (Unix seconds)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PayoutMethod {
    Standard,
    Instant,
}

impl StripePayoutRequest {
    /// Create a new payment request
    pub fn new(
        destination: String,
        amount_cents: i64,
        method: PayoutMethod,
        payment_id: String,
    ) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        
        Self {
            version: 1,
            destination,
            amount_cents,
            currency: "usd".to_string(),
            method,
            description: None,
            statement_descriptor: None,
            metadata: HashMap::new(),
            created_at,
            expires_at: None,
            payment_id
        }
    }
    
    /// Encode to base64 JSON string for transmission
    pub fn encode(&self) -> Result<String, serde_json::Error> {
        let json = serde_json::to_string(self)?;
        Ok(STANDARD.encode(json))
    }
    
    /// Decode from base64 JSON string
    pub fn decode(encoded: &str) -> Result<Self, PaymentRequestError> {
        let json = STANDARD.decode(encoded)
            .map_err(|_| PaymentRequestError::InvalidEncoding)?;
        let json_str = String::from_utf8(json)
            .map_err(|_| PaymentRequestError::InvalidEncoding)?;
        serde_json::from_str(&json_str)
            .map_err(|e| PaymentRequestError::InvalidFormat(e.to_string()))
    }
    
    /// Validate the payment request
    pub fn validate(&self) -> Result<(), PaymentRequestError> {
        // Version check
        if self.version != 1 {
            return Err(PaymentRequestError::UnsupportedVersion(self.version));
        }
        
        // Currency check
        if self.currency.to_ascii_uppercase() != "USD" {
            return Err(PaymentRequestError::InvalidCurrency(self.currency.clone()));
        }
        
        // Amount validation
        if self.amount_cents <= 0 {
            return Err(PaymentRequestError::InvalidAmount);
        }
        
        // Destination validation
        if self.destination.is_empty() {
            return Err(PaymentRequestError::MissingDestination);
        }
  /*      if !self.destination.starts_with("ba_") && !self.destination.starts_with("card_") {
            return Err(PaymentRequestError::InvalidDestinationFormat);
        }*/
        
        // Statement descriptor validation
        if let Some(ref desc) = self.statement_descriptor {
            let max_len = match self.method {
                PayoutMethod::Instant => 22,
                PayoutMethod::Standard => 10,
            };
            if desc.len() > max_len {
                return Err(PaymentRequestError::StatementDescriptorTooLong {
                    method: self.method,
                    max: max_len,
                    actual: desc.len(),
                });
            }
        }
        
        // Description length check
        if let Some(ref desc) = self.description {
            if desc.len() > 1000 {
                return Err(PaymentRequestError::DescriptionTooLong);
            }
        }
        
        // Metadata size check
        if self.metadata.len() > 50 {
            return Err(PaymentRequestError::TooManyMetadataEntries);
        }
        for (k, v) in &self.metadata {
            if k.len() > 500 || v.len() > 500 {
                return Err(PaymentRequestError::MetadataValueTooLong);
            }
        }
        
        // Expiration check
        if let Some(expires_at) = self.expires_at {
            use std::time::{SystemTime, UNIX_EPOCH};
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            if expires_at < now {
                return Err(PaymentRequestError::Expired);
            }
        }
        
        Ok(())
    }
    
    /// Calculate fee for this payout based on Stripe's fee structure
    pub fn calculate_fee(&self) -> i64 {
        match self.method {
            PayoutMethod::Standard => 0, // Standard payouts are free
            PayoutMethod::Instant => {
                // Instant: 1% with $0.50 minimum, $10 maximum
                let fee = (self.amount_cents as f64 * 0.01) as i64;
                fee.max(50).min(1000)
            }
        }
    }
}

#[derive(Debug, Error)]
pub enum PaymentRequestError {
    #[error("Invalid base64 encoding")]
    InvalidEncoding,
    
    #[error("Invalid JSON format: {0}")]
    InvalidFormat(String),
    
    #[error("Unsupported version: {0}")]
    UnsupportedVersion(u8),
    
    #[error("Invalid currency: {0}, only USD supported")]
    InvalidCurrency(String),
    
    #[error("Invalid amount: must be positive")]
    InvalidAmount,
    
    #[error("Missing destination")]
    MissingDestination,
    
    #[error("Invalid destination format: must start with 'ba_' or 'card_'")]
    InvalidDestinationFormat,
    
    #[error("Statement descriptor too long for {method:?} payout: max {max}, got {actual}")]
    StatementDescriptorTooLong {
        method: PayoutMethod,
        max: usize,
        actual: usize,
    },
    
    #[error("Description too long: max 1000 characters")]
    DescriptionTooLong,
    
    #[error("Too many metadata entries: max 50")]
    TooManyMetadataEntries,
    
    #[error("Metadata key or value too long: max 500 characters")]
    MetadataValueTooLong,
    
    #[error("Payment request has expired")]
    Expired,
}