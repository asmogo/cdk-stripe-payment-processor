// Minimal Stripe DTOs and helper types
use serde::{Deserialize, Serialize};
use thiserror::Error;

// Internal helper types enforcing USD + smallest unit (cents)

#[derive(Debug, Error)]
pub enum StripePreconditionError {
    #[error("currency must be USD")]
    NonUsdCurrency,
    #[error("amount must be non-negative cents")]
    InvalidAmount,
}

// Helper to enforce USD & cents preconditions at the API boundary.
pub fn ensure_usd_cents(amount_cents: i64, currency: &str) -> Result<(), StripePreconditionError> {
    require_usd_currency(currency)?;
    require_non_negative_cents(amount_cents)?;
    Ok(())
}

// New granular helpers used across server paths
pub fn require_usd_currency(currency: &str) -> Result<(), StripePreconditionError> {
    if currency.to_ascii_uppercase() != "USD" {
        return Err(StripePreconditionError::NonUsdCurrency);
    }
    Ok(())
}

pub fn require_non_negative_cents(amount_cents: i64) -> Result<(), StripePreconditionError> {
    if amount_cents < 0 {
        return Err(StripePreconditionError::InvalidAmount);
    }
    Ok(())
}

// Minimal Stripe API DTOs

// PaymentIntent minimal shape
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentIntent {
    pub id: String,
    pub status: String,
    pub amount: i64,
    pub currency: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_action: Option<serde_json::Value>,
}

// Payout minimal shape
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Payout {
    pub id: String,
    pub object: String,
    pub amount: i64,
    pub currency: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arrival_date: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_message: Option<String>,
}

// Transfer minimal shape
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transfer {
    pub id: String,
    pub object: String,
    pub amount: i64,
    pub currency: String,
    pub destination: String, // Connected account ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<std::collections::HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reversed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_transaction: Option<String>,
}

// Webhook event types

/// Stripe webhook event envelope
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StripeEvent {
    pub id: String,
    #[serde(rename = "type")]
    pub event_type: String,
    pub data: StripeEventData,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub livemode: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StripeEventData {
    pub object: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_attributes: Option<serde_json::Value>,
}

use uuid::Uuid;
use crate::stripe::payment_request::StripePayoutRequest;

/// Stored quote information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayoutQuote {
    /// Unique quote ID (UUID v4)
    pub quote_id: String,
    
    /// Parsed payment request
    pub payment_request: StripePayoutRequest,
    
    /// Calculated fee in cents
    pub fee_cents: i64,
}

impl PayoutQuote {
    pub fn new(
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