// Minimal Stripe DTOs and helper types
use serde::{Deserialize, Serialize};
use thiserror::Error;

// Internal helper types enforcing USD + smallest unit (cents)
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct AmountCents(pub i64);

// Phantom-validated currency marker; serialized/deserialized as untagged "USD"
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct CurrencyUSDUntagged;

#[derive(Debug, Error)]
pub enum StripePreconditionError {
    #[error("currency must be USD")]
    NonUsdCurrency,
    #[error("amount must be non-negative cents")]
    InvalidAmount,
}

impl StripePreconditionError {
    pub fn code(&self) -> &'static str {
        match self {
            StripePreconditionError::NonUsdCurrency => "non_usd_currency",
            StripePreconditionError::InvalidAmount => "invalid_amount",
        }
    }
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

// Request structs (subset) matching Stripe API forms
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatePaymentIntentRequest {
    pub amount: i64,
    pub currency: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confirmation_method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capture_method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<std::collections::HashMap<String, String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfirmPaymentIntentRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_method: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateRefundRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_intent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub charge: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<i64>,
}

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

// Refund minimal shape
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Refund {
    pub id: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub currency: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_intent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub charge: Option<String>,
}

// Stripe error envelope as returned by REST API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorEnvelope {
    pub error: StripeErrorBody,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StripeErrorBody {
    #[serde(rename = "type")]
    pub type_: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decline_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub param: Option<String>,
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

/// Typed wrapper for payment_intent.succeeded events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentIntentSucceededEvent {
    pub id: String,
    #[serde(rename = "type")]
    pub event_type: String,
    pub data: PaymentIntentEventData,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentIntentEventData {
    pub object: PaymentIntent,
}