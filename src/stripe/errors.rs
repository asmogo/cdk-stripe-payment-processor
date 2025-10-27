// Stripe-specific error types and mappings
// TODO: Expand coverage and map HTTP/network errors precisely.

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tonic::Status;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StripeErrorType {
    ApiConnectionError,
    ApiError,
    AuthenticationError,
    CardError,
    IdempotencyError,
    InvalidRequestError,
    RateLimitError,
    ValidationError,
    Unknown,
}

impl From<&str> for StripeErrorType {
    fn from(s: &str) -> Self {
        match s {
            "api_connection_error" => StripeErrorType::ApiConnectionError,
            "api_error" => StripeErrorType::ApiError,
            "authentication_error" => StripeErrorType::AuthenticationError,
            "card_error" => StripeErrorType::CardError,
            "idempotency_error" => StripeErrorType::IdempotencyError,
            "invalid_request_error" => StripeErrorType::InvalidRequestError,
            "rate_limit_error" => StripeErrorType::RateLimitError,
            "validation_error" => StripeErrorType::ValidationError,
            _ => StripeErrorType::Unknown,
        }
    }
}

// Stripe REST error envelope: { error: { type, code, decline_code, message, param } }
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StripeErrorEnvelope {
    pub error: StripeErrorDetails,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StripeErrorDetails {
    #[serde(rename = "type")]
    pub type_: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decline_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub param: Option<String>,
}

impl StripeErrorEnvelope {
    pub fn to_api_error_with_status(self, status: Option<u16>) -> StripeApiError {
        StripeApiError::Stripe {
            type_: StripeErrorType::from(self.error.type_.as_str()),
            message: self.error.message,
            code: self.error.code,
            param: self.error.param,
            status,
        }
    }
}

#[derive(Debug, Error)]
pub enum StripeApiError {
    #[error("http error: {0}")]
    Http(String),
    #[error("decode error: {0}")]
    Decode(String),
    #[error("stripe error: {type_:?} message={message:?} code={code:?} param={param:?}")]
    Stripe {
        type_: StripeErrorType,
        message: Option<String>,
        code: Option<String>,
        param: Option<String>,
        status: Option<u16>,
    },
    #[error("precondition failed: {0}")]
    Precondition(&'static str),
    #[error("transient error: {0}")]
    Transient(String),
}

// Centralized mapper from StripeApiError -> tonic::Status
pub fn to_tonic_status(e: &StripeApiError) -> Status {
    match e {
        StripeApiError::Http(msg) => Status::unavailable(format!("stripe/http: {msg}")),
        StripeApiError::Decode(msg) => Status::internal(format!("stripe/decode: {msg}")),
        StripeApiError::Stripe { type_, message, code, param, status } => {
            let base = format!(
                "stripe/{:?} status={:?} code={:?} param={:?} msg={:?}",
                type_, status, code, param, message
            );
            match type_ {
                StripeErrorType::InvalidRequestError => Status::invalid_argument(base),
                StripeErrorType::AuthenticationError => Status::unauthenticated(base),
                StripeErrorType::CardError => {
                    // Stripe uses 402; surface as failed_precondition with decline_code if any.
                    Status::failed_precondition(base)
                }
                StripeErrorType::RateLimitError => Status::unavailable(base),
                StripeErrorType::IdempotencyError => Status::aborted(base),
                StripeErrorType::ApiConnectionError | StripeErrorType::ApiError => Status::unavailable(base),
                StripeErrorType::ValidationError => Status::invalid_argument(base),
                StripeErrorType::Unknown => Status::unknown(base),
            }
        }
        StripeApiError::Precondition(msg) => Status::failed_precondition(msg.to_string()),
        StripeApiError::Transient(msg) => Status::unavailable(format!("stripe/transient: {msg}")),
    }
}

impl From<StripeApiError> for Status {
    fn from(e: StripeApiError) -> Self {
        to_tonic_status(&e)
    }
}

// Helper indicating whether an error is likely transient (api_error or 5xx)
pub fn is_transient(http_status: Option<u16>, type_: Option<&StripeErrorType>) -> bool {
    if let Some(s) = http_status {
        if (500..600).contains(&s) {
            return true;
        }
    }
    if let Some(t) = type_ {
        matches!(t, StripeErrorType::ApiConnectionError | StripeErrorType::ApiError | StripeErrorType::RateLimitError)
    } else {
        false
    }
}

// Marker error for retryable cases
#[derive(Debug, Error)]
#[error("transient error: {reason}")]
pub struct TransientError {
    pub reason: String,
}

// Webhook-specific errors
#[derive(Debug, Error)]
pub enum WebhookError {
    #[error("invalid signature: {0}")]
    InvalidSignature(String),
    #[error("timestamp tolerance exceeded: {0}")]
    TimestampTolerance(String),
    #[error("malformed payload: {0}")]
    MalformedPayload(String),
    #[error("missing webhook secret")]
    MissingSecret,
    #[error("missing signature header")]
    MissingSignature,
    #[error("unknown event type: {0}")]
    UnknownEventType(String),
    #[error("event processing failed: {0}")]
    ProcessingFailed(String),
}

impl WebhookError {
    /// Map webhook error to HTTP status code
    pub fn status_code(&self) -> u16 {
        match self {
            WebhookError::InvalidSignature(_) => 401,
            WebhookError::TimestampTolerance(_) => 400,
            WebhookError::MalformedPayload(_) => 400,
            WebhookError::MissingSecret => 500,
            WebhookError::MissingSignature => 401,
            WebhookError::UnknownEventType(_) => 400,
            WebhookError::ProcessingFailed(_) => 500,
        }
    }
}