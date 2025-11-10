// Stripe provider module

pub mod rest;
pub mod webhook;
pub mod types;
pub mod errors;
pub mod metrics;
pub mod payment_state;
pub mod payout_state;
pub mod payment_request;
pub mod quote_store;

use reqwest::Client;
use std::sync::Arc;
use std::time::Duration;
use crate::settings::StripeSettings;
use self::payment_state::PaymentState;
use self::payout_state::PayoutState;
use self::quote_store::QuoteStore;

// Minimal trait to mirror a generic payment provider.
pub trait PaymentProvider: Send + Sync {
    fn name(&self) -> &'static str;
}

#[derive(Clone)]
pub struct StripeProvider {
    pub(crate) http: Client,
    pub(crate) cfg: StripeSettings,
    pub(crate) rest: self::rest::StripeRestClient,
    pub(crate) payment_state: Arc<PaymentState>,
    pub(crate) payout_state: Arc<PayoutState>,
    pub(crate) quote_store: Arc<QuoteStore>,
}

impl StripeProvider {
    // Build reqwest client with rustls and timeout from cfg, store cfg clone.
    pub fn new(cfg: StripeSettings) -> Result<Self, crate::stripe::errors::StripeApiError> {
        let timeout = std::time::Duration::from_millis(if cfg.timeout_ms > 0 { cfg.timeout_ms } else { 15_000 });
        let http = Client::builder()
            .use_rustls_tls()
            .timeout(timeout)
            .build()
            .map_err(|e| crate::stripe::errors::StripeApiError::Http(e.to_string()))?;

        let rest = self::rest::StripeRestClient::new(http.clone(), cfg.api_key.clone())
            .with_account(if cfg.account_id.is_empty() { None } else { Some(cfg.account_id.clone()) })
            .with_version(if cfg.stripe_version.is_empty() { None } else { Some(cfg.stripe_version.clone()) });

        let payment_state = Arc::new(PaymentState::new().with_ttl(cfg.payment_timeout));
        let payout_state = Arc::new(PayoutState::new().with_ttl(cfg.payment_timeout));
        
        // Initialize quote store with default 30-minute TTL
        let quote_store = Arc::new(
            QuoteStore::new()
                .with_ttl(Duration::from_secs(1800))
        );

        Ok(Self {
            http,
            cfg: cfg.clone(),
            rest,
            payment_state,
            payout_state,
            quote_store,
        })
    }

    pub fn rest(&self) -> &self::rest::StripeRestClient {
        &self.rest
    }

    pub fn payment_state(&self) -> Arc<PaymentState> {
        Arc::clone(&self.payment_state)
    }

    pub fn payout_state(&self) -> Arc<PayoutState> {
        Arc::clone(&self.payout_state)
    }

    pub fn quote_store(&self) -> Arc<QuoteStore> {
        Arc::clone(&self.quote_store)
    }

    pub fn webhook_secret(&self) -> &str {
        &self.cfg.webhook_secret
    }

    pub fn webhook_tolerance_seconds(&self) -> i64 {
        self.cfg.webhook_tolerance_seconds
    }
}

impl PaymentProvider for StripeProvider {
    fn name(&self) -> &'static str {
        "stripe"
    }
}