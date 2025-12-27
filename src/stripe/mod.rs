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
use crate::settings::StripeSettings;
use self::payment_state::PaymentState;
use self::payout_state::PayoutState;
use self::quote_store::QuoteStore;


#[derive(Clone)]
pub struct StripeProvider {
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

        let payment_state = Arc::new(PaymentState::new());
        let payout_state = Arc::new(PayoutState::new());
        
        // Initialize quote store with default 30-minute TTL
        let quote_store = Arc::new(QuoteStore::new());

        Ok(Self {
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
}

