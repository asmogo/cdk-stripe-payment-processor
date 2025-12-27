// Stripe REST client
// Implements minimal endpoints with USD/cents enforcement and idempotency header propagation.

use reqwest::{Client, StatusCode};
use std::collections::HashMap;
use std::future::Future;
use rand::{Rng, SeedableRng};
use rand::rngs::SmallRng;
use tracing::{instrument, info, warn};

use crate::stripe::errors::{StripeApiError, StripeErrorEnvelope, is_transient};
use crate::stripe::types::{
    ensure_usd_cents,
    PaymentIntent, Transfer,
};

const STRIPE_API_BASE: &str = "https://api.stripe.com";

#[derive(Clone)]
pub struct StripeRestClient {
    pub(crate) http: Client,
    pub(crate) api_key: String,
    pub(crate) account_id: Option<String>,
    pub(crate) stripe_version: Option<String>,
    // Retry knobs with safe defaults; server may override by rebuilding client if needed
    pub(crate) max_retries: u32,
    pub(crate) base_delay_ms: u64,
    pub(crate) max_delay_ms: u64,
}

impl StripeRestClient {
    pub fn new(http: Client, api_key: String) -> Self {
        Self {
            http,
            api_key,
            account_id: None,
            stripe_version: None,
            max_retries: 3,
            base_delay_ms: 100,
            max_delay_ms: 2_000,
        }
    }

    pub fn with_account(mut self, acct: impl Into<Option<String>>) -> Self {
        self.account_id = acct.into();
        self
    }

    pub fn with_version(mut self, ver: impl Into<Option<String>>) -> Self {
        self.stripe_version = ver.into();
        self
    }

    #[allow(dead_code)]
    pub fn with_retry(mut self, max_retries: u32, base_delay_ms: u64, max_delay_ms: u64) -> Self {
        self.max_retries = max_retries;
        self.base_delay_ms = base_delay_ms.max(1);
        self.max_delay_ms = if max_delay_ms == 0 { self.base_delay_ms } else { max_delay_ms };
        if self.max_delay_ms < self.base_delay_ms {
            self.max_delay_ms = self.base_delay_ms;
        }
        self
    }

    fn apply_common_headers(&self, req: reqwest::RequestBuilder, idempotency_key: Option<&str>) -> reqwest::RequestBuilder {
        let mut req = req.bearer_auth(&self.api_key);
        if let Some(k) = idempotency_key {
            req = req.header("Idempotency-Key", k);
        }
        if let Some(v) = &self.stripe_version {
            if !v.is_empty() {
                req = req.header("Stripe-Version", v);
            }
        }
        if let Some(acct) = &self.account_id {
            if !acct.is_empty() {
                req = req.header("Stripe-Account", acct);
            }
        }
        req
    }

    fn map_error(status: StatusCode, body: &str) -> StripeApiError {
        if let Ok(env) = serde_json::from_str::<StripeErrorEnvelope>(body) {
            env.to_api_error_with_status(Some(status.as_u16()))
        } else {
            StripeApiError::Http(format!("status={} body={}", status.as_u16(), body))
        }
    }

    async fn with_retries<F, Fut, T>(
        &self,
        desc: &str,
        max_retries: u32,
        base_delay_ms: u64,
        max_delay_ms: u64,
        mut op: F,
    ) -> Result<T, StripeApiError>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Result<T, StripeApiError>>,
    {
        let mut attempt: u32 = 0;
        loop {
            match op().await {
                Ok(v) => return Ok(v),
                Err(e) => {
                    // Determine retryability
                    let (http_status, err_type) = match &e {
                        StripeApiError::Stripe { status, type_, .. } => (*status, Some(type_)),
                        StripeApiError::Http(_) => (Some(503), None),
                        StripeApiError::Transient(_) => (Some(503), None),
                        _ => (None, None),
                    };
                    let retryable = is_transient(http_status, err_type);
                    if !retryable || attempt >= max_retries {
                        return Err(e);
                    }

                    // Compute exponential backoff with full jitter
                    let exp = base_delay_ms.saturating_mul(1u64.saturating_mul((1u64 << attempt.min(20)) as u64).max(1));
                    let cap = exp.min(max_delay_ms.max(base_delay_ms));
                    let mut rng = SmallRng::from_entropy();
                    let delay_ms = if cap > base_delay_ms {
                        rng.gen_range(base_delay_ms..=cap)
                    } else {
                        base_delay_ms
                    };

                    warn!(
                        target: "stripe",
                        desc = %desc,
                        attempt = attempt + 1,
                        max_retries = max_retries,
                        http_status = ?http_status,
                        error_type = ?err_type,
                        next_delay_ms = delay_ms,
                        "retrying transient Stripe error"
                    );

                    tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                    attempt += 1;
                }
            }
        }
    }

    // POST /v1/payment_intents
    // application/x-www-form-urlencoded
    // Enforce USD & cents
    #[instrument(skip(self, metadata), fields(method="POST", path="/v1/payment_intents", idempotency_key=?idempotency_key))]
    pub async fn create_payment_intent(
        &self,
        amount_cents: i64,
        currency: &str,
        idempotency_key: Option<&str>,
        confirmation_method: Option<&str>,
        capture_method: Option<&str>,
        metadata: Option<&HashMap<String, String>>,
        automatic_payment_methods_enabled: Option<bool>,
        automatic_payment_methods_allow_redirects: Option<&str>,
    ) -> Result<PaymentIntent, StripeApiError> {
        // Enforce USD & non-negative cents via helpers
        ensure_usd_cents(amount_cents, currency)
            .map_err(|_| StripeApiError::Precondition("USD currency and non-negative cents required"))?;

        // Build form fields
        let mut form: Vec<(String, String)> = Vec::new();
        form.push(("amount".into(), amount_cents.to_string()));
        form.push(("currency".into(), currency.to_ascii_lowercase()));
        if let Some(cm) = confirmation_method {
            form.push(("confirmation_method".into(), cm.to_string()));
        }
        if let Some(cm) = capture_method {
            form.push(("capture_method".into(), cm.to_string()));
        }
        if let Some(meta) = metadata {
            for (k, v) in meta {
                form.push((format!("metadata[{}]", k), v.clone()));
            }
        }
        if let Some(enabled) = automatic_payment_methods_enabled {
            form.push(("automatic_payment_methods[enabled]".into(), enabled.to_string()));
        }
        if let Some(allow_redirects) = automatic_payment_methods_allow_redirects {
            form.push(("automatic_payment_methods[allow_redirects]".into(), allow_redirects.to_string()));
        }

        info!(
            target: "stripe",
            method = "POST",
            path = "/v1/payment_intents",
            amount_cents = amount_cents,
            currency = %currency,
            idempotency_key = idempotency_key.unwrap_or(""),
            "stripe request"
        );

        let req_builder = || {
            let url = format!("{}/v1/payment_intents", STRIPE_API_BASE);
            let req = self.http.post(url).form(&form);
            let req = self.apply_common_headers(req, idempotency_key);
            async move {
                let resp = req.send().await.map_err(|e| StripeApiError::Http(e.to_string()))?;
                let status = resp.status();
                let text = resp.text().await.map_err(|e| StripeApiError::Decode(e.to_string()))?;
                if status.is_success() {
                    serde_json::from_str::<PaymentIntent>(&text).map_err(|e| StripeApiError::Decode(e.to_string()))
                } else {
                    Err(Self::map_error(status, &text))
                }
            }
        };
        self.with_retries(
            "create_payment_intent",
            self.max_retries,
            self.base_delay_ms,
            self.max_delay_ms,
            req_builder,
        ).await
    }



    // GET /v1/payment_intents/{id}
    #[instrument(skip(self), fields(method="GET", path="/v1/payment_intents/{id}", intent_id=%intent_id))]
    pub async fn retrieve_intent(&self, intent_id: &str) -> Result<PaymentIntent, StripeApiError> {
        info!(
            target: "stripe",
            method = "GET",
            path = "/v1/payment_intents/{id}",
            intent_id = %intent_id,
            "stripe request"
        );
        // Keep retrieve lightweight: single retry only
        let req_builder = || {
            let url = format!("{}/v1/payment_intents/{}", STRIPE_API_BASE, intent_id);
            let req = self.http.get(url);
            let req = self.apply_common_headers(req, None);
            async move {
                let resp = req.send().await.map_err(|e| StripeApiError::Http(e.to_string()))?;
                let status = resp.status();
                let text = resp.text().await.map_err(|e| StripeApiError::Decode(e.to_string()))?;
                if status.is_success() {
                    serde_json::from_str::<PaymentIntent>(&text).map_err(|e| StripeApiError::Decode(e.to_string()))
                } else {
                    Err(Self::map_error(status, &text))
                }
            }
        };
        self.with_retries(
            "retrieve_intent",
            1,
            self.base_delay_ms,
            self.max_delay_ms,
            req_builder,
        ).await
    }


    // POST /v1/transfers
    // Create a transfer to a connected Stripe account
    #[instrument(skip(self, _metadata), fields(method="POST", path="/v1/transfers", idempotency_key=?idempotency_key))]
    pub async fn create_transfer(
        &self,
        amount_cents: i64,
        currency: &str,
        destination: &str, // Connected account ID
        _description: Option<&str>,
        _metadata: Option<&HashMap<String, String>>,
        source_type: Option<&str>, // "card" or "bank_account"
        idempotency_key: Option<&str>,
    ) -> Result<Transfer, StripeApiError> {
        // Enforce USD & non-negative cents via helpers
        ensure_usd_cents(amount_cents, currency)
            .map_err(|_| StripeApiError::Precondition("USD currency and non-negative cents required"))?;

        // Build form fields
        let mut form: Vec<(String, String)> = Vec::new();
        form.push(("amount".into(), amount_cents.to_string()));
        form.push(("currency".into(), currency.to_ascii_lowercase()));
        form.push(("destination".into(), destination.to_string()));
        
        // Add source_type to specify which balance to use (defaults to "card" for available balance)
        if let Some(st) = source_type {
            form.push(("source_type".into(), st.to_string()));
        } else {
            // Default to card (available balance) if not specified
            form.push(("source_type".into(), "card".to_string()));
        }
        


        info!(
            target: "stripe",
            method = "POST",
            path = "/v1/transfers",
            amount_cents = amount_cents,
            currency = %currency,
            destination = %destination,
            source_type = source_type.unwrap_or("card"),
            idempotency_key = idempotency_key.unwrap_or(""),
            "stripe request"
        );

        let req_builder = || {
            let url = format!("{}/v1/transfers", STRIPE_API_BASE);
            let req = self.http.post(url).form(&form);
            let req = self.apply_common_headers(req, idempotency_key);
            async move {
                let resp = req.send().await.map_err(|e| StripeApiError::Http(e.to_string()))?;
                let status = resp.status();
                let text = resp.text().await.map_err(|e| StripeApiError::Decode(e.to_string()))?;
                if status.is_success() {
                    serde_json::from_str::<Transfer>(&text).map_err(|e| StripeApiError::Decode(e.to_string()))
                } else {
                    Err(Self::map_error(status, &text))
                }
            }
        };
        self.with_retries(
            "create_transfer",
            self.max_retries,
            self.base_delay_ms,
            self.max_delay_ms,
            req_builder,
        ).await
    }

    // GET /v1/transfers/{id}
    #[instrument(skip(self), fields(method="GET", path="/v1/transfers/{id}", transfer_id=%transfer_id))]
    pub async fn retrieve_transfer(&self, transfer_id: &str) -> Result<Transfer, StripeApiError> {
        info!(
            target: "stripe",
            method = "GET",
            path = "/v1/transfers/{id}",
            transfer_id = %transfer_id,
            "stripe request"
        );
        // Keep retrieve lightweight: single retry only
        let req_builder = || {
            let url = format!("{}/v1/transfers/{}", STRIPE_API_BASE, transfer_id);
            let req = self.http.get(url);
            let req = self.apply_common_headers(req, None);
            async move {
                let resp = req.send().await.map_err(|e| StripeApiError::Http(e.to_string()))?;
                let status = resp.status();
                let text = resp.text().await.map_err(|e| StripeApiError::Decode(e.to_string()))?;
                if status.is_success() {
                    serde_json::from_str::<Transfer>(&text).map_err(|e| StripeApiError::Decode(e.to_string()))
                } else {
                    Err(Self::map_error(status, &text))
                }
            }
        };
        self.with_retries(
            "retrieve_transfer",
            1,
            self.base_delay_ms,
            self.max_delay_ms,
            req_builder,
        ).await
    }

}
