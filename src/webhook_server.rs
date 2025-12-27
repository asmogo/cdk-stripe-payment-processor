// HTTP webhook server for Stripe webhook events

use crate::stripe::errors::WebhookError;
use crate::stripe::payment_state::PaymentState;
use crate::stripe::payout_state::PayoutState;
use crate::stripe::webhook;
use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::post,
    Router,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{error, info};

#[derive(Clone)]
pub struct WebhookState {
    pub payment_state: Arc<PaymentState>,
    pub payout_state: Arc<PayoutState>,
    pub webhook_secret: String,
    pub tolerance_seconds: i64,
}

pub async fn run_webhook_server(
    port: u16,
    payment_state: Arc<PaymentState>,
    payout_state: Arc<PayoutState>,
    webhook_secret: String,
    tolerance_seconds: i64,
) -> anyhow::Result<()> {
    let state = WebhookState {
        payment_state,
        payout_state,
        webhook_secret,
        tolerance_seconds,
    };

    let app = Router::new()
        .route("/stripe/webhook", post(handle_stripe_webhook))
        .route("/health", axum::routing::get(health_check))
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!("Starting webhook HTTP server on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn health_check() -> impl IntoResponse {
    (StatusCode::OK, "OK")
}

async fn handle_stripe_webhook(
    State(state): State<WebhookState>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    match webhook::handle_webhook(
        &body,
        &headers,
        &state.webhook_secret,
        state.tolerance_seconds,
        state.payment_state.clone(),
        state.payout_state.clone(),
    )
    .await
    {
        Ok(()) => {
            info!("Webhook processed successfully");
            (StatusCode::OK, "OK".to_string())
        }
        Err(e) => {
            error!("Webhook processing failed: {}", e);
            let status_code = match e {
                WebhookError::InvalidSignature(_) => StatusCode::UNAUTHORIZED,
                WebhookError::MissingSignature => StatusCode::UNAUTHORIZED,
                WebhookError::TimestampTolerance(_) => StatusCode::BAD_REQUEST,
                WebhookError::MalformedPayload(_) => StatusCode::BAD_REQUEST,
                WebhookError::MissingSecret => StatusCode::INTERNAL_SERVER_ERROR,
                WebhookError::ProcessingFailed(_) => StatusCode::INTERNAL_SERVER_ERROR,
            };
            (status_code, e.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stripe::payment_state::PaymentState;

    #[tokio::test]
    async fn test_health_check() {
        let response = health_check().await.into_response();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_webhook_missing_signature() {
        let state = WebhookState {
            payment_state: Arc::new(PaymentState::new()),
            payout_state: Arc::new(PayoutState::new()),
            webhook_secret: "whsec_test".to_string(),
            tolerance_seconds: 300,
        };

        let headers = HeaderMap::new();
        let body = Bytes::from("{}");

        let response = handle_stripe_webhook(State(state), headers, body)
            .await
            .into_response();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}