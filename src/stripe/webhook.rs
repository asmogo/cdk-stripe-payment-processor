// Stripe webhook handling with signature verification and event processing

use crate::stripe::errors::WebhookError;
use crate::stripe::payment_state::{PaymentState, PaymentStatus};
use crate::stripe::types::{PaymentIntent, StripeEvent};
use crate::stripe_counter_inc;
use anyhow::Result;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info, instrument, warn};

/// Main webhook handler - verifies signature and processes event
#[instrument(skip(payload, headers, payment_state))]
pub async fn handle_webhook(
    payload: &[u8],
    headers: &http::HeaderMap,
    webhook_secret: &str,
    tolerance_seconds: i64,
    payment_state: Arc<PaymentState>,
) -> Result<(), WebhookError> {
    // Verify signature
    verify_signature(payload, headers, webhook_secret, tolerance_seconds)?;

    // Parse event
    let evt: StripeEvent = serde_json::from_slice(payload)
        .map_err(|e| WebhookError::MalformedPayload(format!("JSON parse error: {}", e)))?;

    stripe_counter_inc!("stripe.webhook.received", "event_type" => &evt.event_type);

    // Process event
    process_event(&evt, payment_state).await?;

    Ok(())
}

/// Verify Stripe webhook signature using HMAC SHA-256
pub fn verify_signature(
    payload: &[u8],
    headers: &http::HeaderMap,
    webhook_secret: &str,
    tolerance_seconds: i64,
) -> Result<(), WebhookError> {
    if webhook_secret.is_empty() {
        return Err(WebhookError::MissingSecret);
    }

    // Extract Stripe-Signature header
    let signature_header = headers
        .get("stripe-signature")
        .or_else(|| headers.get("Stripe-Signature"))
        .ok_or(WebhookError::MissingSignature)?
        .to_str()
        .map_err(|e| WebhookError::InvalidSignature(format!("Invalid header encoding: {}", e)))?;

    // Parse signature header: t=timestamp,v1=signature[,v1=signature2,...]
    let mut timestamp: Option<i64> = None;
    let mut signatures: Vec<&str> = Vec::new();

    for part in signature_header.split(',') {
        let kv: Vec<&str> = part.splitn(2, '=').collect();
        if kv.len() != 2 {
            continue;
        }
        match kv[0] {
            "t" => {
                timestamp = kv[1].parse().ok();
            }
            "v1" => {
                signatures.push(kv[1]);
            }
            _ => {} // Ignore unknown fields
        }
    }

    let timestamp = timestamp.ok_or_else(|| {
        WebhookError::InvalidSignature("Missing timestamp in signature header".to_string())
    })?;

    if signatures.is_empty() {
        return Err(WebhookError::InvalidSignature(
            "No v1 signature found".to_string(),
        ));
    }

    // Check timestamp tolerance
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| WebhookError::InvalidSignature(format!("System time error: {}", e)))?
        .as_secs() as i64;

    let time_diff = (current_time - timestamp).abs();
    if time_diff > tolerance_seconds {
        return Err(WebhookError::TimestampTolerance(format!(
            "Timestamp {} differs from current time {} by {} seconds (tolerance: {})",
            timestamp, current_time, time_diff, tolerance_seconds
        )));
    }

    // Construct signed payload: timestamp.payload
    let signed_payload = format!("{}.{}", timestamp, String::from_utf8_lossy(payload));

    // Compute expected signature using HMAC-SHA256
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(webhook_secret.as_bytes())
        .map_err(|e| WebhookError::InvalidSignature(format!("HMAC init error: {}", e)))?;
    mac.update(signed_payload.as_bytes());
    let expected_signature = hex::encode(mac.finalize().into_bytes());

    // Compare with provided signatures (constant-time comparison)
    let signature_valid = signatures.iter().any(|sig| {
        // Use constant-time comparison to prevent timing attacks
        expected_signature.as_bytes().len() == sig.as_bytes().len()
            && expected_signature
                .as_bytes()
                .iter()
                .zip(sig.as_bytes())
                .fold(0u8, |acc, (a, b)| acc | (a ^ b))
                == 0
    });

    if !signature_valid {
        return Err(WebhookError::InvalidSignature(format!(
            "Signature mismatch. Expected: {}, Got: {:?}",
            expected_signature, signatures
        )));
    }

    debug!(
        timestamp = timestamp,
        time_diff = time_diff,
        "Webhook signature verified successfully"
    );

    Ok(())
}

/// Process webhook event and dispatch to appropriate handlers
#[instrument(skip(evt, payment_state))]
pub async fn process_event(
    evt: &StripeEvent,
    payment_state: Arc<PaymentState>,
) -> Result<(), WebhookError> {
    let event_type = evt.event_type.as_str();

    debug!(
        event_id = %evt.id,
        event_type = %event_type,
        "Processing webhook event"
    );

    match event_type {
        "payment_intent.succeeded" => {
            handle_payment_intent_succeeded(evt, payment_state).await?;
            stripe_counter_inc!("stripe.webhook.processed", "event_type" => "payment_intent.succeeded", "status" => "success");
        }
        "payment_intent.payment_failed" => {
            handle_payment_intent_failed(evt, payment_state).await?;
            stripe_counter_inc!("stripe.webhook.processed", "event_type" => "payment_intent.payment_failed", "status" => "success");
        }
        "payment_intent.canceled" => {
            handle_payment_intent_canceled(evt, payment_state).await?;
            stripe_counter_inc!("stripe.webhook.processed", "event_type" => "payment_intent.canceled", "status" => "success");
        }
        _ => {
            info!(event_type = %event_type, "Ignoring unknown/unsupported event type");
            stripe_counter_inc!("stripe.webhook.ignored", "event_type" => event_type);
        }
    }

    Ok(())
}

/// Handle payment_intent.succeeded event
async fn handle_payment_intent_succeeded(
    evt: &StripeEvent,
    payment_state: Arc<PaymentState>,
) -> Result<(), WebhookError> {
    let intent: PaymentIntent = serde_json::from_value(evt.data.object.clone())
        .map_err(|e| WebhookError::ProcessingFailed(format!("Failed to parse PaymentIntent: {}", e)))?;

    info!(
        payment_intent_id = %intent.id,
        amount = intent.amount,
        currency = %intent.currency,
        "Payment intent succeeded"
    );

    let receivers = payment_state
        .publish_status(
            &intent.id,
            PaymentStatus::Succeeded {
                amount: intent.amount,
                currency: intent.currency.clone(),
            },
            Some("Payment completed successfully".to_string()),
            Some(&evt.id),
        )
        .await
        .map_err(|e| WebhookError::ProcessingFailed(format!("Failed to publish status: {}", e)))?;

    if receivers > 0 {
        payment_state.mark_completed(&intent.id).await;
        stripe_counter_inc!("stripe.payment.completed", "has_waiter" => "true");
    } else {
        warn!(
            payment_intent_id = %intent.id,
            "Payment succeeded but no waiters registered"
        );
        stripe_counter_inc!("stripe.payment.completed", "has_waiter" => "false");
    }

    Ok(())
}

/// Handle payment_intent.payment_failed event
async fn handle_payment_intent_failed(
    evt: &StripeEvent,
    payment_state: Arc<PaymentState>,
) -> Result<(), WebhookError> {
    let intent: PaymentIntent = serde_json::from_value(evt.data.object.clone())
        .map_err(|e| WebhookError::ProcessingFailed(format!("Failed to parse PaymentIntent: {}", e)))?;

    warn!(
        payment_intent_id = %intent.id,
        status = %intent.status,
        "Payment intent failed"
    );

    let reason = format!("Payment failed with status: {}", intent.status);
    
    payment_state
        .publish_status(
            &intent.id,
            PaymentStatus::Failed { reason: reason.clone() },
            Some(reason),
            Some(&evt.id),
        )
        .await
        .map_err(|e| WebhookError::ProcessingFailed(format!("Failed to publish status: {}", e)))?;

    payment_state.mark_completed(&intent.id).await;
    stripe_counter_inc!("stripe.payment.failed");

    Ok(())
}

/// Handle payment_intent.canceled event
async fn handle_payment_intent_canceled(
    evt: &StripeEvent,
    payment_state: Arc<PaymentState>,
) -> Result<(), WebhookError> {
    let intent: PaymentIntent = serde_json::from_value(evt.data.object.clone())
        .map_err(|e| WebhookError::ProcessingFailed(format!("Failed to parse PaymentIntent: {}", e)))?;

    info!(
        payment_intent_id = %intent.id,
        "Payment intent canceled"
    );

    payment_state
        .publish_status(
            &intent.id,
            PaymentStatus::Failed {
                reason: "Payment canceled".to_string(),
            },
            Some("Payment was canceled".to_string()),
            Some(&evt.id),
        )
        .await
        .map_err(|e| WebhookError::ProcessingFailed(format!("Failed to publish status: {}", e)))?;

    payment_state.mark_completed(&intent.id).await;
    stripe_counter_inc!("stripe.payment.canceled");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_signature_valid() {
        let payload = br#"{"id":"evt_test","type":"payment_intent.succeeded","data":{"object":{}}}"#;
        let secret = "whsec_test_secret";
        let timestamp = 1234567890i64;

        // Compute expected signature
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        type HmacSha256 = Hmac<Sha256>;

        let signed_payload = format!("{}.{}", timestamp, String::from_utf8_lossy(payload));
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(signed_payload.as_bytes());
        let signature = hex::encode(mac.finalize().into_bytes());

        let sig_header = format!("t={},v1={}", timestamp, signature);

        let mut headers = http::HeaderMap::new();
        headers.insert("stripe-signature", sig_header.parse().unwrap());

        // With very large tolerance for testing
        let result = verify_signature(payload, &headers, secret, i64::MAX);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_signature_invalid() {
        let payload = br#"{"id":"evt_test","type":"payment_intent.succeeded"}"#;
        let secret = "whsec_test_secret";
        let timestamp = 1234567890i64;
        let wrong_signature = "0000000000000000000000000000000000000000000000000000000000000000";

        let sig_header = format!("t={},v1={}", timestamp, wrong_signature);

        let mut headers = http::HeaderMap::new();
        headers.insert("stripe-signature", sig_header.parse().unwrap());

        let result = verify_signature(payload, &headers, secret, i64::MAX);
        assert!(matches!(result, Err(WebhookError::InvalidSignature(_))));
    }

    #[test]
    fn test_verify_signature_missing_header() {
        let payload = b"test";
        let headers = http::HeaderMap::new();

        let result = verify_signature(payload, &headers, "secret", 300);
        assert!(matches!(result, Err(WebhookError::MissingSignature)));
    }

    #[test]
    fn test_verify_signature_timestamp_tolerance() {
        let payload = b"test";
        let secret = "whsec_test_secret";
        let old_timestamp = 1000i64; // Very old timestamp

        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        type HmacSha256 = Hmac<Sha256>;

        let signed_payload = format!("{}.{}", old_timestamp, String::from_utf8_lossy(payload));
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(signed_payload.as_bytes());
        let signature = hex::encode(mac.finalize().into_bytes());

        let sig_header = format!("t={},v1={}", old_timestamp, signature);

        let mut headers = http::HeaderMap::new();
        headers.insert("stripe-signature", sig_header.parse().unwrap());

        let result = verify_signature(payload, &headers, secret, 300);
        assert!(matches!(result, Err(WebhookError::TimestampTolerance(_))));
    }
}