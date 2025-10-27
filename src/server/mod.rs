use anyhow::Result;
use async_trait::async_trait;
use std::collections::HashMap;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};
use tracing::debug;

use crate::pb::cdk_payment_processor as pb;
use crate::settings::Config;
use crate::stripe::StripeProvider;

pub struct PaymentProcessorService {
    cfg: Config,
    pub(crate) stripe: StripeProvider,
}

impl PaymentProcessorService {
    pub async fn try_new(cfg: Config) -> Result<Self> {
        let stripe = StripeProvider::new(cfg.stripe.clone())?;
        Ok(Self { cfg, stripe })
    }
}

#[async_trait]
impl pb::cdk_payment_processor_server::CdkPaymentProcessor for PaymentProcessorService {
    async fn get_settings(
        &self,
        _request: Request<pb::EmptyRequest>,
    ) -> Result<Response<pb::SettingsResponse>, Status> {
        let settings = "{\"bolt11\":true, \"mpp\":false, \"unit\":\"usd\", \"invoice_description\":true, \"bolt12\":false, \"amountless\":false}";
        Ok(Response::new(pb::SettingsResponse { inner: settings.to_string() }))
    }

    async fn create_payment(
        &self,
        request: Request<pb::CreatePaymentRequest>,
    ) -> Result<Response<pb::CreatePaymentResponse>, Status> {
        let req = request.into_inner();
        
        // Extract amount from options
        let mut amount_sat: u64 = 0;
        if let Some(opts) = req.options.and_then(|o| o.options) {
            match opts {
                pb::incoming_payment_options::Options::Bolt11(b11) => amount_sat = b11.amount,
                pb::incoming_payment_options::Options::Bolt12(b12) => {
                    amount_sat = b12.amount.unwrap_or_default()
                }
            }
        }
        
        // Convert sats to USD cents (for demo: 1 sat = 1 cent, adjust as needed)
        // TODO: Use actual exchange rate
        let amount_cents = amount_sat as i64;
        
        // Create metadata to track the request
        let mut metadata = HashMap::new();
        metadata.insert("unit".to_string(), req.unit.clone());
        metadata.insert("amount_sat".to_string(), amount_sat.to_string());
        
        // Create payment intent with automatic confirmation
        let intent = self.stripe.rest()
            .create_payment_intent(
                amount_cents,
                "usd",
                None, // idempotency_key
                None, // confirmation_method
                Some("automatic"), // capture_method
                Some(&metadata),
                Some(true), // automatic_payment_methods_enabled
                None, // automatic_payment_methods_allow_redirects
            )
            .await
            .map_err(|e| Status::internal(format!("create payment intent failed: {}", e)))?;
        
        // Register this payment with PaymentState so webhooks can notify waiters
        let payment_state = self.stripe.payment_state();
        let _rx = payment_state
            .register_waiter(&intent.id, metadata.clone())
            .await
            .map_err(|e| Status::internal(format!("failed to register payment waiter: {}", e)))?;
        
        debug!(payment_intent_id = %intent.id, "Registered payment waiter for new payment intent");
        
        // Return payment intent ID as the identifier and client_secret as the request
        let resp = pb::CreatePaymentResponse {
            request_identifier: Some(pb::PaymentIdentifier {
                r#type: pb::PaymentIdentifierType::CustomId as i32,
                value: Some(pb::payment_identifier::Value::Id(intent.id.clone())),
            }),
            request: intent.client_secret.unwrap_or_else(|| intent.id.clone()),
            expiry: None,
        };
        Ok(Response::new(resp))
    }

    async fn get_payment_quote(
        &self,
        _request: Request<pb::PaymentQuoteRequest>,
    ) -> Result<Response<pb::PaymentQuoteResponse>, Status> {
        // Stripe doesn't support outgoing payments in the same way
        // This is primarily for incoming payments (payment intents)
        Err(Status::unimplemented(
            "get_payment_quote not applicable for Stripe provider (incoming payments only)",
        ))
    }

    async fn make_payment(
        &self,
        _request: Request<pb::MakePaymentRequest>,
    ) -> Result<Response<pb::MakePaymentResponse>, Status> {
        // Stripe doesn't support outgoing payments
        // This provider is for receiving payments only
        Err(Status::unimplemented(
            "make_payment not applicable for Stripe provider (incoming payments only)",
        ))
    }

    async fn check_incoming_payment(
        &self,
        request: Request<pb::CheckIncomingPaymentRequest>,
    ) -> Result<Response<pb::CheckIncomingPaymentResponse>, Status> {
        let req = request.into_inner();
        let pid = req
            .request_identifier
            .ok_or_else(|| Status::invalid_argument("missing request_identifier"))?;
        
        // For Stripe, we expect PaymentId (payment intent ID)
        let intent_id = match pid.value {
            Some(pb::payment_identifier::Value::Id(id)) => id,
            _ => return Err(Status::invalid_argument("expected payment intent ID")),
        };
        
        // Retrieve the payment intent
        let intent = self.stripe.rest()
            .retrieve_intent(&intent_id)
            .await
            .map_err(|e| Status::internal(format!("retrieve payment intent failed: {}", e)))?;
        
        // Convert cents back to sats (reverse of create_payment conversion)
        let amount_sat = intent.amount as u64;
        
        // Determine if payment is complete
        let payment_id = if intent.status == "succeeded" {
            intent.id.clone()
        } else {
            String::new()
        };
        
        let resp = pb::CheckIncomingPaymentResponse {
            payments: vec![pb::WaitIncomingPaymentResponse {
                payment_identifier: Some(pb::PaymentIdentifier {
                    r#type: pb::PaymentIdentifierType::CustomId as i32,
                    value: Some(pb::payment_identifier::Value::Id(intent.id)),
                }),
                payment_amount: amount_sat,
                unit: "usd".to_string(),
                payment_id,
            }],
        };
        Ok(Response::new(resp))
    }

    async fn check_outgoing_payment(
        &self,
        _request: Request<pb::CheckOutgoingPaymentRequest>,
    ) -> Result<Response<pb::MakePaymentResponse>, Status> {
        // Stripe doesn't support outgoing payments
        Err(Status::unimplemented(
            "check_outgoing_payment not applicable for Stripe provider (incoming payments only)",
        ))
    }

    type WaitIncomingPaymentStream = ReceiverStream<Result<pb::WaitIncomingPaymentResponse, Status>>;

    async fn wait_incoming_payment(
        &self,
        _request: Request<pb::EmptyRequest>,
    ) -> Result<Response<Self::WaitIncomingPaymentStream>, Status> {
        // Note: In the CDK protocol, wait_incoming_payment typically waits for ANY incoming payment
        // This is a simplified implementation that demonstrates the streaming pattern
        // In production, you might maintain a queue of pending payments to wait for
        
        let payment_state = self.stripe.payment_state();
        let timeout_duration = self.cfg.stripe.payment_timeout;

        // Create a channel for the stream
        let (tx, rx) = tokio::sync::mpsc::channel(32);

        debug!("WaitIncomingPayment stream established - will complete when webhook events arrive");

        // Spawn background task to handle streaming
        // This is a simplified implementation - in production you'd track multiple payments
        tokio::spawn(async move {
            // Send initial processing status
            let initial_msg = pb::WaitIncomingPaymentResponse {
                payment_identifier: Some(pb::PaymentIdentifier {
                    r#type: pb::PaymentIdentifierType::CustomId as i32,
                    value: Some(pb::payment_identifier::Value::Id("awaiting_webhook".to_string())),
                }),
                payment_amount: 0,
                unit: "usd".to_string(),
                payment_id: String::new(),
            };

            if tx.send(Ok(initial_msg)).await.is_err() {
                debug!("WaitIncomingPayment stream closed before initial message sent");
                return;
            }

            // In a real implementation, you would:
            // 1. Listen to a queue of payment intents waiting for completion
            // 2. Subscribe to their status updates via PaymentState
            // 3. Stream updates as they arrive
            // 4. Complete when any payment succeeds or timeout occurs
            
            // For now, just keep the stream alive until timeout
            tokio::select! {
                _ = tokio::time::sleep(timeout_duration) => {
                    debug!("WaitIncomingPayment stream timed out");
                    let _ = tx.send(Err(Status::deadline_exceeded(
                        "No payment received within timeout period"
                    ))).await;
                }
                _ = tx.closed() => {
                    debug!("WaitIncomingPayment stream cancelled by client");
                }
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }
}