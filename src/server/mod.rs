use anyhow::Result;
use async_trait::async_trait;
use std::collections::HashMap;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};
use tracing::debug;

use crate::pb::cdk_payment_processor as pb;
use crate::settings::Config;
use crate::stripe::payment_request::StripePayoutRequest;
use crate::stripe::StripeProvider;

pub struct PaymentProcessorService {
    pub(crate) stripe: StripeProvider,
}

impl PaymentProcessorService {
    pub async fn try_new(cfg: Config) -> Result<Self> {
        let stripe = StripeProvider::new(cfg.stripe.clone())?;
        Ok(Self { stripe })
    }
}

#[async_trait]
impl pb::cdk_payment_processor_server::CdkPaymentProcessor for PaymentProcessorService {
    async fn get_settings(
        &self,
        _request: Request<pb::EmptyRequest>,
    ) -> Result<Response<pb::SettingsResponse>, Status> {
        Ok(Response::new(pb::SettingsResponse {
            unit: "usd".to_string(),
            bolt11: None,
            bolt12: None,
            custom: HashMap::from([
                ("stripe".to_string(), "{\"sandbox\":true}".to_string()),
            ]),
        }))
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
                pb::incoming_payment_options::Options::Custom(b11) => amount_sat = b11.amount.unwrap_or_default(),
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
                req.unit.as_str(),
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
            .register_waiter(&intent.id)
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
        request: Request<pb::PaymentQuoteRequest>,
    ) -> Result<Response<pb::PaymentQuoteResponse>, Status> {
        let req = request.into_inner();
        
        // 1. Decode payment request from base64-encoded JSON
        let payout_request = StripePayoutRequest::decode(&req.request)
            .map_err(|e| {
                Status::invalid_argument(format!("Failed to decode payment request: {}", e))
            })?;

        // 2. Validate payment request
        payout_request.validate()
            .map_err(|e| {
                Status::invalid_argument(format!("Invalid payment request: {}", e))
            })?;
        
        // 3. Create and store quote
        let quote_store = self.stripe.quote_store();
        let quote = quote_store
            .create_quote(payout_request.clone(), req.request.clone())
            .await
            .map_err(|e| {
                Status::internal(format!("Failed to create quote: {}", e))
            })?;


        let fee_msats = quote.fee_cents as u64 * 10;

        debug!(
            quote_id = %quote.quote_id,
            amount_cents = quote.payment_request.amount_cents,
            fee_cents = quote.fee_cents,
            method = ?quote.payment_request.method,
            "Created payment quote"
        );
        
        // 5. Build response with quote information
        let resp = pb::PaymentQuoteResponse {
            request_identifier: Some(pb::PaymentIdentifier {
                r#type: pb::PaymentIdentifierType::CustomId as i32,
                value: Some(pb::payment_identifier::Value::Id(quote.quote_id)),
            }),
            amount: quote.payment_request.amount_cents as u64,
            fee: fee_msats,
            state: pb::QuoteState::Issued as i32,
            unit: req.unit,
        };
        
        Ok(Response::new(resp))
    }

    async fn make_payment(
        &self,
        request: Request<pb::MakePaymentRequest>,
    ) -> Result<Response<pb::MakePaymentResponse>, Status> {
        let req = request.into_inner();
        
        // Extract payment options
        let payment_opts = req.payment_options
            .ok_or_else(|| Status::invalid_argument("missing payment_options"))?;
        // Extract quote_id from payment options (bolt11 or bolt12 field contains the quote_id)
        let json_request = match payment_opts.options {
            Some(pb::outgoing_payment_variant::Options::Bolt11(opts)) => {
                if opts.bolt11.is_empty() {
                    return Err(Status::invalid_argument("Missing quote ID in bolt11 field"));
                }
                opts.bolt11
            },
            Some(pb::outgoing_payment_variant::Options::Custom(opts)) => {
                opts.offer.to_owned()
            }
            Some(pb::outgoing_payment_variant::Options::Bolt12(opts)) => {
                if opts.offer.is_empty() {
                    return Err(Status::invalid_argument("Missing quote ID in bolt12 field"));
                }
                opts.offer
            }
            None => return Err(Status::invalid_argument("payment options required")),
        };
        let payout_request = StripePayoutRequest::decode(&json_request).unwrap();

        // Create metadata including quote_id and any custom metadata from the payment request
        let mut metadata = HashMap::new();
        metadata.insert("amount_cents".to_string(), payout_request.clone().amount_cents.to_string());
        for (k, v) in payout_request.clone().metadata {
            metadata.insert(k.clone(), v.clone());
        }
        
        // Create idempotency key for safe retries
        let idempotency_key = format!("quote_{}", payout_request.payment_id.clone());
        
        // Create the transfer with details from the quote
        // Note: destination should be a connected Stripe account ID (e.g., acct_xxx)
        // source_type defaults to "card" (available balance)
        let transfer = self.stripe.rest()
            .create_transfer(
                payout_request.clone().amount_cents,
                payout_request.clone().currency.as_str(),
                &payout_request.clone().destination,
                payout_request.clone().description.as_deref(),
                Some(&metadata),
                Some("card"), // Use card balance (available balance)
                Some(&idempotency_key),
            )
            .await
            .map_err(|e| Status::internal(format!("create transfer failed: {}", e)))?;
        
   
        debug!(
            transfer_id = %transfer.id,
            "Quote marked as executed"
        );
        
        // Register this transfer with PayoutState so webhooks can notify waiters
        // Note: We're reusing PayoutState for transfers - you may want to rename this later
        let payout_state = self.stripe.payout_state();
        let _rx = payout_state
            .register_waiter(&transfer.id)
            .await
            .map_err(|e| Status::internal(format!("failed to register transfer waiter: {}", e)))?;
        
        debug!(transfer_id = %transfer.id, "Registered transfer waiter for new transfer");
        
        // Transfers don't have a status field like payouts do
        // They are typically created successfully or fail immediately
        // For now, we'll mark them as Paid (successful)
        let status = pb::QuoteState::Paid;
        
        // Return transfer details with actual amount from quote
        let resp = pb::MakePaymentResponse {
            payment_identifier: Some(pb::PaymentIdentifier {
                r#type: pb::PaymentIdentifierType::CustomId as i32,
                value: Some(pb::payment_identifier::Value::Id(transfer.id.clone())),
            }),
            payment_proof: Some(transfer.id),
            status: status as i32,
            total_spent: payout_request.clone().amount_cents as u64,
            unit: "usd".to_string(),
        };
        
        Ok(Response::new(resp))
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


        // Determine if payment is complete
        let payment_id = intent.id.clone();
        let payment_amount = if intent.status == "succeeded" {
            intent.amount as u64
        } else {
            0
        };
        let resp = pb::CheckIncomingPaymentResponse {
            payments: vec![pb::WaitIncomingPaymentResponse {
                payment_identifier: Some(pb::PaymentIdentifier {
                    r#type: pb::PaymentIdentifierType::CustomId as i32,
                    value: Some(pb::payment_identifier::Value::Id(intent.id)),
                }),
                payment_amount,
                unit: "usd".to_string(),
                payment_id,
            }],
        };
        Ok(Response::new(resp))
    }

    async fn check_outgoing_payment(
        &self,
        request: Request<pb::CheckOutgoingPaymentRequest>,
    ) -> Result<Response<pb::MakePaymentResponse>, Status> {
        let req = request.into_inner();
        let pid = req
            .request_identifier
            .ok_or_else(|| Status::invalid_argument("missing request_identifier"))?;
        
        // For Stripe, we expect PaymentId (transfer ID)
        let transfer_id = match pid.value {
            Some(pb::payment_identifier::Value::Id(id)) => id,
            _ => return Err(Status::invalid_argument("expected transfer ID")),
        };
        
        // Retrieve the transfer
        let transfer = self.stripe.rest()
            .retrieve_transfer(&transfer_id)
            .await
            .map_err(|e| Status::internal(format!("retrieve transfer failed: {}", e)))?;
        
        // Transfers don't have a status field like payouts
        // If we successfully retrieved it and it's not reversed, it's paid
        let status = if transfer.reversed.unwrap_or(false) {
            pb::QuoteState::Failed
        } else {
            pb::QuoteState::Paid
        };
        
        let payment_proof = if !transfer.reversed.unwrap_or(false) {
            Some(transfer.id.clone())
        } else {
            None
        };
        
        let resp = pb::MakePaymentResponse {
            payment_identifier: Some(pb::PaymentIdentifier {
                r#type: pb::PaymentIdentifierType::CustomId as i32,
                value: Some(pb::payment_identifier::Value::Id(transfer.id)),
            }),
            payment_proof,
            status: status as i32,
            total_spent: transfer.amount as u64,
            unit: "usd".to_string(),
        };
        
        Ok(Response::new(resp))
    }

    type WaitIncomingPaymentStream = ReceiverStream<Result<pb::WaitIncomingPaymentResponse, Status>>;

    async fn wait_incoming_payment(
        &self,
        _request: Request<pb::EmptyRequest>,
    ) -> Result<Response<Self::WaitIncomingPaymentStream>, Status> {
        let mut rx = self.stripe.payment_state().subscribe();
        let (tx, rx_grpc) = tokio::sync::mpsc::channel(32);

        debug!("WaitIncomingPayment stream established");

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    update = rx.recv() => {
                        match update {
                            Ok(msg) => {
                                debug!(
                                    payment_intent_id = %msg.payment_intent_id,
                                    status = ?msg.status,
                                    "Received payment status update from broadcast"
                                );
                                if let crate::stripe::payment_state::PaymentStatus::Succeeded { amount, currency } = msg.status {
                                    if amount <= 0 || msg.payment_intent_id.is_empty() {
                                        debug!("Skipping invalid payment update (amount: {}, id: '{}')", amount, msg.payment_intent_id);
                                        continue;
                                    }
                                    let resp = pb::WaitIncomingPaymentResponse {
                                        payment_identifier: Some(pb::PaymentIdentifier {
                                            r#type: pb::PaymentIdentifierType::CustomId as i32,
                                            value: Some(pb::payment_identifier::Value::Id(msg.payment_intent_id.clone())),
                                        }),
                                        payment_amount: amount as u64,
                                        unit: currency,
                                        payment_id: msg.payment_intent_id,
                                    };
                                    
                                    if tx.send(Ok(resp)).await.is_err() {
                                        debug!("WaitIncomingPayment stream closed by client");
                                        break;
                                    }
                                }
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                                break;
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                                // Ignore lagging, but in production you might want to handle it
                                continue;
                            }
                        }
                    }
                    _ = tx.closed() => {
                        debug!("WaitIncomingPayment stream closed by client");
                        break;
                    }
                }
            }
        });

        Ok(Response::new(ReceiverStream::new(rx_grpc)))
    }
}