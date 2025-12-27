// Payment state coordination module for managing active payment sessions and broadcasting updates

use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, RwLock};
use tracing::{debug, warn};

const DEFAULT_CHANNEL_CAPACITY: usize = 100;
const DEFAULT_SESSION_TTL: Duration = Duration::from_secs(3600); // 1 hour

/// Status of a payment as it progresses through the lifecycle
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PaymentStatus {
    Succeeded { amount: i64, currency: String },
    Failed { reason: String },
}

/// Update message sent to waiters
#[derive(Debug, Clone)]
pub struct PaymentStatusUpdate {
    pub payment_intent_id: String,
    pub status: PaymentStatus,
}

/// Internal session data for a payment intent
struct PaymentSession {
    tx: broadcast::Sender<PaymentStatusUpdate>,
    created_at: Instant,
    last_event_id: Option<String>,
    completed: bool,
}

impl PaymentSession {
    fn new() -> Self {
        let (tx, _rx) = broadcast::channel(DEFAULT_CHANNEL_CAPACITY);
        Self {
            tx,
            created_at: Instant::now(),
            last_event_id: None,
            completed: false,
        }
    }

    fn is_expired(&self, ttl: Duration) -> bool {
        self.created_at.elapsed() > ttl
    }
}

/// Shared payment state coordinator
pub struct PaymentState {
    sessions: Arc<RwLock<HashMap<String, PaymentSession>>>,
    global_tx: broadcast::Sender<PaymentStatusUpdate>,
    session_ttl: Duration,
}

impl PaymentState {
    pub fn new() -> Self {
        let (global_tx, _rx) = broadcast::channel(DEFAULT_CHANNEL_CAPACITY * 10);
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            global_tx,
            session_ttl: DEFAULT_SESSION_TTL,
        }
    }


    /// Register a waiter for payment updates and return a receiver
    pub async fn register_waiter(
        &self,
        payment_intent_id: &str,
    ) -> Result<broadcast::Receiver<PaymentStatusUpdate>> {
        let mut sessions = self.sessions.write().await;
        
        // Clean up expired sessions opportunistically
        self.cleanup_expired_sessions(&mut sessions);

        let session = sessions
            .entry(payment_intent_id.to_string())
            .or_insert_with(|| {
                debug!(
                    payment_intent_id = %payment_intent_id,
                    "Registering new payment session"
                );
                PaymentSession::new()
            });

        let rx = session.tx.subscribe();
        Ok(rx)
    }

    /// Publish a status update to all waiters for a payment intent
    pub async fn publish_status(
        &self,
        payment_intent_id: &str,
        status: PaymentStatus,
        event_id: Option<&str>,
    ) -> Result<usize> {
        let mut sessions = self.sessions.write().await;

        let session = match sessions.get_mut(payment_intent_id) {
            Some(s) => s,
            None => {
                warn!(
                    payment_intent_id = %payment_intent_id,
                    "No waiter found for payment status update"
                );
                return Ok(0);
            }
        };

        // Update last event ID
        if let Some(event_id) = event_id {
            session.last_event_id = Some(event_id.to_string());
        }

        let update = PaymentStatusUpdate {
            payment_intent_id: payment_intent_id.to_string(),
            status,
        };

        // Send to global channel
        let _ = self.global_tx.send(update.clone());

        match session.tx.send(update) {
            Ok(count) => {
                debug!(
                    payment_intent_id = %payment_intent_id,
                    receivers = count,
                    "Published payment status update"
                );
                Ok(count)
            }
            Err(e) => {
                warn!(
                    payment_intent_id = %payment_intent_id,
                    error = %e,
                    "Failed to publish payment status update (no receivers)"
                );
                Ok(0)
            }
        }
    }

    /// Subscribe to all payment status updates
    pub fn subscribe(&self) -> broadcast::Receiver<PaymentStatusUpdate> {
        self.global_tx.subscribe()
    }

    /// Mark a payment session as completed
    pub async fn mark_completed(&self, payment_intent_id: &str) {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(payment_intent_id) {
            session.completed = true;
            debug!(
                payment_intent_id = %payment_intent_id,
                "Marked payment session as completed"
            );
        }
    }

    /// Clean up expired sessions (called opportunistically during register_waiter)
    fn cleanup_expired_sessions(&self, sessions: &mut HashMap<String, PaymentSession>) {
        let expired: Vec<String> = sessions
            .iter()
            .filter(|(_, session)| session.is_expired(self.session_ttl))
            .map(|(id, _)| id.clone())
            .collect();

        for id in expired {
            sessions.remove(&id);
            debug!(payment_intent_id = %id, "Cleaned up expired payment session");
        }
    }
}

impl Default for PaymentState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_register_and_publish() {
        let state = PaymentState::new();
        let mut rx = state
            .register_waiter("pi_test")
            .await
            .unwrap();

        let count = state
            .publish_status(
                "pi_test",
                PaymentStatus::Succeeded {
                    amount: 100,
                    currency: "usd".to_string(),
                },
                Some("evt_1"),
            )
            .await
            .unwrap();

        assert_eq!(count, 1);

        let update = rx.recv().await.unwrap();
        assert_eq!(update.payment_intent_id, "pi_test");
        if let PaymentStatus::Succeeded { amount, .. } = update.status {
            assert_eq!(amount, 100);
        } else {
            panic!("Wrong status");
        }
    }

}

