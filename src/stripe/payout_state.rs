// Payout state coordination module for managing active payout sessions and broadcasting updates

use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, RwLock};
use tracing::{debug, warn};

const DEFAULT_CHANNEL_CAPACITY: usize = 100;
const DEFAULT_SESSION_TTL: Duration = Duration::from_secs(3600); // 1 hour

/// Status of a payout as it progresses through the lifecycle
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PayoutStatus {
    Pending,
    Paid { amount: i64, currency: String },
    Failed { reason: String },
    Canceled,
}

/// Update message sent to waiters
#[derive(Debug, Clone)]
pub struct PayoutStatusUpdate {
    pub _payout_id: String,
    pub _status: PayoutStatus,
}

/// Internal session data for a payout
struct PayoutSession {
    tx: broadcast::Sender<PayoutStatusUpdate>,
    created_at: Instant,
    last_event_id: Option<String>,
    completed: bool,
}

impl PayoutSession {
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

/// Shared payout state coordinator
pub struct PayoutState {
    sessions: Arc<RwLock<HashMap<String, PayoutSession>>>,
    session_ttl: Duration,
}

impl PayoutState {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            session_ttl: DEFAULT_SESSION_TTL,
        }
    }


    /// Register a waiter for payout updates and return a receiver
    pub async fn register_waiter(
        &self,
        payout_id: &str,
    ) -> Result<broadcast::Receiver<PayoutStatusUpdate>> {
        let mut sessions = self.sessions.write().await;
        
        // Clean up expired sessions opportunistically
        self.cleanup_expired_sessions(&mut sessions);

        let session = sessions
            .entry(payout_id.to_string())
            .or_insert_with(|| {
                debug!(
                    payout_id = %payout_id,
                    "Registering new payout session"
                );
                PayoutSession::new()
            });

        let rx = session.tx.subscribe();
        Ok(rx)
    }

    /// Publish a status update to all waiters for a payout
    pub async fn publish_status(
        &self,
        payout_id: &str,
        status: PayoutStatus,
        event_id: Option<&str>,
    ) -> Result<usize> {
        let mut sessions = self.sessions.write().await;

        let session = match sessions.get_mut(payout_id) {
            Some(s) => s,
            None => {
                warn!(
                    payout_id = %payout_id,
                    "No waiter found for payout status update"
                );
                return Ok(0);
            }
        };

        // Update last event ID
        if let Some(event_id) = event_id {
            session.last_event_id = Some(event_id.to_string());
        }

        let update = PayoutStatusUpdate {
            _payout_id: payout_id.to_string(),
            _status: status,
        };

        match session.tx.send(update) {
            Ok(count) => {
                debug!(
                    payout_id = %payout_id,
                    receivers = count,
                    "Published payout status update"
                );
                Ok(count)
            }
            Err(e) => {
                warn!(
                    payout_id = %payout_id,
                    error = %e,
                    "Failed to publish payout status update (no receivers)"
                );
                Ok(0)
            }
        }
    }

    /// Mark a payout session as completed
    pub async fn mark_completed(&self, payout_id: &str) {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.get_mut(payout_id) {
            session.completed = true;
            debug!(
                payout_id = %payout_id,
                "Marked payout session as completed"
            );
        }
    }

    /// Clean up expired sessions (called opportunistically during register_waiter)
    fn cleanup_expired_sessions(&self, sessions: &mut HashMap<String, PayoutSession>) {
        let expired: Vec<String> = sessions
            .iter()
            .filter(|(_, session)| session.is_expired(self.session_ttl))
            .map(|(id, _)| id.clone())
            .collect();

        for id in expired {
            sessions.remove(&id);
            debug!(payout_id = %id, "Cleaned up expired payout session");
        }
    }
}

impl Default for PayoutState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_register_and_publish() {
        let state = PayoutState::new();
        let mut rx = state
            .register_waiter("po_test")
            .await
            .unwrap();

        let count = state
            .publish_status(
                "po_test",
                PayoutStatus::Pending,
                Some("evt_1"),
            )
            .await
            .unwrap();

        assert_eq!(count, 1);

        let update = rx.recv().await.unwrap();
        assert_eq!(update._payout_id, "po_test");
        assert_eq!(update._status, PayoutStatus::Pending);
    }

}

