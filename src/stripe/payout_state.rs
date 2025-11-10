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
    InTransit,
    Paid { amount: i64, currency: String },
    Failed { reason: String },
    Canceled,
    Timeout,
}

/// Update message sent to waiters
#[derive(Debug, Clone)]
pub struct PayoutStatusUpdate {
    pub payout_id: String,
    pub status: PayoutStatus,
    pub message: Option<String>,
}

/// Internal session data for a payout
struct PayoutSession {
    payout_id: String,
    tx: broadcast::Sender<PayoutStatusUpdate>,
    metadata: HashMap<String, String>,
    created_at: Instant,
    last_event_id: Option<String>,
    completed: bool,
}

impl PayoutSession {
    fn new(payout_id: String, metadata: HashMap<String, String>) -> Self {
        let (tx, _rx) = broadcast::channel(DEFAULT_CHANNEL_CAPACITY);
        Self {
            payout_id,
            tx,
            metadata,
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

    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.session_ttl = ttl;
        self
    }

    /// Register a waiter for payout updates and return a receiver
    pub async fn register_waiter(
        &self,
        payout_id: &str,
        metadata: HashMap<String, String>,
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
                PayoutSession::new(payout_id.to_string(), metadata)
            });

        let rx = session.tx.subscribe();
        Ok(rx)
    }

    /// Publish a status update to all waiters for a payout
    pub async fn publish_status(
        &self,
        payout_id: &str,
        status: PayoutStatus,
        message: Option<String>,
        event_id: Option<&str>,
    ) -> Result<usize> {
        let mut sessions = self.sessions.write().await;

        // Check for duplicate event
        if let Some(session) = sessions.get(payout_id) {
            if let (Some(event_id), Some(last_event_id)) = (event_id, &session.last_event_id) {
                if event_id == last_event_id {
                    debug!(
                        payout_id = %payout_id,
                        event_id = %event_id,
                        "Skipping duplicate event"
                    );
                    return Ok(0);
                }
            }
        }

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
            payout_id: payout_id.to_string(),
            status,
            message,
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

    /// Remove a waiter/session
    pub async fn remove_waiter(&self, payout_id: &str) {
        let mut sessions = self.sessions.write().await;
        if sessions.remove(payout_id).is_some() {
            debug!(
                payout_id = %payout_id,
                "Removed payout session"
            );
        }
    }

    /// Get a snapshot of the current status
    pub async fn get_status_snapshot(&self, payout_id: &str) -> Option<(bool, Option<String>)> {
        let sessions = self.sessions.read().await;
        sessions.get(payout_id).map(|s| (s.completed, s.last_event_id.clone()))
    }

    /// Check if a session exists
    pub async fn has_session(&self, payout_id: &str) -> bool {
        let sessions = self.sessions.read().await;
        sessions.contains_key(payout_id)
    }

    /// Get receiver count for a session
    pub async fn receiver_count(&self, payout_id: &str) -> usize {
        let sessions = self.sessions.read().await;
        sessions
            .get(payout_id)
            .map(|s| s.tx.receiver_count())
            .unwrap_or(0)
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

    /// Manually trigger cleanup of expired sessions
    pub async fn cleanup(&self) {
        let mut sessions = self.sessions.write().await;
        self.cleanup_expired_sessions(&mut sessions);
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
            .register_waiter("po_test", HashMap::new())
            .await
            .unwrap();

        let count = state
            .publish_status(
                "po_test",
                PayoutStatus::Pending,
                Some("Processing payout".to_string()),
                Some("evt_1"),
            )
            .await
            .unwrap();

        assert_eq!(count, 1);

        let update = rx.recv().await.unwrap();
        assert_eq!(update.payout_id, "po_test");
        assert_eq!(update.status, PayoutStatus::Pending);
    }

    #[tokio::test]
    async fn test_duplicate_event_idempotency() {
        let state = PayoutState::new();
        let _rx = state
            .register_waiter("po_test", HashMap::new())
            .await
            .unwrap();

        // First event
        let count1 = state
            .publish_status(
                "po_test",
                PayoutStatus::Pending,
                None,
                Some("evt_1"),
            )
            .await
            .unwrap();
        assert_eq!(count1, 1);

        // Duplicate event - should be skipped
        let count2 = state
            .publish_status(
                "po_test",
                PayoutStatus::Paid {
                    amount: 100,
                    currency: "usd".to_string(),
                },
                None,
                Some("evt_1"),
            )
            .await
            .unwrap();
        assert_eq!(count2, 0);
    }

    #[tokio::test]
    async fn test_session_ttl() {
        let state = PayoutState::new().with_ttl(Duration::from_millis(100));
        state
            .register_waiter("po_test", HashMap::new())
            .await
            .unwrap();

        assert!(state.has_session("po_test").await);

        tokio::time::sleep(Duration::from_millis(200)).await;

        // Trigger cleanup by registering a new waiter
        state
            .register_waiter("po_test2", HashMap::new())
            .await
            .unwrap();

        // Original session should be cleaned up
        assert!(!state.has_session("po_test").await);
    }
}