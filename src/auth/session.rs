use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use time::{Duration, OffsetDateTime};
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::error::Result;

use super::user::{Privilege, UserRole};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub user_id: String,
    pub role: UserRole,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
    pub data: Option<serde_json::Value>,
}

impl Session {
    pub fn is_expired(&self) -> bool {
        OffsetDateTime::now_utc() > self.expires_at
    }

    pub fn has_privilege(&self, priv_: Privilege) -> bool {
        self.role.has_privilege(priv_)
    }
}

#[derive(Clone)]
pub struct SessionStore {
    inner: Arc<RwLock<HashMap<String, Session>>>,
    default_ttl: Duration,
}

impl SessionStore {
    pub fn new(ttl_secs: i64) -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
            default_ttl: Duration::seconds(ttl_secs),
        }
    }

    pub async fn create(&self, user_id: &str, role: UserRole) -> Result<Session> {
        let session = self.new_session(user_id, role);
        let mut guard = self.inner.write().await;
        guard.insert(session.id.clone(), session.clone());
        Ok(session)
    }

    pub async fn create_for_login(
        &self,
        user_id: &str,
        role: UserRole,
        allow_multiple_sessions: bool,
    ) -> Result<(Session, Vec<String>)> {
        let session = self.new_session(user_id, role);
        let mut guard = self.inner.write().await;
        let revoked = if allow_multiple_sessions {
            Vec::new()
        } else {
            // Only revoke existing sessions for the same user (multi-user safe)
            let ids: Vec<String> = guard
                .iter()
                .filter(|(_, s)| s.user_id == user_id)
                .map(|(id, _)| id.clone())
                .collect();
            for id in &ids {
                guard.remove(id);
            }
            ids
        };
        guard.insert(session.id.clone(), session.clone());
        Ok((session, revoked))
    }

    fn new_session(&self, user_id: &str, role: UserRole) -> Session {
        let now = OffsetDateTime::now_utc();
        Session {
            id: Uuid::new_v4().to_string(),
            user_id: user_id.to_string(),
            role,
            created_at: now,
            expires_at: now + self.default_ttl,
            data: None,
        }
    }

    pub async fn get(&self, session_id: &str) -> Result<Option<Session>> {
        let mut guard = self.inner.write().await;
        let Some(session) = guard.get(session_id).cloned() else {
            return Ok(None);
        };
        if session.is_expired() {
            guard.remove(session_id);
            return Ok(None);
        }
        Ok(Some(session))
    }

    pub async fn delete(&self, session_id: &str) -> Result<()> {
        let mut guard = self.inner.write().await;
        guard.remove(session_id);
        Ok(())
    }

    pub async fn cleanup_expired(&self) -> Result<u64> {
        let mut guard = self.inner.write().await;
        let before = guard.len();
        guard.retain(|_, s| !s.is_expired());
        Ok((before - guard.len()) as u64)
    }

    pub async fn delete_all(&self) -> Result<u64> {
        let mut guard = self.inner.write().await;
        let n = guard.len() as u64;
        guard.clear();
        Ok(n)
    }

    pub async fn delete_all_except(&self, session_id: &str) -> Result<Vec<String>> {
        let mut guard = self.inner.write().await;
        let revoked: Vec<String> = guard
            .keys()
            .filter(|id| id.as_str() != session_id)
            .cloned()
            .collect();
        guard.retain(|id, _| id == session_id);
        Ok(revoked)
    }

    pub async fn list_ids(&self) -> Result<Vec<String>> {
        let guard = self.inner.read().await;
        Ok(guard.keys().cloned().collect())
    }

    pub async fn extend(&self, session_id: &str) -> Result<()> {
        let mut guard = self.inner.write().await;
        if let Some(session) = guard.get_mut(session_id) {
            if session.is_expired() {
                guard.remove(session_id);
            } else {
                session.expires_at = OffsetDateTime::now_utc() + self.default_ttl;
            }
        }
        Ok(())
    }

    pub async fn delete_by_user(&self, user_id: &str) -> Result<Vec<String>> {
        let mut guard = self.inner.write().await;
        let removed: Vec<String> = guard
            .iter()
            .filter(|(_, s)| s.user_id == user_id)
            .map(|(id, _)| id.clone())
            .collect();
        for id in &removed {
            guard.remove(id);
        }
        Ok(removed)
    }

    pub async fn find_by_user(&self, user_id: &str) -> Result<Option<Session>> {
        let guard = self.inner.read().await;
        let found = guard
            .iter()
            .find(|(_, s)| s.user_id == user_id && !s.is_expired())
            .map(|(_, s)| s.clone());
        Ok(found)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn delete_all_except_preserves_only_current_session() {
        let sessions = SessionStore::new(60);
        let current = sessions.create("user", UserRole::Administrator).await.unwrap();
        let other = sessions.create("user", UserRole::Administrator).await.unwrap();

        let revoked = sessions.delete_all_except(&current.id).await.unwrap();
        assert_eq!(revoked, vec![other.id.clone()]);
        assert!(sessions.get(&current.id).await.unwrap().is_some());
        assert!(sessions.get(&other.id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn login_creation_applies_session_policy_atomically() {
        let sessions = SessionStore::new(60);
        let existing = sessions.create("user", UserRole::Administrator).await.unwrap();

        let (multiple, revoked) = sessions.create_for_login("user", UserRole::Administrator, true).await.unwrap();
        assert!(revoked.is_empty());
        assert!(sessions.get(&existing.id).await.unwrap().is_some());
        assert!(sessions.get(&multiple.id).await.unwrap().is_some());

        let (single, mut revoked) = sessions.create_for_login("user", UserRole::Administrator, false).await.unwrap();
        revoked.sort();
        let mut expected = vec![existing.id, multiple.id];
        expected.sort();
        assert_eq!(revoked, expected);
        assert_eq!(sessions.list_ids().await.unwrap(), vec![single.id]);
    }
}
