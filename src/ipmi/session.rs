//! IPMI 2.0 RMCP+ session management.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use super::protocol::{AUTH_TYPE_RMCP_PLUS, PRIV_ADMINISTRATOR};

const SESSION_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_SESSIONS: usize = 8;

#[allow(dead_code)]
pub struct IpmiSession {
    pub session_id: u32,
    pub auth_type: u8,
    pub privilege: u8,
    pub client_seq: u32,
    pub server_seq: u32,
    pub is_active: bool,
    pub last_activity: Instant,
    pub console_session_id: u32,
    pub bmc_rand: Option<[u8; 16]>,
    pub console_rand: Option<[u8; 16]>,
    pub dh_private: Option<Vec<u8>>,
    pub dh_shared_secret: Option<Vec<u8>>,
    pub sik: Option<[u8; 20]>,
    pub k1: Option<[u8; 20]>,
    pub k2: Option<[u8; 16]>,
    pub username: Option<String>,
    pub auth_algo: u8,
    pub integrity_algo: u8,
    pub conf_algo: u8,
}

impl IpmiSession {
    pub fn new(session_id: u32, console_session_id: u32) -> Self {
        Self {
            session_id,
            auth_type: AUTH_TYPE_RMCP_PLUS,
            privilege: PRIV_ADMINISTRATOR,
            client_seq: 0,
            server_seq: 1,
            is_active: false,
            last_activity: Instant::now(),
            console_session_id,
            bmc_rand: None,
            console_rand: None,
            dh_private: None,
            dh_shared_secret: None,
            sik: None,
            k1: None,
            k2: None,
            username: None,
            auth_algo: 0,
            integrity_algo: 0,
            conf_algo: 0,
        }
    }

    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    pub fn is_expired(&self) -> bool {
        self.last_activity.elapsed() > SESSION_TIMEOUT
    }
}

pub struct SessionManager {
    sessions: HashMap<u32, IpmiSession>,
    next_id: AtomicU32,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            next_id: AtomicU32::new(1),
        }
    }

    fn allocate_id(&self) -> u32 {
        let mut id = self.next_id.fetch_add(1, Ordering::Relaxed);
        while id == 0 {
            id = self.next_id.fetch_add(1, Ordering::Relaxed);
        }
        id
    }

    pub fn create_session(&mut self, console_session_id: u32) -> u32 {
        self.cleanup_expired();
        if self.sessions.len() >= MAX_SESSIONS {
            self.evict_oldest();
        }
        let session_id = self.allocate_id();
        let session = IpmiSession::new(session_id, console_session_id);
        self.sessions.insert(session_id, session);
        session_id
    }

    pub fn get_session(&self, session_id: u32) -> Option<&IpmiSession> {
        self.sessions.get(&session_id)
    }

    pub fn get_session_mut(&mut self, session_id: u32) -> Option<&mut IpmiSession> {
        self.sessions.get_mut(&session_id)
    }

    pub fn remove_session(&mut self, session_id: u32) {
        self.sessions.remove(&session_id);
    }

    fn evict_oldest(&mut self) {
        if let Some(id) = self
            .sessions
            .iter()
            .filter(|(_, s)| !s.is_active)
            .min_by_key(|(_, s)| s.last_activity)
            .map(|(id, _)| *id)
            .or_else(|| {
                self.sessions
                    .iter()
                    .min_by_key(|(_, s)| s.last_activity)
                    .map(|(id, _)| *id)
            })
        {
            self.sessions.remove(&id);
        }
    }

    fn cleanup_expired(&mut self) {
        self.sessions.retain(|_, s| !s.is_expired());
    }
}
