use std::collections::HashMap;

use actix::prelude::*;
use serde::{Deserialize, Serialize};

/// Presence state for an AID
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PresenceState {
    Online,
    Away,
    Offline,
}

/// Messages sent to the ConnectionManager actor

/// Register a new WebSocket session
#[derive(Message)]
#[rtype(result = "()")]
pub struct Connect {
    pub aid: String,
    pub addr: Recipient<WsMessage>,
}

/// Unregister a WebSocket session
#[derive(Message)]
#[rtype(result = "()")]
pub struct Disconnect {
    pub aid: String,
    pub addr: Recipient<WsMessage>,
}

/// Relay a message to a specific AID's active sessions
#[derive(Message)]
#[rtype(result = "bool")]
pub struct RelayMessage {
    pub to_aid: String,
    pub text: String,
}

/// Query presence for a set of AIDs
#[derive(Message)]
#[rtype(result = "Vec<(String, PresenceState)>")]
pub struct QueryPresence {
    pub aids: Vec<String>,
}

/// Relay ephemeral data (typing, presence) to a specific AID
#[derive(Message)]
#[rtype(result = "()")]
pub struct RelayEphemeral {
    pub to_aid: String,
    pub text: String,
}

/// Update presence visibility config
#[derive(Message)]
#[rtype(result = "()")]
pub struct SetPresenceConfig {
    pub aid: String,
    pub hidden_from: Vec<String>,
}

/// Message sent to individual WsSession actors
#[derive(Message, Clone)]
#[rtype(result = "()")]
pub struct WsMessage(pub String);

/// The central connection manager actor
pub struct ConnectionManager {
    /// AID -> list of active WebSocket session addresses
    sessions: HashMap<String, Vec<Recipient<WsMessage>>>,
    /// AID -> current presence state
    presence: HashMap<String, PresenceState>,
    /// AID -> list of HMAC tokens to hide presence from
    presence_hidden: HashMap<String, Vec<String>>,
}

impl ConnectionManager {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            presence: HashMap::new(),
            presence_hidden: HashMap::new(),
        }
    }

    fn broadcast_presence(&self, aid: &str, state: &PresenceState) {
        let msg = serde_json::json!({
            "type": "presence",
            "aid": aid,
            "state": state,
        })
        .to_string();

        let hidden = self.presence_hidden.get(aid);

        // Send presence update to all other connected AIDs
        for (other_aid, sessions) in &self.sessions {
            if other_aid == aid {
                continue;
            }
            // Check if this AID is hidden from the other
            if let Some(hidden_list) = hidden {
                if hidden_list.contains(other_aid) {
                    continue;
                }
            }
            for addr in sessions {
                let _ = addr.do_send(WsMessage(msg.clone()));
            }
        }
    }
}

impl Actor for ConnectionManager {
    type Context = Context<Self>;
}

impl Handler<Connect> for ConnectionManager {
    type Result = ();

    fn handle(&mut self, msg: Connect, _ctx: &mut Self::Context) {
        let was_offline = !self.sessions.contains_key(&msg.aid)
            || self.sessions.get(&msg.aid).map(|s| s.is_empty()).unwrap_or(true);

        self.sessions
            .entry(msg.aid.clone())
            .or_default()
            .push(msg.addr);

        if was_offline {
            self.presence
                .insert(msg.aid.clone(), PresenceState::Online);
            self.broadcast_presence(&msg.aid, &PresenceState::Online);
        }
    }
}

impl Handler<Disconnect> for ConnectionManager {
    type Result = ();

    fn handle(&mut self, msg: Disconnect, _ctx: &mut Self::Context) {
        if let Some(sessions) = self.sessions.get_mut(&msg.aid) {
            sessions.retain(|addr| addr != &msg.addr);
            if sessions.is_empty() {
                self.sessions.remove(&msg.aid);
                self.presence
                    .insert(msg.aid.clone(), PresenceState::Offline);
                self.broadcast_presence(&msg.aid, &PresenceState::Offline);
            }
        }
    }
}

impl Handler<RelayMessage> for ConnectionManager {
    type Result = bool;

    fn handle(&mut self, msg: RelayMessage, _ctx: &mut Self::Context) -> bool {
        if let Some(sessions) = self.sessions.get(&msg.to_aid) {
            if sessions.is_empty() {
                return false;
            }
            for addr in sessions {
                let _ = addr.do_send(WsMessage(msg.text.clone()));
            }
            true
        } else {
            false
        }
    }
}

impl Handler<QueryPresence> for ConnectionManager {
    type Result = Vec<(String, PresenceState)>;

    fn handle(&mut self, msg: QueryPresence, _ctx: &mut Self::Context) -> Self::Result {
        msg.aids
            .into_iter()
            .map(|aid| {
                let state = self
                    .presence
                    .get(&aid)
                    .cloned()
                    .unwrap_or(PresenceState::Offline);
                (aid, state)
            })
            .collect()
    }
}

impl Handler<RelayEphemeral> for ConnectionManager {
    type Result = ();

    fn handle(&mut self, msg: RelayEphemeral, _ctx: &mut Self::Context) {
        if let Some(sessions) = self.sessions.get(&msg.to_aid) {
            for addr in sessions {
                let _ = addr.do_send(WsMessage(msg.text.clone()));
            }
        }
    }
}

impl Handler<SetPresenceConfig> for ConnectionManager {
    type Result = ();

    fn handle(&mut self, msg: SetPresenceConfig, _ctx: &mut Self::Context) {
        self.presence_hidden.insert(msg.aid, msg.hidden_from);
    }
}
