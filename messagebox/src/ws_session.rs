use std::time::{Duration, Instant};

use actix::prelude::*;
use actix_web_actors::ws;
use serde::Deserialize;
use tracing::{debug, info, warn};

use crate::connection::{
    Connect, ConnectionManager, Disconnect, QueryPresence, RelayEphemeral, RelayMessage,
    SetPresenceConfig, WsMessage,
};

const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);
const CLIENT_TIMEOUT: Duration = Duration::from_secs(60);

/// Per-connection WebSocket session actor
pub struct WsSession {
    /// Authenticated AID for this session
    pub aid: String,
    /// Last heartbeat received
    pub last_hb: Instant,
    /// Connection manager address
    pub manager: Addr<ConnectionManager>,
}

impl WsSession {
    fn start_heartbeat(&self, ctx: &mut ws::WebsocketContext<Self>) {
        ctx.run_interval(HEARTBEAT_INTERVAL, |act, ctx| {
            if Instant::now().duration_since(act.last_hb) > CLIENT_TIMEOUT {
                warn!(aid = %act.aid, "WebSocket heartbeat timeout, closing connection");
                act.manager.do_send(Disconnect {
                    aid: act.aid.clone(),
                    addr: ctx.address().recipient(),
                });
                ctx.stop();
                return;
            }
            ctx.ping(b"");
        });
    }

    fn handle_text_message(&self, text: &str, ctx: &mut ws::WebsocketContext<Self>) {
        // Try to parse as a control frame
        if let Ok(frame) = serde_json::from_str::<WsFrame>(text) {
            debug!(aid = %self.aid, frame_type = %frame.r#type, "WS incoming frame");
            match frame.r#type.as_str() {
                "msg" => {
                    // Relay message to recipient
                    if let Some(to) = frame.to {
                        debug!(aid = %self.aid, to_aid = %to, "Relaying message");
                        let manager = self.manager.clone();
                        let text = text.to_string();
                        ctx.spawn(
                            async move {
                                let delivered = manager
                                    .send(RelayMessage {
                                        to_aid: to.clone(),
                                        text: text.clone(),
                                    })
                                    .await
                                    .unwrap_or(false);

                                // Send ack back to sender
                                let ack = serde_json::json!({
                                    "type": "ack",
                                    "to": to,
                                    "delivered": delivered,
                                });
                                ack.to_string()
                            }
                            .into_actor(self)
                            .map(|ack_text, _act, ctx| {
                                ctx.text(ack_text);
                            }),
                        );
                    } else {
                        warn!(aid = %self.aid, "Message frame missing 'to' field");
                    }
                }
                "typing" => {
                    if let Some(to) = frame.to {
                        debug!(aid = %self.aid, to_aid = %to, "Relaying typing indicator");
                        self.manager.do_send(RelayEphemeral {
                            to_aid: to,
                            text: text.to_string(),
                        });
                    } else {
                        debug!(aid = %self.aid, "Typing frame missing 'to' field");
                    }
                }
                "presence_query" => {
                    if let Some(aids) = frame.aids {
                        debug!(aid = %self.aid, query_count = aids.len(), "Querying presence");
                        let manager = self.manager.clone();
                        ctx.spawn(
                            async move {
                                let results = manager
                                    .send(QueryPresence { aids })
                                    .await
                                    .unwrap_or_default();
                                serde_json::json!({
                                    "type": "presence_result",
                                    "presence": results.into_iter()
                                        .map(|(aid, state)| serde_json::json!({"aid": aid, "state": state}))
                                        .collect::<Vec<_>>(),
                                })
                                .to_string()
                            }
                            .into_actor(self)
                            .map(|result_text, _act, ctx| {
                                ctx.text(result_text);
                            }),
                        );
                    } else {
                        debug!(aid = %self.aid, "Presence query frame missing 'aids' field");
                    }
                }
                "presence_config" => {
                    if let Some(hidden_from) = frame.hidden_from {
                        debug!(aid = %self.aid, hidden_count = hidden_from.len(), "Updating presence config");
                        self.manager.do_send(SetPresenceConfig {
                            aid: self.aid.clone(),
                            hidden_from,
                        });
                    } else {
                        debug!(aid = %self.aid, "Presence config frame missing 'hidden_from' field");
                    }
                }
                _ => {
                    ctx.text(
                        serde_json::json!({"type": "error", "message": "unknown frame type"})
                            .to_string(),
                    );
                }
            }
        } else {
            ctx.text(serde_json::json!({"type": "error", "message": "invalid JSON"}).to_string());
        }
    }
}

/// Minimal frame structure for parsing incoming WebSocket messages
#[derive(Deserialize)]
struct WsFrame {
    r#type: String,
    to: Option<String>,
    aids: Option<Vec<String>>,
    hidden_from: Option<Vec<String>>,
}

impl Actor for WsSession {
    type Context = ws::WebsocketContext<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        info!(aid = %self.aid, "WebSocket session started");
        debug!(aid = %self.aid, "Starting heartbeat");
        self.start_heartbeat(ctx);
        self.manager.do_send(Connect {
            aid: self.aid.clone(),
            addr: ctx.address().recipient(),
        });
    }

    fn stopping(&mut self, ctx: &mut Self::Context) -> Running {
        info!(aid = %self.aid, "WebSocket session stopping");
        self.manager.do_send(Disconnect {
            aid: self.aid.clone(),
            addr: ctx.address().recipient(),
        });
        Running::Stop
    }
}

impl Handler<WsMessage> for WsSession {
    type Result = ();

    fn handle(&mut self, msg: WsMessage, ctx: &mut Self::Context) {
        ctx.text(msg.0);
    }
}

impl StreamHandler<Result<ws::Message, ws::ProtocolError>> for WsSession {
    fn handle(&mut self, msg: Result<ws::Message, ws::ProtocolError>, ctx: &mut Self::Context) {
        let msg = match msg {
            Ok(msg) => msg,
            Err(e) => {
                warn!(aid = %self.aid, error = %e, "WebSocket protocol error, stopping");
                ctx.stop();
                return;
            }
        };

        match msg {
            ws::Message::Ping(data) => {
                self.last_hb = Instant::now();
                ctx.pong(&data);
            }
            ws::Message::Pong(_) => {
                self.last_hb = Instant::now();
            }
            ws::Message::Text(text) => {
                self.handle_text_message(&text, ctx);
            }
            ws::Message::Binary(bin) => {
                debug!(aid = %self.aid, bin_len = bin.len(), "Received binary frame");
                // Binary frames are forwarded as-is (for E2E encrypted payloads)
                // For now, echo back — will be routed in future
                ctx.binary(bin);
            }
            ws::Message::Close(reason) => {
                debug!(aid = %self.aid, reason = ?reason, "WebSocket close requested");
                ctx.close(reason);
                ctx.stop();
            }
            _ => {
                debug!(aid = %self.aid, "Received unhandled WebSocket frame type");
            }
        }
    }
}
