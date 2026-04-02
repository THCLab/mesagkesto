use std::time::{Duration, Instant};

use actix::prelude::*;
use actix_web_actors::ws;
use serde::Deserialize;
use tracing::{debug, warn};

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
                warn!(aid = %act.aid, "WebSocket heartbeat timeout");
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

    fn handle_text_message(
        &self,
        text: &str,
        ctx: &mut ws::WebsocketContext<Self>,
    ) {
        // Try to parse as a control frame
        if let Ok(frame) = serde_json::from_str::<WsFrame>(text) {
            debug!(aid = %self.aid, frame_type = %frame.r#type, "WS incoming frame");
            match frame.r#type.as_str() {
                "msg" => {
                    // Relay message to recipient
                    if let Some(to) = frame.to {
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
                    }
                }
                "typing" => {
                    if let Some(to) = frame.to {
                        self.manager.do_send(RelayEphemeral {
                            to_aid: to,
                            text: text.to_string(),
                        });
                    }
                }
                "presence_query" => {
                    if let Some(aids) = frame.aids {
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
                    }
                }
                "presence_config" => {
                    if let Some(hidden_from) = frame.hidden_from {
                        self.manager.do_send(SetPresenceConfig {
                            aid: self.aid.clone(),
                            hidden_from,
                        });
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
            ctx.text(
                serde_json::json!({"type": "error", "message": "invalid JSON"}).to_string(),
            );
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
        debug!(aid = %self.aid, "WS session started");
        self.start_heartbeat(ctx);
        self.manager.do_send(Connect {
            aid: self.aid.clone(),
            addr: ctx.address().recipient(),
        });
    }

    fn stopping(&mut self, ctx: &mut Self::Context) -> Running {
        debug!(aid = %self.aid, "WS session stopping");
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
            Err(_) => {
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
                // Binary frames are forwarded as-is (for E2E encrypted payloads)
                // For now, echo back — will be routed in future
                ctx.binary(bin);
            }
            ws::Message::Close(reason) => {
                ctx.close(reason);
                ctx.stop();
            }
            _ => (),
        }
    }
}
