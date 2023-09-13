use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use serde_json::json;
use tokio::sync::mpsc;

pub enum NotifyMessage {
    Notify { identifier: String, digest: String },
    SaveToken { identifier: String, token: String },
}

pub struct NotifyActor {
    // From where get messages
    receiver: mpsc::Receiver<NotifyMessage>,
    server_key: String,
    tokens_map: Arc<Mutex<HashMap<String, String>>>,
}

impl NotifyActor {
    fn new(receiver: mpsc::Receiver<NotifyMessage>, server_key: String) -> Self {
        NotifyActor {
            receiver,
            server_key,
            tokens_map: Arc::new(Mutex::new(HashMap::new())),
        }
    }
    async fn handle_message(&mut self, msg: NotifyMessage) {
        match msg {
            NotifyMessage::Notify { identifier, digest } => {
                match self.tokens_map.lock().unwrap().get(&identifier) {
                    Some(token) => {
                        let body = json!({
                        "notification": {
                            "body": {"d": digest, "i": identifier},
                            "title": "Got message for you"
                        },
                        "priority": "high",
                        "data": {
                            "click_action": "FLUTTER_NOTIFICATION_CLICK",
                            "id": "1",
                            "status": "done",
                            "body": {"d": digest, "i": identifier},
                        },
                        "to": token,
                        });
                        let res = ureq::post("https://fcm.googleapis.com/fcm/send")
                            .set("Authorization", &format!("key={}", self.server_key))
                            .set("Content-Type", "application/json; charset=UTF-8")
                            .send_json(body)
                            .unwrap();
                        println!("Notifying token {}, res: {:?}", token, res);
                    }
                    None => (),
                };
            }
            NotifyMessage::SaveToken { identifier, token } => {
                self.tokens_map.lock().unwrap().insert(identifier, token);
            }
        }
    }
}

async fn run_my_actor(mut actor: NotifyActor) {
    while let Some(msg) = actor.receiver.recv().await {
        actor.handle_message(msg).await;
    }
}

#[derive(Clone)]
pub struct NotifyHandle {
    notify_sender: mpsc::Sender<NotifyMessage>,
}

impl NotifyHandle {
    pub fn new(server_key: String) -> Self {
        let (sender, receiver) = mpsc::channel(8);
        let actor = NotifyActor::new(receiver, server_key);
        tokio::spawn(run_my_actor(actor));

        Self {
            notify_sender: sender,
        }
    }

    pub async fn notify(&self, identifier: String, digest: String) {
        let msg = NotifyMessage::Notify { identifier, digest };

        // Ignore send errors. If this send fails, so does the
        // recv.await below. There's no reason to check for the
        // same failure twice.
        let _ = self.notify_sender.send(msg).await;
    }

    pub async fn save_token(&self, identifier: String, token: String) {
        let msg = NotifyMessage::SaveToken { identifier, token };

        // Ignore send errors. If this send fails, so does the
        // recv.await below. There's no reason to check for the
        // same failure twice.
        let _ = self.notify_sender.send(msg).await;
    }
}
