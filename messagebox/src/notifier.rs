use serde_json::json;
use tokio::sync::mpsc;

use crate::db::Db;

pub enum NotifyMessage {
    Notify { identifier: String, digest: String },
    SaveToken { identifier: String, token: String },
}

pub struct NotifyActor {
    receiver: mpsc::Receiver<NotifyMessage>,
    server_key: String,
    db: Db,
}

impl NotifyActor {
    fn new(receiver: mpsc::Receiver<NotifyMessage>, server_key: String, db: Db) -> Self {
        NotifyActor {
            receiver,
            server_key,
            db,
        }
    }

    async fn handle_message(&mut self, msg: NotifyMessage) {
        match msg {
            NotifyMessage::Notify { identifier, digest } => {
                match self.db.get_firebase_token(&identifier) {
                    Ok(Some(token)) => {
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
                    Ok(None) => (),
                    Err(e) => eprintln!("Failed to get firebase token: {}", e),
                }
            }
            NotifyMessage::SaveToken { identifier, token } => {
                if let Err(e) = self.db.save_firebase_token(&identifier, &token) {
                    eprintln!("Failed to save firebase token: {}", e);
                }
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
    pub fn new(server_key: String, db: Db) -> Self {
        let (sender, receiver) = mpsc::channel(8);
        let actor = NotifyActor::new(receiver, server_key, db);
        tokio::spawn(run_my_actor(actor));

        Self {
            notify_sender: sender,
        }
    }

    pub async fn notify(&self, identifier: String, digest: String) {
        let msg = NotifyMessage::Notify { identifier, digest };
        let _ = self.notify_sender.send(msg).await;
    }

    pub async fn save_token(&self, identifier: String, token: String) {
        let msg = NotifyMessage::SaveToken { identifier, token };
        let _ = self.notify_sender.send(msg).await;
    }
}
