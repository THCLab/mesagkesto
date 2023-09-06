use std::collections::LinkedList;

use tokio::sync::{mpsc, oneshot};

use crate::{
    messagebox_listener::ApiError,
    validate::{ValidateHandle, ValidateMessage, ValidationError},
};

pub enum QueueMessage {
    Handle {
        message: String,
        // where to return result
        sender: oneshot::Sender<Option<String>>,
    },
}

pub struct QueueActor {
    // From where get messages
    receiver: mpsc::Receiver<QueueMessage>,
    queue: LinkedList<ValidateMessage>,
    validator: ValidateHandle,
}

impl QueueActor {
    fn new(receiver: mpsc::Receiver<QueueMessage>, validator: ValidateHandle) -> Self {
        QueueActor {
            receiver,
            queue: LinkedList::new(),
            validator,
        }
    }
    async fn handle_message(&mut self, msg: QueueMessage) {
        match msg {
            QueueMessage::Handle { message, sender } => {
                if self.queue.is_empty() {
                    match self.validator.validate(message.clone(), sender).await {
                        Ok(_) => (),
                        Err(ValidationError::FullChannel(message)) => self.queue.push_back(message),
                    }
                } else {
                    self.queue
                        .push_back(ValidateMessage::Authenticate { message, sender })
                };
            }
        }
    }
}

async fn run_my_actor(mut actor: QueueActor) {
    tokio::spawn(async move {
        while let Some(msg) = actor.receiver.recv().await {
            actor.handle_message(msg).await;
        }
        while let Some(ValidateMessage::Authenticate { message, sender }) = actor.queue.pop_front()
        {
            match actor.validator.validate(message, sender).await {
                Ok(_) => (),
                Err(ValidationError::FullChannel(message)) => actor.queue.push_front(message),
            };
        }
    });
}

#[derive(Clone)]
pub struct QueueHandle {
    queue_sender: mpsc::Sender<QueueMessage>,
}

impl QueueHandle {
    pub fn new(validator: ValidateHandle) -> Self {
        let (sender, receiver) = mpsc::channel(8);
        let actor = QueueActor::new(receiver, validator);
        tokio::spawn(run_my_actor(actor));

        Self {
            queue_sender: sender,
        }
    }

    pub async fn handle(&self, message: String) -> Result<Option<String>, ApiError> {
        let (sender, recv) = oneshot::channel();
        let msg = QueueMessage::Handle { message, sender };

        // Ignore send errors. If this send fails, so does the
        // recv.await below. There's no reason to check for the
        // same failure twice.
        let _ = self.queue_sender.send(msg).await;
        Ok(recv.await.expect("Actor task has been killed"))
    }
}
