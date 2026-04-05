use chrono::Utc;
use keri_sdk::keri_core::actor::prelude::{HashFunction, HashFunctionCode};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info, warn};

use crate::{
    acl::AclHandle,
    channel::{ChannelHandle, ChannelType, MemberRole},
    notifier::NotifyHandle,
    responses_store::ResponsesHandle,
    storage::StorageHandle,
    MessageboxError,
};

#[derive(Serialize, Deserialize)]
#[serde(tag = "t")]
#[serde(rename_all = "lowercase")]
pub enum MessageType {
    Qry(QueryArguments),
    Exn(ExchangeArguments),
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
pub enum QueryArguments {
    ByDigest { i: String, d: Vec<String> },
    BySn { i: String, s: usize },
}

impl ToString for MessageType {
    fn to_string(&self) -> String {
        serde_json::to_string(&self).unwrap()
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "r")]
#[serde(rename_all = "lowercase")]
pub enum ExchangeArguments {
    // Forward `a` to other identifier
    Fwd {
        i: String,
        a: String,
    },
    // Save firebase token (f) of given identifier (i)
    #[serde(rename = "/auth/f")]
    SetFirebase {
        i: String,
        f: String,
    },
    // Create a new channel
    #[serde(rename = "/ch/create")]
    ChannelCreate {
        channel_type: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        topic: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        description: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        avatar: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        background: Option<String>,
        #[serde(default)]
        members: Vec<String>,
    },
    // Send a message to a channel
    #[serde(rename = "/ch/msg")]
    ChannelMsg {
        ch: String,
        a: String,
    },
    // Invite an AID to a channel
    #[serde(rename = "/ch/invite")]
    ChannelInvite {
        ch: String,
        to: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        role: Option<String>,
    },
    // Accept a channel invite
    #[serde(rename = "/ch/accept")]
    ChannelAccept {
        ch: String,
    },
    // Reject a channel invite
    #[serde(rename = "/ch/reject")]
    ChannelReject {
        ch: String,
    },
    // Leave a channel
    #[serde(rename = "/ch/leave")]
    ChannelLeave {
        ch: String,
    },
    // Remove a member from a channel
    #[serde(rename = "/ch/remove")]
    ChannelRemove {
        ch: String,
        target: String,
    },
    // Set a member's role in a channel
    #[serde(rename = "/ch/role")]
    ChannelSetRole {
        ch: String,
        target: String,
        role: String,
    },
    // Update channel profile metadata (creator only)
    #[serde(rename = "/ch/update")]
    ChannelUpdate {
        ch: String,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        description: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        avatar: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none", default)]
        background: Option<String>,
    },
    // Subscribe to a public broadcast channel
    #[serde(rename = "/ch/sub")]
    ChannelSubscribe {
        ch: String,
    },
}

pub enum ValidateMessage {
    Authenticate {
        message: String,
        /// AID of the CESR-verified sender (if extractable from signature)
        sender_aid: Option<String>,
        // where to return result
        sender: oneshot::Sender<Result<Option<String>, MessageboxError>>,
    },
    ProcessAndSave {
        message: String,
    },
}

pub struct ValidateActor {
    // From where get messages
    receiver: mpsc::Receiver<ValidateMessage>,
    storage: StorageHandle,
    notify: NotifyHandle,
    responses_handle: ResponsesHandle,
    acl: AclHandle,
    channel: ChannelHandle,
}

impl ValidateActor {
    fn new(
        receiver: mpsc::Receiver<ValidateMessage>,
        storage: StorageHandle,
        notify: NotifyHandle,
        responses: ResponsesHandle,
        acl: AclHandle,
        channel: ChannelHandle,
    ) -> Self {
        ValidateActor {
            receiver,
            storage,
            notify,
            responses_handle: responses,
            acl,
            channel,
        }
    }

    async fn process(
        &self,
        message: &str,
        sender_aid: Option<&str>,
    ) -> Result<Option<String>, MessageboxError> {
        debug!(message_len = message.len(), sender = ?sender_aid, "Processing message");
        if let Ok(parsed) = serde_json::from_str::<MessageType>(message) {
            match parsed {
                MessageType::Qry(qry) => match qry {
                    QueryArguments::ByDigest { i, d } => {
                        debug!(identifier = %i, digest_count = d.len(), "Query by digest");
                        Ok(self.storage.get_by_digest(&i, d).await)
                    }
                    QueryArguments::BySn { i, s } => {
                        debug!(identifier = %i, sn = s, "Query by sequence number");
                        Ok(self.storage.get_by_index(&i, s).await)
                    }
                },
                MessageType::Exn(exn) => match exn {
                    ExchangeArguments::Fwd { i, a } => {
                        // ACL enforcement: check if the sender is authorized to
                        // write to recipient `i`'s mailbox.
                        let acl_tokens = self.acl.get_tokens(&i).await;
                        if !acl_tokens.is_empty() {
                            let authorized = match sender_aid {
                                Some(aid) => acl_tokens.iter().any(|t| t == aid),
                                None => false,
                            };
                            if !authorized {
                                let sender_str = sender_aid.unwrap_or("unknown").to_string();
                                warn!(
                                    sender = %sender_str,
                                    recipient = %i,
                                    "ACL denied: sender not in recipient's whitelist"
                                );
                                return Err(MessageboxError::AclDenied(sender_str));
                            }
                        }

                        info!(recipient = %i, sender = ?sender_aid, msg_len = a.len(), "Forwarding message");
                        let digest_algo: HashFunction = (HashFunctionCode::Blake3_256).into();
                        let sai = digest_algo.derive(a.as_bytes()).to_string();
                        self.storage.save(i.clone(), a, sai).await.to_string();
                        Ok(None)
                    }
                    ExchangeArguments::SetFirebase { i, f: t } => {
                        info!(identifier = %i, "Registering Firebase token");
                        self.notify.save_token(i, t).await;
                        Ok(None)
                    }
                    ExchangeArguments::ChannelCreate {
                        channel_type,
                        topic,
                        description,
                        avatar,
                        background,
                        members,
                    } => {
                        let sender_str = sender_aid
                            .ok_or(MessageboxError::VerificationFailure)?
                            .to_string();
                        let ct = parse_channel_type(&channel_type)?;
                        info!(creator = %sender_str, channel_type = %channel_type, "Creating channel");
                        let channel = self
                            .channel
                            .create(sender_str, ct, topic, description, avatar, background, members)
                            .await?;

                        // Notify invited members
                        for member in &channel.members {
                            if member.status == crate::channel::MemberStatus::Invited {
                                self.notify
                                    .notify(member.aid.clone(), channel.said.clone())
                                    .await;
                            }
                        }

                        Ok(Some(serde_json::to_string(&channel).unwrap()))
                    }
                    ExchangeArguments::ChannelMsg { ch, a } => {
                        let sender_str = sender_aid
                            .ok_or(MessageboxError::VerificationFailure)?
                            .to_string();
                        let channel = self
                            .channel
                            .get(&ch)
                            .await
                            .ok_or(MessageboxError::UnknownMessage(
                                "Channel not found".into(),
                            ))?;

                        // Check write permission
                        if !channel.can_write(&sender_str) {
                            warn!(sender = %sender_str, channel = %ch, "Channel write denied");
                            return Err(MessageboxError::AclDenied(sender_str));
                        }

                        info!(channel = %ch, sender = %sender_str, msg_len = a.len(), "Channel message");
                        let digest_algo: HashFunction = (HashFunctionCode::Blake3_256).into();
                        let sai = digest_algo.derive(a.as_bytes()).to_string();
                        // Store structured message with sender metadata
                        let structured_msg = json!({
                            "sender": sender_str,
                            "content": a,
                            "ts": Utc::now().to_rfc3339(),
                            "digest": sai,
                        });
                        self.storage
                            .save_channel(ch.clone(), structured_msg.to_string(), sai.clone())
                            .await;

                        // Notify active members (except sender)
                        for member in &channel.members {
                            if member.status == crate::channel::MemberStatus::Active
                                && member.aid != sender_str
                            {
                                self.notify
                                    .notify(member.aid.clone(), sai.clone())
                                    .await;
                            }
                        }

                        Ok(None)
                    }
                    ExchangeArguments::ChannelInvite { ch, to, role } => {
                        let sender_str = sender_aid
                            .ok_or(MessageboxError::VerificationFailure)?
                            .to_string();
                        let member_role = role
                            .as_deref()
                            .map(parse_member_role)
                            .transpose()?
                            .unwrap_or(MemberRole::Member);
                        info!(channel = %ch, inviter = %sender_str, target = %to, "Channel invite");
                        self.channel
                            .invite(ch.clone(), sender_str, to.clone(), member_role)
                            .await?;
                        self.notify.notify(to, ch).await;
                        Ok(None)
                    }
                    ExchangeArguments::ChannelAccept { ch } => {
                        let sender_str = sender_aid
                            .ok_or(MessageboxError::VerificationFailure)?
                            .to_string();
                        info!(channel = %ch, accepter = %sender_str, "Channel accept");
                        self.channel.accept(ch, sender_str).await?;
                        Ok(None)
                    }
                    ExchangeArguments::ChannelReject { ch } => {
                        let sender_str = sender_aid
                            .ok_or(MessageboxError::VerificationFailure)?
                            .to_string();
                        info!(channel = %ch, rejecter = %sender_str, "Channel reject");
                        self.channel.reject(ch, sender_str).await?;
                        Ok(None)
                    }
                    ExchangeArguments::ChannelLeave { ch } => {
                        let sender_str = sender_aid
                            .ok_or(MessageboxError::VerificationFailure)?
                            .to_string();
                        info!(channel = %ch, leaver = %sender_str, "Channel leave");
                        self.channel.leave(ch, sender_str).await?;
                        Ok(None)
                    }
                    ExchangeArguments::ChannelRemove { ch, target } => {
                        let sender_str = sender_aid
                            .ok_or(MessageboxError::VerificationFailure)?
                            .to_string();
                        info!(channel = %ch, remover = %sender_str, target = %target, "Channel remove");
                        self.channel.remove(ch, sender_str, target).await?;
                        Ok(None)
                    }
                    ExchangeArguments::ChannelSetRole { ch, target, role } => {
                        let sender_str = sender_aid
                            .ok_or(MessageboxError::VerificationFailure)?
                            .to_string();
                        let member_role = parse_member_role(&role)?;
                        info!(channel = %ch, setter = %sender_str, target = %target, role = %role, "Channel set role");
                        self.channel
                            .set_role(ch, sender_str, target, member_role)
                            .await?;
                        Ok(None)
                    }
                    ExchangeArguments::ChannelUpdate {
                        ch,
                        description,
                        avatar,
                        background,
                    } => {
                        let sender_str = sender_aid
                            .ok_or(MessageboxError::VerificationFailure)?
                            .to_string();
                        info!(channel = %ch, updater = %sender_str, "Channel update");
                        self.channel
                            .update(ch, sender_str, description, avatar, background)
                            .await?;
                        Ok(None)
                    }
                    ExchangeArguments::ChannelSubscribe { ch } => {
                        // For public broadcasts, subscription is handled by EMQX natively.
                        // This is a no-op on the server side.
                        debug!(channel = %ch, "Channel subscribe (no-op, handled by MQTT broker)");
                        Ok(None)
                    }
                },
            }
        } else {
            warn!(
                message_len = message.len(),
                "Failed to parse message as MessageType"
            );
            Err(MessageboxError::UnknownMessage(message.into()))
        }
    }

    async fn handle_message(&mut self, msg: ValidateMessage) {
        match msg {
            ValidateMessage::Authenticate {
                message,
                sender_aid,
                sender,
            } => {
                debug!(
                    message_len = message.len(),
                    sender_aid = ?sender_aid,
                    "Validating and authenticating message"
                );
                let _ = sender.send(self.process(&message, sender_aid.as_deref()).await);
            }
            ValidateMessage::ProcessAndSave { message } => {
                debug!(message_len = message.len(), "Processing and saving message");
                match self.process(&message, None).await {
                    Ok(to_save) => {
                        if let Some(response) = to_save {
                            debug!(response_len = response.len(), "Saving async query response");
                            let digest: keri_sdk::SelfAddressingIdentifier =
                                HashFunction::from(HashFunctionCode::Blake3_256)
                                    .derive(message.as_bytes());
                            self.responses_handle.save(response, digest).await;
                        } else {
                            debug!("No async response to save");
                        };
                    }
                    Err(e) => {
                        warn!(error = %e, "Failed to process message");
                    }
                };
            }
        }
    }
}

async fn run_my_actor(mut actor: ValidateActor) {
    while let Some(msg) = actor.receiver.recv().await {
        actor.handle_message(msg).await
    }
}

#[derive(Clone)]
pub struct ValidateHandle {
    validate_sender: mpsc::Sender<ValidateMessage>,
}

impl ValidateHandle {
    pub fn new(
        storage_handle: StorageHandle,
        notify_handle: NotifyHandle,
        responses: ResponsesHandle,
        acl_handle: AclHandle,
        channel_handle: ChannelHandle,
    ) -> Self {
        let (sender, receiver) = mpsc::channel(8);
        let actor = ValidateActor::new(
            receiver,
            storage_handle,
            notify_handle,
            responses,
            acl_handle,
            channel_handle,
        );
        tokio::spawn(run_my_actor(actor));
        debug!("Validate actor initialized");

        Self {
            validate_sender: sender,
        }
    }

    pub async fn validate(
        &self,
        message: String,
        sender_aid: Option<String>,
    ) -> Result<Option<String>, MessageboxError> {
        let (send, recv) = oneshot::channel();
        let msg = ValidateMessage::Authenticate {
            message,
            sender_aid,
            sender: send,
        };

        // Ignore send errors. If this send fails, so does the
        // recv.await below. There's no reason to check for the
        // same failure twice.
        let _ = self.validate_sender.send(msg).await;
        match recv.await {
            Ok(res) => res,
            Err(_) => {
                warn!("Validate actor task has been killed");
                Err(MessageboxError::KilledSender)
            }
        }
    }

    pub async fn process_and_save(&self, message: String) {
        let msg = ValidateMessage::ProcessAndSave { message };

        // Ignore send errors. If this send fails, so does the
        // recv.await below. There's no reason to check for the
        // same failure twice.
        let _ = self.validate_sender.send(msg).await;
    }
}

fn parse_channel_type(s: &str) -> Result<ChannelType, MessageboxError> {
    match s {
        "direct" => Ok(ChannelType::Direct),
        "broadcast" => Ok(ChannelType::Broadcast),
        "broadcast_private" => Ok(ChannelType::BroadcastPrivate),
        "group" => Ok(ChannelType::Group),
        _ => Err(MessageboxError::Unparsable(format!(
            "Unknown channel type: {}",
            s
        ))),
    }
}

fn parse_member_role(s: &str) -> Result<MemberRole, MessageboxError> {
    match s {
        "admin" => Ok(MemberRole::Admin),
        "member" => Ok(MemberRole::Member),
        _ => Err(MessageboxError::Unparsable(format!(
            "Unknown member role: {}",
            s
        ))),
    }
}
