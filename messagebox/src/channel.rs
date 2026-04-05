use chrono::Utc;
use keri_sdk::keri_core::actor::prelude::{HashFunction, HashFunctionCode};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info};

use crate::{db::Db, MessageboxError};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChannelType {
    Direct,
    Broadcast,
    BroadcastPrivate,
    Group,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MemberRole {
    Creator,
    Admin,
    Member,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MemberStatus {
    Active,
    Invited,
    Left,
    Removed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelMember {
    pub aid: String,
    pub role: MemberRole,
    pub status: MemberStatus,
    pub joined_at: Option<String>,
    pub invited_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Channel {
    pub said: String,
    pub channel_type: ChannelType,
    pub creator: String,
    pub topic: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub avatar: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub background: Option<String>,
    pub members: Vec<ChannelMember>,
    pub created_at: String,
    pub updated_at: String,
}

impl Channel {
    fn is_active_member(&self, aid: &str) -> bool {
        self.members
            .iter()
            .any(|m| m.aid == aid && m.status == MemberStatus::Active)
    }

    fn is_creator(&self, aid: &str) -> bool {
        self.creator == aid
    }

    fn is_admin_or_creator(&self, aid: &str) -> bool {
        self.members.iter().any(|m| {
            m.aid == aid
                && m.status == MemberStatus::Active
                && (m.role == MemberRole::Creator || m.role == MemberRole::Admin)
        })
    }

    pub fn can_write(&self, aid: &str) -> bool {
        match self.channel_type {
            ChannelType::Broadcast | ChannelType::BroadcastPrivate => self.is_creator(aid),
            ChannelType::Direct | ChannelType::Group => self.is_active_member(aid),
        }
    }

    pub fn can_read(&self, aid: &str) -> bool {
        match self.channel_type {
            ChannelType::Broadcast => true, // public
            _ => self.is_active_member(aid),
        }
    }
}

fn compute_channel_said(
    channel_type: &ChannelType,
    creator: &str,
    members: &[String],
    topic: &Option<String>,
    created_at: &str,
) -> String {
    let creation_event = serde_json::json!({
        "type": channel_type,
        "creator": creator,
        "members": members,
        "topic": topic,
        "created_at": created_at,
    });
    let digest: HashFunction = HashFunctionCode::Blake3_256.into();
    digest
        .derive(creation_event.to_string().as_bytes())
        .to_string()
}

pub enum ChannelMsg {
    Create {
        creator_aid: String,
        channel_type: ChannelType,
        topic: Option<String>,
        description: Option<String>,
        avatar: Option<String>,
        background: Option<String>,
        initial_members: Vec<String>,
        sender: oneshot::Sender<Result<Channel, MessageboxError>>,
    },
    Get {
        channel_said: String,
        sender: oneshot::Sender<Option<Channel>>,
    },
    GetByTopic {
        owner_aid: String,
        topic: String,
        sender: oneshot::Sender<Option<Channel>>,
    },
    Invite {
        channel_said: String,
        inviter_aid: String,
        target_aid: String,
        role: MemberRole,
        sender: oneshot::Sender<Result<(), MessageboxError>>,
    },
    Accept {
        channel_said: String,
        accepter_aid: String,
        sender: oneshot::Sender<Result<(), MessageboxError>>,
    },
    Reject {
        channel_said: String,
        rejecter_aid: String,
        sender: oneshot::Sender<Result<(), MessageboxError>>,
    },
    Leave {
        channel_said: String,
        leaver_aid: String,
        sender: oneshot::Sender<Result<(), MessageboxError>>,
    },
    Remove {
        channel_said: String,
        remover_aid: String,
        target_aid: String,
        sender: oneshot::Sender<Result<(), MessageboxError>>,
    },
    SetRole {
        channel_said: String,
        setter_aid: String,
        target_aid: String,
        role: MemberRole,
        sender: oneshot::Sender<Result<(), MessageboxError>>,
    },
    Update {
        channel_said: String,
        updater_aid: String,
        description: Option<String>,
        avatar: Option<String>,
        background: Option<String>,
        sender: oneshot::Sender<Result<(), MessageboxError>>,
    },
    Delete {
        channel_said: String,
        deleter_aid: String,
        sender: oneshot::Sender<Result<(), MessageboxError>>,
    },
    ListForAid {
        aid: String,
        sender: oneshot::Sender<Vec<Channel>>,
    },
    GetPendingInvites {
        aid: String,
        sender: oneshot::Sender<Vec<(String, String)>>,
    },
    ListAll {
        sender: oneshot::Sender<Vec<Channel>>,
    },
}

struct ChannelActor {
    receiver: mpsc::Receiver<ChannelMsg>,
    db: Db,
}

impl ChannelActor {
    fn new(receiver: mpsc::Receiver<ChannelMsg>, db: Db) -> Self {
        Self { receiver, db }
    }

    fn load_channel(&self, said: &str) -> Option<Channel> {
        self.db
            .get_channel(said)
            .ok()
            .flatten()
            .and_then(|json| serde_json::from_str(&json).ok())
    }

    fn save_channel(&self, channel: &Channel) -> Result<(), MessageboxError> {
        let json = serde_json::to_string(channel)
            .map_err(|e| MessageboxError::Unparsable(e.to_string()))?;
        self.db
            .save_channel(&channel.said, &json)
            .map_err(|e| MessageboxError::Communication(e.to_string()))
    }

    async fn handle_message(&mut self, msg: ChannelMsg) {
        match msg {
            ChannelMsg::Create {
                creator_aid,
                channel_type,
                topic,
                description,
                avatar,
                background,
                initial_members,
                sender,
            } => {
                let _ = sender.send(self.handle_create(
                    creator_aid,
                    channel_type,
                    topic,
                    description,
                    avatar,
                    background,
                    initial_members,
                ));
            }
            ChannelMsg::Get {
                channel_said,
                sender,
            } => {
                let _ = sender.send(self.load_channel(&channel_said));
            }
            ChannelMsg::GetByTopic {
                owner_aid,
                topic,
                sender,
            } => {
                let result = self
                    .db
                    .get_broadcast_by_topic(&owner_aid, &topic)
                    .ok()
                    .flatten()
                    .and_then(|said| self.load_channel(&said));
                let _ = sender.send(result);
            }
            ChannelMsg::Invite {
                channel_said,
                inviter_aid,
                target_aid,
                role,
                sender,
            } => {
                let _ =
                    sender.send(self.handle_invite(&channel_said, &inviter_aid, &target_aid, role));
            }
            ChannelMsg::Accept {
                channel_said,
                accepter_aid,
                sender,
            } => {
                let _ = sender.send(self.handle_accept(&channel_said, &accepter_aid));
            }
            ChannelMsg::Reject {
                channel_said,
                rejecter_aid,
                sender,
            } => {
                let _ = sender.send(self.handle_reject(&channel_said, &rejecter_aid));
            }
            ChannelMsg::Leave {
                channel_said,
                leaver_aid,
                sender,
            } => {
                let _ = sender.send(self.handle_leave(&channel_said, &leaver_aid));
            }
            ChannelMsg::Remove {
                channel_said,
                remover_aid,
                target_aid,
                sender,
            } => {
                let _ = sender.send(self.handle_remove(&channel_said, &remover_aid, &target_aid));
            }
            ChannelMsg::SetRole {
                channel_said,
                setter_aid,
                target_aid,
                role,
                sender,
            } => {
                let _ =
                    sender.send(self.handle_set_role(&channel_said, &setter_aid, &target_aid, role));
            }
            ChannelMsg::Update {
                channel_said,
                updater_aid,
                description,
                avatar,
                background,
                sender,
            } => {
                let _ = sender.send(self.handle_update(
                    &channel_said,
                    &updater_aid,
                    description,
                    avatar,
                    background,
                ));
            }
            ChannelMsg::Delete {
                channel_said,
                deleter_aid,
                sender,
            } => {
                let _ = sender.send(self.handle_delete(&channel_said, &deleter_aid));
            }
            ChannelMsg::ListForAid { aid, sender } => {
                let channels = self
                    .db
                    .list_channels_for_aid(&aid)
                    .unwrap_or_default()
                    .into_iter()
                    .filter_map(|(_, json)| serde_json::from_str::<Channel>(&json).ok())
                    .filter(|ch| ch.is_active_member(&aid) || ch.creator == aid)
                    .collect();
                let _ = sender.send(channels);
            }
            ChannelMsg::GetPendingInvites { aid, sender } => {
                let invites = self.db.get_pending_invites(&aid).unwrap_or_default();
                let _ = sender.send(invites);
            }
            ChannelMsg::ListAll { sender } => {
                let channels = self
                    .db
                    .list_all_channels()
                    .unwrap_or_default()
                    .into_iter()
                    .filter_map(|(_, json)| serde_json::from_str::<Channel>(&json).ok())
                    .collect();
                let _ = sender.send(channels);
            }
        }
    }

    fn handle_create(
        &self,
        creator_aid: String,
        channel_type: ChannelType,
        topic: Option<String>,
        description: Option<String>,
        avatar: Option<String>,
        background: Option<String>,
        initial_members: Vec<String>,
    ) -> Result<Channel, MessageboxError> {
        let now = Utc::now().to_rfc3339();
        let said = compute_channel_said(
            &channel_type,
            &creator_aid,
            &initial_members,
            &topic,
            &now,
        );

        debug!(said = %said, creator = %creator_aid, channel_type = ?channel_type, "Creating channel");

        // Build members list
        let mut members = vec![ChannelMember {
            aid: creator_aid.clone(),
            role: MemberRole::Creator,
            status: MemberStatus::Active,
            joined_at: Some(now.clone()),
            invited_at: now.clone(),
        }];

        // For direct channels, the other member is automatically included
        // For groups/broadcast_private, initial members get invited
        let invites: Vec<(&str, String)> = match channel_type {
            ChannelType::Direct => {
                if initial_members.len() != 1 {
                    return Err(MessageboxError::Unparsable(
                        "Direct channel requires exactly 1 other member".into(),
                    ));
                }
                // Direct channel: other member is immediately active
                members.push(ChannelMember {
                    aid: initial_members[0].clone(),
                    role: MemberRole::Member,
                    status: MemberStatus::Active,
                    joined_at: Some(now.clone()),
                    invited_at: now.clone(),
                });
                vec![]
            }
            ChannelType::Broadcast => {
                // Broadcast: only creator, no initial members needed
                vec![]
            }
            ChannelType::BroadcastPrivate | ChannelType::Group => {
                // Members start as invited
                let mut invite_data = Vec::new();
                for member_aid in &initial_members {
                    members.push(ChannelMember {
                        aid: member_aid.clone(),
                        role: MemberRole::Member,
                        status: MemberStatus::Invited,
                        joined_at: None,
                        invited_at: now.clone(),
                    });
                    let invite_json = serde_json::json!({
                        "channel_said": said,
                        "inviter": creator_aid,
                        "role": "member",
                        "invited_at": now,
                    })
                    .to_string();
                    invite_data.push((member_aid.as_str(), invite_json));
                }
                invite_data
            }
        };

        let channel = Channel {
            said: said.clone(),
            channel_type: channel_type.clone(),
            creator: creator_aid.clone(),
            topic: topic.clone(),
            description,
            avatar,
            background,
            members,
            created_at: now.clone(),
            updated_at: now,
        };

        let metadata_json = serde_json::to_string(&channel)
            .map_err(|e| MessageboxError::Unparsable(e.to_string()))?;

        // Build broadcast index if applicable
        let broadcast_index = match channel_type {
            ChannelType::Broadcast | ChannelType::BroadcastPrivate => {
                topic.as_deref().map(|t| (creator_aid.as_str(), t))
            }
            _ => None,
        };

        // Build invite references for the atomic write
        let invite_refs: Vec<(&str, &str)> = invites
            .iter()
            .map(|(aid, json)| (*aid, json.as_str()))
            .collect();

        self.db
            .save_channel_with_invites(&said, &metadata_json, broadcast_index, &invite_refs)
            .map_err(|e| MessageboxError::Communication(e.to_string()))?;

        info!(said = %said, channel_type = ?channel.channel_type, "Channel created");
        Ok(channel)
    }

    fn handle_invite(
        &self,
        channel_said: &str,
        inviter_aid: &str,
        target_aid: &str,
        role: MemberRole,
    ) -> Result<(), MessageboxError> {
        let mut channel = self
            .load_channel(channel_said)
            .ok_or(MessageboxError::UnknownMessage("Channel not found".into()))?;

        // Only creator/admin can invite
        if !channel.is_admin_or_creator(inviter_aid) {
            return Err(MessageboxError::AclDenied(inviter_aid.to_string()));
        }

        // Check if already a member
        if channel.members.iter().any(|m| {
            m.aid == target_aid
                && (m.status == MemberStatus::Active || m.status == MemberStatus::Invited)
        }) {
            return Err(MessageboxError::Unparsable(
                "Already a member or invited".into(),
            ));
        }

        let now = Utc::now().to_rfc3339();

        // Remove any old left/removed entries for this AID
        channel.members.retain(|m| m.aid != target_aid);

        channel.members.push(ChannelMember {
            aid: target_aid.to_string(),
            role: role.clone(),
            status: MemberStatus::Invited,
            joined_at: None,
            invited_at: now.clone(),
        });
        channel.updated_at = now.clone();
        self.save_channel(&channel)?;

        // Save invite record
        let invite_json = serde_json::json!({
            "channel_said": channel_said,
            "inviter": inviter_aid,
            "role": role,
            "invited_at": now,
        })
        .to_string();
        self.db
            .save_invite(target_aid, channel_said, &invite_json)
            .map_err(|e| MessageboxError::Communication(e.to_string()))?;

        debug!(channel = %channel_said, target = %target_aid, "Member invited");
        Ok(())
    }

    fn handle_accept(
        &self,
        channel_said: &str,
        accepter_aid: &str,
    ) -> Result<(), MessageboxError> {
        let mut channel = self
            .load_channel(channel_said)
            .ok_or(MessageboxError::UnknownMessage("Channel not found".into()))?;

        let member = channel
            .members
            .iter_mut()
            .find(|m| m.aid == accepter_aid && m.status == MemberStatus::Invited)
            .ok_or(MessageboxError::Unparsable("No pending invite".into()))?;

        let now = Utc::now().to_rfc3339();
        member.status = MemberStatus::Active;
        member.joined_at = Some(now.clone());
        channel.updated_at = now;
        self.save_channel(&channel)?;

        // Remove invite record
        let _ = self.db.delete_invite(accepter_aid, channel_said);

        info!(channel = %channel_said, member = %accepter_aid, "Member accepted invite");
        Ok(())
    }

    fn handle_reject(
        &self,
        channel_said: &str,
        rejecter_aid: &str,
    ) -> Result<(), MessageboxError> {
        let mut channel = self
            .load_channel(channel_said)
            .ok_or(MessageboxError::UnknownMessage("Channel not found".into()))?;

        channel
            .members
            .retain(|m| !(m.aid == rejecter_aid && m.status == MemberStatus::Invited));
        channel.updated_at = Utc::now().to_rfc3339();
        self.save_channel(&channel)?;

        let _ = self.db.delete_invite(rejecter_aid, channel_said);

        debug!(channel = %channel_said, member = %rejecter_aid, "Member rejected invite");
        Ok(())
    }

    fn handle_leave(
        &self,
        channel_said: &str,
        leaver_aid: &str,
    ) -> Result<(), MessageboxError> {
        let mut channel = self
            .load_channel(channel_said)
            .ok_or(MessageboxError::UnknownMessage("Channel not found".into()))?;

        // Creator cannot leave
        if channel.is_creator(leaver_aid) {
            return Err(MessageboxError::Unparsable(
                "Creator cannot leave, delete the channel instead".into(),
            ));
        }

        if let Some(member) = channel.members.iter_mut().find(|m| m.aid == leaver_aid) {
            member.status = MemberStatus::Left;
            channel.updated_at = Utc::now().to_rfc3339();
            self.save_channel(&channel)?;
            info!(channel = %channel_said, member = %leaver_aid, "Member left channel");
        }

        Ok(())
    }

    fn handle_remove(
        &self,
        channel_said: &str,
        remover_aid: &str,
        target_aid: &str,
    ) -> Result<(), MessageboxError> {
        let mut channel = self
            .load_channel(channel_said)
            .ok_or(MessageboxError::UnknownMessage("Channel not found".into()))?;

        if !channel.is_admin_or_creator(remover_aid) {
            return Err(MessageboxError::AclDenied(remover_aid.to_string()));
        }

        // Cannot remove the creator
        if channel.is_creator(target_aid) {
            return Err(MessageboxError::Unparsable(
                "Cannot remove channel creator".into(),
            ));
        }

        if let Some(member) = channel.members.iter_mut().find(|m| m.aid == target_aid) {
            member.status = MemberStatus::Removed;
            channel.updated_at = Utc::now().to_rfc3339();
            self.save_channel(&channel)?;
            info!(channel = %channel_said, target = %target_aid, remover = %remover_aid, "Member removed");
        }

        Ok(())
    }

    fn handle_set_role(
        &self,
        channel_said: &str,
        setter_aid: &str,
        target_aid: &str,
        role: MemberRole,
    ) -> Result<(), MessageboxError> {
        let mut channel = self
            .load_channel(channel_said)
            .ok_or(MessageboxError::UnknownMessage("Channel not found".into()))?;

        // Only creator can set roles
        if !channel.is_creator(setter_aid) {
            return Err(MessageboxError::AclDenied(setter_aid.to_string()));
        }

        // Cannot change creator's own role
        if channel.is_creator(target_aid) {
            return Err(MessageboxError::Unparsable(
                "Cannot change creator's role".into(),
            ));
        }

        if let Some(member) = channel
            .members
            .iter_mut()
            .find(|m| m.aid == target_aid && m.status == MemberStatus::Active)
        {
            member.role = role.clone();
            channel.updated_at = Utc::now().to_rfc3339();
            self.save_channel(&channel)?;
            info!(channel = %channel_said, target = %target_aid, role = ?role, "Member role updated");
        }

        Ok(())
    }

    fn handle_update(
        &self,
        channel_said: &str,
        updater_aid: &str,
        description: Option<String>,
        avatar: Option<String>,
        background: Option<String>,
    ) -> Result<(), MessageboxError> {
        let mut channel = self
            .load_channel(channel_said)
            .ok_or(MessageboxError::UnknownMessage("Channel not found".into()))?;

        if !channel.is_creator(updater_aid) {
            return Err(MessageboxError::AclDenied(updater_aid.to_string()));
        }

        if let Some(d) = description {
            channel.description = if d.is_empty() { None } else { Some(d) };
        }
        if let Some(a) = avatar {
            channel.avatar = if a.is_empty() { None } else { Some(a) };
        }
        if let Some(b) = background {
            channel.background = if b.is_empty() { None } else { Some(b) };
        }

        channel.updated_at = Utc::now().to_rfc3339();
        self.save_channel(&channel)
    }

    fn handle_delete(
        &self,
        channel_said: &str,
        deleter_aid: &str,
    ) -> Result<(), MessageboxError> {
        let channel = self
            .load_channel(channel_said)
            .ok_or(MessageboxError::UnknownMessage("Channel not found".into()))?;

        if !channel.is_creator(deleter_aid) {
            return Err(MessageboxError::AclDenied(deleter_aid.to_string()));
        }

        // Remove broadcast index if applicable
        if let Some(topic) = &channel.topic {
            if matches!(
                channel.channel_type,
                ChannelType::Broadcast | ChannelType::BroadcastPrivate
            ) {
                let _ = self.db.delete_broadcast_index(&channel.creator, topic);
            }
        }

        self.db
            .delete_channel(channel_said)
            .map_err(|e| MessageboxError::Communication(e.to_string()))?;

        info!(said = %channel_said, "Channel deleted");
        Ok(())
    }
}

async fn run_channel_actor(mut actor: ChannelActor) {
    while let Some(msg) = actor.receiver.recv().await {
        actor.handle_message(msg).await;
    }
}

#[derive(Clone)]
pub struct ChannelHandle {
    sender: mpsc::Sender<ChannelMsg>,
}

impl ChannelHandle {
    pub fn new(db: Db) -> Self {
        let (sender, receiver) = mpsc::channel(32);
        let actor = ChannelActor::new(receiver, db);
        tokio::spawn(run_channel_actor(actor));
        debug!("Channel actor initialized");
        Self { sender }
    }

    pub async fn create(
        &self,
        creator_aid: String,
        channel_type: ChannelType,
        topic: Option<String>,
        description: Option<String>,
        avatar: Option<String>,
        background: Option<String>,
        initial_members: Vec<String>,
    ) -> Result<Channel, MessageboxError> {
        let (send, recv) = oneshot::channel();
        let _ = self
            .sender
            .send(ChannelMsg::Create {
                creator_aid,
                channel_type,
                topic,
                description,
                avatar,
                background,
                initial_members,
                sender: send,
            })
            .await;
        recv.await.map_err(|_| MessageboxError::KilledSender)?
    }

    pub async fn get(&self, channel_said: &str) -> Option<Channel> {
        let (send, recv) = oneshot::channel();
        let _ = self
            .sender
            .send(ChannelMsg::Get {
                channel_said: channel_said.to_string(),
                sender: send,
            })
            .await;
        recv.await.ok().flatten()
    }

    pub async fn get_by_topic(&self, owner_aid: &str, topic: &str) -> Option<Channel> {
        let (send, recv) = oneshot::channel();
        let _ = self
            .sender
            .send(ChannelMsg::GetByTopic {
                owner_aid: owner_aid.to_string(),
                topic: topic.to_string(),
                sender: send,
            })
            .await;
        recv.await.ok().flatten()
    }

    pub async fn invite(
        &self,
        channel_said: String,
        inviter_aid: String,
        target_aid: String,
        role: MemberRole,
    ) -> Result<(), MessageboxError> {
        let (send, recv) = oneshot::channel();
        let _ = self
            .sender
            .send(ChannelMsg::Invite {
                channel_said,
                inviter_aid,
                target_aid,
                role,
                sender: send,
            })
            .await;
        recv.await.map_err(|_| MessageboxError::KilledSender)?
    }

    pub async fn accept(
        &self,
        channel_said: String,
        accepter_aid: String,
    ) -> Result<(), MessageboxError> {
        let (send, recv) = oneshot::channel();
        let _ = self
            .sender
            .send(ChannelMsg::Accept {
                channel_said,
                accepter_aid,
                sender: send,
            })
            .await;
        recv.await.map_err(|_| MessageboxError::KilledSender)?
    }

    pub async fn reject(
        &self,
        channel_said: String,
        rejecter_aid: String,
    ) -> Result<(), MessageboxError> {
        let (send, recv) = oneshot::channel();
        let _ = self
            .sender
            .send(ChannelMsg::Reject {
                channel_said,
                rejecter_aid,
                sender: send,
            })
            .await;
        recv.await.map_err(|_| MessageboxError::KilledSender)?
    }

    pub async fn leave(
        &self,
        channel_said: String,
        leaver_aid: String,
    ) -> Result<(), MessageboxError> {
        let (send, recv) = oneshot::channel();
        let _ = self
            .sender
            .send(ChannelMsg::Leave {
                channel_said,
                leaver_aid,
                sender: send,
            })
            .await;
        recv.await.map_err(|_| MessageboxError::KilledSender)?
    }

    pub async fn remove(
        &self,
        channel_said: String,
        remover_aid: String,
        target_aid: String,
    ) -> Result<(), MessageboxError> {
        let (send, recv) = oneshot::channel();
        let _ = self
            .sender
            .send(ChannelMsg::Remove {
                channel_said,
                remover_aid,
                target_aid,
                sender: send,
            })
            .await;
        recv.await.map_err(|_| MessageboxError::KilledSender)?
    }

    pub async fn set_role(
        &self,
        channel_said: String,
        setter_aid: String,
        target_aid: String,
        role: MemberRole,
    ) -> Result<(), MessageboxError> {
        let (send, recv) = oneshot::channel();
        let _ = self
            .sender
            .send(ChannelMsg::SetRole {
                channel_said,
                setter_aid,
                target_aid,
                role,
                sender: send,
            })
            .await;
        recv.await.map_err(|_| MessageboxError::KilledSender)?
    }

    pub async fn update(
        &self,
        channel_said: String,
        updater_aid: String,
        description: Option<String>,
        avatar: Option<String>,
        background: Option<String>,
    ) -> Result<(), MessageboxError> {
        let (send, recv) = oneshot::channel();
        let _ = self
            .sender
            .send(ChannelMsg::Update {
                channel_said,
                updater_aid,
                description,
                avatar,
                background,
                sender: send,
            })
            .await;
        recv.await.map_err(|_| MessageboxError::KilledSender)?
    }

    pub async fn delete(
        &self,
        channel_said: String,
        deleter_aid: String,
    ) -> Result<(), MessageboxError> {
        let (send, recv) = oneshot::channel();
        let _ = self
            .sender
            .send(ChannelMsg::Delete {
                channel_said,
                deleter_aid,
                sender: send,
            })
            .await;
        recv.await.map_err(|_| MessageboxError::KilledSender)?
    }

    pub async fn list_for_aid(&self, aid: &str) -> Vec<Channel> {
        let (send, recv) = oneshot::channel();
        let _ = self
            .sender
            .send(ChannelMsg::ListForAid {
                aid: aid.to_string(),
                sender: send,
            })
            .await;
        recv.await.unwrap_or_default()
    }

    pub async fn get_pending_invites(&self, aid: &str) -> Vec<(String, String)> {
        let (send, recv) = oneshot::channel();
        let _ = self
            .sender
            .send(ChannelMsg::GetPendingInvites {
                aid: aid.to_string(),
                sender: send,
            })
            .await;
        recv.await.unwrap_or_default()
    }

    pub async fn list_all(&self) -> Vec<Channel> {
        let (send, recv) = oneshot::channel();
        let _ = self.sender.send(ChannelMsg::ListAll { sender: send }).await;
        recv.await.unwrap_or_default()
    }
}
