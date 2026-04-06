use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{Modify, OpenApi};

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Mesaĝkesto API",
        version = "1.0.0",
        description = "Secure real-time messaging service built on KERI identifiers.\n\n## Authentication\n\nEndpoints under `/mailbox/*` and `DELETE /auth/session` require a session token\nobtained via the DauthZ challenge-response flow. Pass it as:\n\n```\nAuthorization: Bearer <session_token>\n```\n\n## Authentication Flow\n\n1. `GET /auth/challenge?purpose=registration` — get a challenge\n2. Sign the challenge with your KERI keys (CESR envelope)\n3. `POST /auth/respond` — submit signed challenge\n4. On **registration**: server provisions a mailbox, returns account info\n5. On **identification**: server issues a session token (1hr expiry)\n\n## CESR Messages\n\n`POST /` accepts CESR-encoded JSON with attached cryptographic signatures.\nThe sender's OOBI must be resolved first via `POST /resolve`.",
        license(name = "EUPL 1.2", url = "https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12")
    ),
    servers(
        (url = "http://localhost:8081", description = "Local development")
    ),
    tags(
        (name = "KERI", description = "KERI message processing, OOBI resolution, and endpoint discovery"),
        (name = "Authentication", description = "DauthZ challenge-response authentication and session management"),
        (name = "Mailbox", description = "Mailbox provisioning, metadata, and ACL management"),
        (name = "WebSocket", description = "Real-time messaging via WebSocket"),
        (name = "Channels", description = "Channel and broadcast messaging"),
        (name = "Mail", description = "Formal mail federation endpoints (server-to-server and client)"),
        (name = "Vault", description = "Content-addressed blob storage"),
        (name = "Admin", description = "Administrative endpoints — invite and whitelist management (admin AID only)"),
        (name = "MQTT", description = "MQTT authorization hooks (EMQX integration)")
    ),
    paths(
        // KERI
        crate::messagebox_listener::http_handlers::introduce,
        crate::messagebox_listener::http_handlers::get_eid_oobi,
        crate::messagebox_listener::http_handlers::get_cid_oobi,
        crate::messagebox_listener::http_handlers::process_message,
        crate::messagebox_listener::http_handlers::register,
        crate::messagebox_listener::http_handlers::resolve_oobi,
        crate::messagebox_listener::http_handlers::get_response,
        // Authentication
        crate::messagebox_listener::http_handlers::auth_challenge,
        crate::messagebox_listener::http_handlers::auth_respond,
        crate::messagebox_listener::http_handlers::auth_revoke,
        // Mailbox
        crate::messagebox_listener::http_handlers::get_mailbox,
        crate::messagebox_listener::http_handlers::delete_mailbox,
        crate::messagebox_listener::http_handlers::set_acl,
        crate::messagebox_listener::http_handlers::get_acl,
        // WebSocket
        crate::messagebox_listener::http_handlers::ws_upgrade,
        // Channels
        crate::messagebox_listener::http_handlers::list_channels,
        crate::messagebox_listener::http_handlers::pending_invites,
        crate::messagebox_listener::http_handlers::get_channel,
        crate::messagebox_listener::http_handlers::get_channel_messages,
        crate::messagebox_listener::http_handlers::list_broadcasts,
        crate::messagebox_listener::http_handlers::discover_broadcast,
        crate::messagebox_listener::http_handlers::get_broadcast_messages,
        // MQTT
        crate::messagebox_listener::http_handlers::mqtt_authz,
        // Mail
        crate::messagebox_listener::http_handlers::mail_deliver,
        crate::messagebox_listener::http_handlers::mail_receipt,
        crate::messagebox_listener::http_handlers::mail_get_messages,
        crate::messagebox_listener::http_handlers::mail_delete_message,
        // Vault
        crate::messagebox_listener::http_handlers::vault_put,
        crate::messagebox_listener::http_handlers::vault_get,
        // Admin
        crate::messagebox_listener::http_handlers::admin_create_invite,
        crate::messagebox_listener::http_handlers::admin_list_invites,
        crate::messagebox_listener::http_handlers::admin_revoke_invite,
        crate::messagebox_listener::http_handlers::admin_add_whitelist,
        crate::messagebox_listener::http_handlers::admin_list_whitelist,
        crate::messagebox_listener::http_handlers::admin_remove_whitelist,
    ),
    components(schemas(
        // Domain types
        crate::channel::Channel,
        crate::channel::ChannelType,
        crate::channel::MemberRole,
        crate::channel::MemberStatus,
        crate::channel::ChannelMember,
        crate::mailbox::MailboxState,
        crate::mailbox::MailboxMetadata,
        crate::session::Session,
        crate::registration::InviteToken,
        // Request types
        crate::messagebox_listener::http_handlers::AclPayload,
        crate::messagebox_listener::http_handlers::MqttAuthzRequest,
        crate::messagebox_listener::http_handlers::CreateInviteBody,
        crate::messagebox_listener::http_handlers::AddWhitelistBody,
        crate::messagebox_listener::http_handlers::AuthResponsePayload,
        // Response types
        crate::messagebox_listener::http_handlers::RegistrationResponse,
        crate::messagebox_listener::http_handlers::AuthenticatedResponse,
        crate::messagebox_listener::http_handlers::AuthErrorResponse,
        crate::messagebox_listener::http_handlers::AclTokensResponse,
        crate::messagebox_listener::http_handlers::MqttAuthzResult,
        crate::messagebox_listener::http_handlers::ChannelMessagesResponse,
        crate::messagebox_listener::http_handlers::PendingInviteItem,
        crate::messagebox_listener::http_handlers::MailDeliveryReceipt,
    )),
    modifiers(&SecurityAddon)
)]
pub struct ApiDoc;

struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "bearerAuth",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .description(Some(
                            "Session token from `POST /auth/respond` (identification flow)",
                        ))
                        .build(),
                ),
            );
        }
    }
}
