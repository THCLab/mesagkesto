# Mesaĝkesto

Secure real-time messaging service built on KERI identifiers.

## Overview

Mesaĝkesto is a multi-tenant message box service where any KERI AID can
provision a mailbox, exchange messages with whitelisted contacts, and benefit
from end-to-end encryption. It verifies CESR-encoded messages using
cryptographic signatures against the sender's Key Event Log (KEL).

### Key Features

- **KERI-native identity** — AIDs (Autonomous Identifiers) are first-class citizens
- **Unified channel system** — four channel types: direct (1:1), broadcast (public 1:N), broadcast_private (1:N whitelisted), and group (N:N with creator/admin/member roles)
- **Public broadcast channels** — RSS/Twitter-style feeds where an AID publishes authentic (CESR-signed) messages that anyone can subscribe to and verify
- **DauthZ authentication** — challenge-response proof of AID ownership for mailbox provisioning
- **MQTT integration (EMQX)** — issues JWTs for MQTT broker authentication; per-channel authorization via HTTP hook; anonymous subscribe for public broadcasts
- **Persistent storage** — messages stored in embedded redb database, survive restarts
- **Session management** — session tokens with expiry and revocation; MQTT JWTs issued alongside session tokens
- **Mailbox lifecycle** — provision, activate, suspend, and delete mailboxes
- **WebSocket real-time transport** — bidirectional messaging with presence and typing indicators (legacy, being replaced by MQTT)
- **Contact list (ACL)** — per-mailbox sender whitelist; enforced both on HTTP endpoints and via EMQX authorization hook
- **Firebase push notifications** — notify clients of new messages and channel events
- **OOBI resolution** — discover and resolve identifier endpoints
- **Broadcast demo page** — standalone HTML/JS viewer for public channels (no server required)

## Getting Started

### Configuration

Copy the example config and edit:

```bash
cp messagebox.yml.example messagebox.yml
```

See [`messagebox.yml.example`](messagebox.yml.example) for a fully commented template.

| Key | Description | Required |
|-----|-------------|----------|
| `db_path` | Directory for KEL and message database storage (redb) | Yes |
| `oobi_path` | Directory for OOBI storage | Yes |
| `http_port` | HTTP listen port | Yes |
| `public_url` | Public URL for OOBI advertisement (must be reachable by peers) | Yes |
| `watcher_oobi` | Watcher OOBI JSON string for KEL updates | Yes |
| `server_key` | Firebase Cloud Messaging server key for push notifications | Yes |
| `seed` | Ed25519 keypair seed (CESR-encoded). Auto-generated if omitted | No |
| `dauthz_state_dir` | Directory for DauthZ state. Enables auth, mailbox, ACL, and WebSocket endpoints | No |
| `jwt_secret` | Shared secret for signing MQTT JWTs (HS256). Must match EMQX `AUTHENTICATION__1__SECRET` | No |
| `mqtt_url` | MQTT broker WebSocket URL returned to clients (e.g. `ws://host:8083/mqtt`) | No |
| `registration_mode` | `"public"` (default) or `"invite_only"`. Controls who can register a mailbox | No |
| `admin_aid` | AID granted admin privileges. Auto-provisioned at startup. Required for `/admin/*` endpoints | No |

**Modes of operation:**
- **With `dauthz_state_dir`** — Full messaging service: authentication, mailboxes, ACL, WebSocket, and KERI relay.
- **Without `dauthz_state_dir`** — KERI relay only: message processing, OOBI resolution, no auth or mailbox endpoints.

**MQTT mode** (requires `jwt_secret` + `mqtt_url`):
When both are set, `POST /auth/respond` returns additional fields in the authentication response: `mqtt_token` (a signed JWT for the MQTT broker) and `mqtt_url`. Clients use these to connect to EMQX directly for real-time messaging, bypassing HTTP for message exchange. The `jwt_secret` must match the EMQX JWT authentication secret.

CLI arguments (`-d`, `-u`, `-p`, `-s`, `-k`) override YAML config values.

### Build & Run

```bash
cargo build --release
./target/release/messagebox -c messagebox.yml
```

### Logging

Logging uses the `RUST_LOG` environment variable (via `tracing`). Default level is `info`.

```bash
# Default (info-level)
./target/release/messagebox -c messagebox.yml

# Debug — logs every HTTP request/response, WebSocket frame, CESR parsing,
# signature verification, storage operations, and actor messages
RUST_LOG=debug ./target/release/messagebox -c messagebox.yml

# Debug only for messagebox, info for dependencies
RUST_LOG=messagebox=debug ./target/release/messagebox -c messagebox.yml

# Trace — maximum verbosity (includes actix internals)
RUST_LOG=trace ./target/release/messagebox -c messagebox.yml
```

### Docker

```bash
docker build -t mesagkesto .
docker run -p 8080:8081 mesagkesto
```

## API

The full API specification is available in [`openapi.yaml`](openapi.yaml) (OpenAPI 3.1). It is auto-generated from source code annotations using [utoipa](https://github.com/juhaku/utoipa) and kept in sync via CI.

To regenerate after modifying endpoints:

```bash
cargo test -p messagebox --test test_openapi_export
```

This writes `openapi.yaml` at the repository root. The CI workflow (`.github/workflows/openapi.yml`) auto-commits changes on pushes to `main` and fails PRs if the spec is outdated.

### KERI Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST /` | Process a CESR-signed message |
| `POST /register` | Register OOBI reply events |
| `POST /resolve` | Resolve an OOBI |
| `GET /introduce` | Get this messagebox's own OOBI |
| `GET /oobi/{id}` | Get location scheme for an endpoint identifier |
| `GET /oobi/{cid}/{role}/{eid}` | Get end-role OOBI with location scheme |
| `GET /messages/{said}` | Retrieve async response by SAID |

### Authentication Endpoints

Enabled when `dauthz_state_dir` is configured.

| Method | Path | Description |
|--------|------|-------------|
| `GET /auth/challenge?oobi=...&purpose=...&invite_token=...` | Request signed DauthZ challenge bound to OOBI |
| `POST /auth/respond` | Submit CESR-signed nonce to complete authentication |
| `DELETE /auth/session` | Revoke session (requires `Authorization: Bearer <token>`) |

### Mailbox Endpoints

Requires authentication (`Authorization: Bearer <token>`).

| Method | Path | Description |
|--------|------|-------------|
| `GET /mailbox` | Get mailbox metadata for authenticated AID |
| `DELETE /mailbox` | Delete mailbox for authenticated AID |
| `PUT /mailbox/acl` | Set ACL whitelist tokens |
| `GET /mailbox/acl` | Get ACL whitelist tokens |

### Registration Modes

The server supports two registration modes, controlled by the `registration_mode` config field:

#### Public (default)

Anyone with a KERI AID can register a mailbox. No additional configuration required.

#### Invite-only

Registration is restricted. A user can register only if:

1. **Their AID is whitelisted** — an admin has added the AID to the server's whitelist via `POST /admin/whitelist`, OR
2. **They present a valid invite token** — a one-time token generated by the admin via `POST /admin/invites`, passed as the `invite_token` query parameter on `GET /auth/challenge?purpose=registration&invite_token=<token>`

Both mechanisms coexist: a registration attempt succeeds if either condition is met. Invite tokens are single-use — consumed upon successful registration. AID whitelist entries persist, allowing re-registration.

The check happens at challenge creation time (`GET /auth/challenge`). Unauthorized attempts receive a `403 Forbidden` response. Login (`purpose=identification`) is never gated.

**Setup:**

```yaml
registration_mode: "invite_only"
admin_aid: "DAID..."       # your admin AID
dauthz_state_dir: "./dauthz/"
```

When `admin_aid` is set, the server auto-provisions and activates a mailbox for that AID at startup. The admin then authenticates via the normal DauthZ challenge/response flow to obtain a session token for the admin endpoints.

### Admin Endpoints

Requires authentication as the `admin_aid` (`Authorization: Bearer <token>` where the session belongs to the admin AID).

| Method | Path | Description |
|--------|------|-------------|
| `POST /admin/invites` | Generate a new invite token. Optional body: `{"label": "for Alice"}` |
| `GET /admin/invites` | List all active invite tokens |
| `DELETE /admin/invites/{token}` | Revoke an invite token |
| `POST /admin/whitelist` | Add an AID to the registration whitelist. Body: `{"aid": "DAID..."}` |
| `GET /admin/whitelist` | List all whitelisted AIDs |
| `DELETE /admin/whitelist/{aid}` | Remove an AID from the whitelist |

### Channel Endpoints

#### Authenticated (requires `Authorization: Bearer <token>`)

| Method | Path | Description |
|--------|------|-------------|
| `GET /channels` | List all channels the authenticated AID is a member of |
| `GET /channels/pending` | List pending channel invites |
| `GET /channels/{said}` | Get channel metadata and members (must be a member) |
| `GET /channels/{said}/messages?s=N` | Get channel messages from sequence number N (must be a member) |

#### Public (no authentication required)

| Method | Path | Description |
|--------|------|-------------|
| `GET /broadcasts` | List all public broadcast channels on this instance |
| `GET /broadcast/{aid}/{topic}` | Discover a broadcast channel by owner AID and topic name |
| `GET /broadcast/{aid}/{topic}/messages?s=N` | Get public broadcast messages from sequence number N |

#### Channel Operations via CESR

All channel mutations are submitted as CESR-signed exchange messages through `POST /`. The sender's AID is extracted from the signature.

| Route (`r` field) | Fields | Description |
|--------------------|--------|-------------|
| `/ch/create` | `channel_type`, `topic?`, `members[]` | Create a channel. Types: `direct`, `broadcast`, `broadcast_private`, `group` |
| `/ch/msg` | `ch`, `a` | Send a message to a channel |
| `/ch/invite` | `ch`, `to`, `role?` | Invite an AID to a channel (creator/admin only) |
| `/ch/accept` | `ch` | Accept a channel invite |
| `/ch/reject` | `ch` | Reject a channel invite |
| `/ch/leave` | `ch` | Leave a channel (creator cannot leave) |
| `/ch/remove` | `ch`, `target` | Remove a member (creator/admin only) |
| `/ch/role` | `ch`, `target`, `role` | Set a member's role: `admin` or `member` (creator only) |
| `/ch/sub` | `ch` | Subscribe to a public broadcast (no-op server-side, MQTT handles it) |

#### Channel Types

| Type | Writers | Readers | Encrypted | MQTT topic |
|------|---------|---------|-----------|------------|
| `direct` | Both members | Both members | Yes (client-side) | `ch/{said}/msg` |
| `broadcast` | Creator only | Anyone | No (public, signed) | `ch/{said}/msg` (anonymous subscribe) |
| `broadcast_private` | Creator only | Whitelisted AIDs | Yes (client-side) | `ch/{said}/msg` |
| `group` | All members | All members | Yes (client-side) | `ch/{said}/msg` |

#### Membership Roles

- **Creator** — full control: delete channel, assign admins, invite/remove members
- **Admin** — invite/remove members, moderate (designated by creator)
- **Member** — read + write (group/direct) or read-only (broadcasts)

Channel IDs are SAIDs (Self-Addressing Identifiers) — Blake3-256 hashes of the channel creation event, making them globally unique and content-addressable.

### Formal Mail Federation Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST /mail/deliver` | Receive a CESR-signed mail envelope from a remote mesagkesto (server-to-server) |
| `POST /mail/receipt` | Receive a read receipt from a remote mesagkesto (server-to-server) |
| `GET /mail/messages?from_seq=N` | Client polls for pending mail (authenticated) |
| `DELETE /mail/messages/{seq}` | Acknowledge receipt of a mail message (authenticated) |

### Storage Vault Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `PUT /vault/{said}` | Upload a content-addressed blob — SAID must match SHA-256 hash (authenticated) |
| `GET /vault/{said}` | Download a blob by SAID (publicly accessible, content-addressed) |

### MQTT Authorization Endpoint

| Method | Path | Description |
|--------|------|-------------|
| `POST /mqtt/authz` | EMQX HTTP authorization hook for sender-level ACL checks |

This endpoint is called by EMQX on each PUBLISH/SUBSCRIBE to authorize access. It handles three topic patterns:

- **`msg/inbox/{recipient_aid}`** (legacy) — checks sender ACL whitelist. Empty ACL = open inbox.
- **`ch/{channel_said}/msg`** and **`ch/{channel_said}/meta`** — per-channel authorization:
  - PUBLISH: broadcast channels allow only the creator; direct/group channels allow any active member
  - SUBSCRIBE: public broadcasts allow anonymous subscribe; all other types require active membership
- **`sys/inbox/{aid}`** — personal notification topic. Only the matching AID can subscribe; external publish is denied.

Configure in EMQX as an HTTP authorization backend:

```
authorization.sources.2 {
  type = http
  method = post
  url = "http://mesagkesto:3236/mqtt/authz"
  body {
    clientid = "${clientid}"
    topic = "${topic}"
    action = "${action}"
  }
}
```

### WebSocket

| Method | Path | Description |
|--------|------|-------------|
| `GET /ws?token=<session_token>` | Upgrade to WebSocket connection |

### Authentication Flow

1. Client requests challenge: `GET /auth/challenge?oobi=<OOBI_JSON>&purpose=registration[&invite_token=<token>]`
2. If `purpose=registration` and server is in `invite_only` mode: server checks that the AID is whitelisted or a valid invite token is provided (403 if neither)
3. Server parses the OOBI to extract the AID, resolves it (caches the client's KEL)
4. Server returns a CESR stream: challenge JSON payload + nontransferable receipt couples (service signature)
5. Client **parses the CESR stream** and verifies the attached signature against the `service_aid` to confirm the challenge is authentic
6. Client signs `{"nonce": "<nonce>"}` with their KERI keys (CESR envelope)
7. Client submits: `POST /auth/respond` with the CESR-signed nonce as raw body
8. Server verifies the CESR signature against the client's KEL (already resolved), looks up the bound AID
9. On **registration**: server provisions a mailbox (and consumes the invite token if one was used), returns account info
10. On **identification**: server issues a `SessionToken` (1hr expiry)
11. Use the token for authenticated endpoints: `Authorization: Bearer <token>`

### Session Lifecycle

Sessions are issued on successful identification (login) and stored in the embedded redb database.

- **Token format**: UUID v4 (session token) + HS256 JWT (MQTT token, when `jwt_secret` is configured)
- **Expiry**: 1 hour from issuance (both session and MQTT tokens share the same expiry)
- **Validation**: session tokens checked on every authenticated HTTP request; expired sessions are automatically cleaned up
- **MQTT JWT claims**: `sub` = AID (used as MQTT `client_id`), `exp` = expiry timestamp, `iat` = issued-at
- **Revocation**: `DELETE /auth/session` with the session token in the `Authorization` header
- **Multi-device**: multiple sessions can be active for the same AID simultaneously

### Contact List (ACL)

The ACL system uses **HMAC-based blind authorization** so the server enforces write permissions without being able to inspect the contact list.

**How it works:**

1. Mailbox owner derives a secret key: `K_whitelist = HKDF(identity_secret, "mesagkesto-whitelist-v1")`
2. For each allowed contact, owner computes: `token = HMAC-SHA256(K_whitelist, contact_AID)`
3. Owner uploads the token set: `PUT /mailbox/acl` with `{"tokens": ["<hex>", ...]}`
4. The server stores these opaque 32-byte tokens per mailbox

**Write authorization:**

- When adding a contact, the recipient computes the token for the sender and shares it out-of-band (e.g., during OOBI exchange)
- The sender includes this `auth_token` in the message envelope
- The server checks `acl_tokens.contains(auth_token)` — accepts or rejects with 403
- The server never learns which AID maps to which token (HMAC is one-way without `K_whitelist`)

### WebSocket Protocol

Connect via `GET /ws?token=<session_token>`. The connection supports these JSON frame types:

| Type | Direction | Description |
|------|-----------|-------------|
| `msg` | Client → Server | Relay message to `to` AID. Server responds with `ack`. |
| `ack` | Server → Client | Confirms message was relayed. `delivered: true` if recipient is online. |
| `typing` | Client → Server | Typing indicator. Fields: `to`, `state` (`started`/`stopped`). Ephemeral, never stored. |
| `presence_query` | Client → Server | Query presence for a list of AIDs. Fields: `aids`. |
| `presence_result` | Server → Client | Response with presence states per AID. |
| `presence_config` | Client → Server | Set visibility. Fields: `hidden_from` (list of HMAC tokens to hide presence from). |
| `presence` | Server → Client | Push notification when a contact's presence changes. |

Heartbeat: server pings every 30s, disconnects after 60s without a pong.

## Tests

Run the default test suite (network tests skipped):

```bash
cargo test
```

Run network-dependent tests (requires reachable witness/messagebox endpoints):

```bash
RUN_NETWORK_TESTS=1 cargo test
```

## Architecture

The service uses an **actor model** with tokio `mpsc`/`oneshot` channels. Each subsystem follows the `Handle`/`Actor` pattern:

```
HTTP ──────> AuthHandle (DauthZ challenge-response)
           > RegistrationHandle (public/invite-only gating, admin invite/whitelist)
           > MailboxHandle (provisioning lifecycle)
           > AclHandle (whitelist token management)
           > ChannelHandle (channel CRUD, membership, permissions)
           > MessageBox ──> VerifyHandle ──> ValidateHandle ──> StorageHandle (redb)
                                                             > NotifyHandle
                                                             > ChannelHandle
                         > OobiHandle
                         > ResponsesHandle

MQTT ──────> EMQX broker ──> mqtt_authz hook (per-channel authorization)

WebSocket ─> ConnectionManager ──> WsSession(s)
                                 > Presence tracking
                                 > Typing relay
                                 > Message relay to online recipients
```

### Key Concepts

- **EID** — Endpoint Identifier: ID of the entity controlling an endpoint
- **CID** — Controlling Identifier: ID of the entity that assigned a role to an EID
- Messages are CESR-encoded JSON with attached cryptographic signatures
- Verification requires the sender's OOBI to be resolved first (to fetch their KEL)
- If KEL state is stale during verification, the message is queued for re-verification after updating from the watcher

## Broadcast Demo Page

A standalone HTML page for viewing public broadcast channels is included at `demo/broadcast.html`. No build step or server required — open it directly in a browser or host on any static file server.

**Features:**
- Discovers channels via `GET /broadcast/{aid}/{topic}`
- Fetches message history via HTTP
- Real-time updates via MQTT WebSocket (connects to EMQX anonymously)
- Falls back to HTTP polling (30s) if MQTT is unavailable
- Stores message history in IndexedDB for offline access

**Usage:**

Open directly and fill in the form, or pass URL parameters:

```
broadcast.html?url=http://localhost:3236&aid=EBilc4-...&topic=announcements&mqtt=ws://localhost:8083/mqtt
```

## License

EUPL 1.2

We have distilled the most crucial license specifics to make your adoption seamless: [see here for details](https://github.com/THCLab/licensing).
