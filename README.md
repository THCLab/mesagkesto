# Mesaĝkesto

Secure real-time messaging service built on KERI identifiers.

## Overview

Mesaĝkesto is a multi-tenant message box service where any KERI AID can
provision a mailbox, exchange messages with whitelisted contacts, and benefit
from end-to-end encryption. It verifies CESR-encoded messages using
cryptographic signatures against the sender's Key Event Log (KEL).

### Key Features

- **KERI-native identity** — AIDs (Autonomous Identifiers) are first-class citizens
- **DauthZ authentication** — challenge-response proof of AID ownership for mailbox provisioning
- **MQTT integration (EMQX)** — issues JWTs for MQTT broker authentication; acts as auth bridge between KERI and EMQX
- **Persistent storage** — messages stored in embedded redb database, survive restarts
- **Session management** — session tokens with expiry and revocation; MQTT JWTs issued alongside session tokens
- **Mailbox lifecycle** — provision, activate, suspend, and delete mailboxes
- **WebSocket real-time transport** — bidirectional messaging with presence and typing indicators (legacy, being replaced by MQTT)
- **Contact list (ACL)** — per-mailbox sender whitelist; enforced both on HTTP endpoints and via EMQX authorization hook
- **Firebase push notifications** — notify clients of new messages
- **OOBI resolution** — discover and resolve identifier endpoints

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
| `GET /auth/challenge?oobi=...&purpose=...` | Request signed DauthZ challenge bound to OOBI |
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

### MQTT Authorization Endpoint

| Method | Path | Description |
|--------|------|-------------|
| `POST /mqtt/authz` | EMQX HTTP authorization hook for sender-level ACL checks |

This endpoint is called by EMQX on each PUBLISH to `msg/inbox/{recipient_aid}`. It checks the sender's `clientid` (AID) against the recipient's ACL whitelist. If the ACL is empty, the inbox is open (anyone can send). If the ACL has entries, only listed AIDs are permitted.

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

1. Client requests challenge: `GET /auth/challenge?oobi=<OOBI_JSON>&purpose=registration`
2. Server parses the OOBI to extract the AID, resolves it (caches the client's KEL)
3. Server returns a CESR stream: challenge JSON payload + nontransferable receipt couples (service signature)
4. Client **parses the CESR stream** and verifies the attached signature against the `service_aid` to confirm the challenge is authentic
5. Client signs `{"nonce": "<nonce>"}` with their KERI keys (CESR envelope)
6. Client submits: `POST /auth/respond` with the CESR-signed nonce as raw body
7. Server verifies the CESR signature against the client's KEL (already resolved), looks up the bound AID
8. On **registration**: server provisions a mailbox, returns account info
9. On **identification**: server issues a `SessionToken` (1hr expiry)
10. Use the token for authenticated endpoints: `Authorization: Bearer <token>`

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
           > MailboxHandle (provisioning lifecycle)
           > AclHandle (whitelist token management)
           > MessageBox ──> VerifyHandle ──> ValidateHandle ──> StorageHandle (redb)
                                                             > NotifyHandle
                         > OobiHandle
                         > ResponsesHandle

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

## License

EUPL 1.2

We have distilled the most crucial license specifics to make your adoption seamless: [see here for details](https://github.com/THCLab/licensing).
