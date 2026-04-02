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
- **Persistent storage** — messages stored in embedded redb database, survive restarts
- **Session management** — JWT-like session tokens with expiry and revocation
- **Mailbox lifecycle** — provision, activate, suspend, and delete mailboxes
- **Firebase push notifications** — notify clients of new messages
- **OOBI resolution** — discover and resolve identifier endpoints

## Getting Started

### Configuration

Copy the example config and edit:

```bash
cp messagebox.yml.example messagebox.yml
```

Configuration values (`messagebox.yml`):

| Key | Description |
|-----|-------------|
| `db_path` | Directory for KEL and message database storage |
| `oobi_path` | Directory for OOBI storage |
| `http_port` | HTTP listen port |
| `public_url` | Public URL for OOBI advertisement |
| `seed` | Ed25519 keypair seed (optional, auto-generated if omitted) |
| `server_key` | Firebase FCM server key |
| `watcher_oobi` | Watcher OOBI JSON for KEL updates |
| `dauthz_state_dir` | Directory for DauthZ state (enables authentication, optional) |

CLI arguments override YAML config values.

### Build & Run

```bash
cargo build --release
./target/release/messagebox -c messagebox.yml
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
| `GET /auth/challenge?purpose=registration\|identification` | Request DauthZ challenge |
| `POST /auth/respond` | Submit signed challenge response |
| `DELETE /auth/session` | Revoke session (requires `Authorization: Bearer <token>`) |

### Mailbox Endpoints

Requires authentication.

| Method | Path | Description |
|--------|------|-------------|
| `GET /mailbox` | Get mailbox metadata for authenticated AID |
| `DELETE /mailbox` | Delete mailbox for authenticated AID |

### Authentication Flow

1. Client requests challenge: `GET /auth/challenge?purpose=registration`
2. Server returns a `Challenge` JSON with nonce, service AID, expiry
3. Client signs the challenge with their KERI keys
4. Client submits: `POST /auth/respond` with `ChallengeResponse` (entity_aid, entity_oobi, nonce, signed_challenge)
5. On **registration**: server provisions a mailbox, returns account info
6. On **identification**: server issues a `SessionToken` (1hr expiry)
7. Use the token for authenticated endpoints: `Authorization: Bearer <token>`

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
           > MessageBox ──> VerifyHandle ──> ValidateHandle ──> StorageHandle (redb)
                                                             > NotifyHandle
                         > OobiHandle
                         > ResponsesHandle
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
