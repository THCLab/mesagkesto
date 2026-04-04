# Messagebox

## Endpoints

- `POST /` - allows users to send `qry` or `exn` message,
- `POST /resolve` - allows providing oobi of identifier, to be able to verify its signature,
- `GET /messages/<said>` - enable checking the message processing status by senders.


Oobi specific endpoints:
- `GET /introduce` - returns messagebox contact information - identifier and address in form of oobi,
- `GET /<identifier>/oobi` - returns signed reply message with messagebox contact information. This information proofs that the messagebox identifier has control over its address,
- `GET /<endpoint_identifier>/messagebox/<controller_identifier>` - returns reply message from other `<controller_identifier>`, that proofs that `<endpoint_identifier>` is used as its messagebox.
- `POST /register` - gets messages from other identifiers, who designated entity as its messagebox.

### Formal Mail Federation

Server-to-server mail delivery between mesagkesto instances, enabling decentralized AID-based formal communication:

- `POST /mail/deliver` — receive a CESR-signed mail envelope from a remote mesagkesto. Verifies recipients exist locally, stores for delivery, returns a signed delivery receipt.
- `POST /mail/receipt` — receive a read receipt from a remote mesagkesto (signed by the reader's AID).
- `GET /mail/messages?from_seq={n}` — authenticated client polls for pending mail (Bearer token required).
- `DELETE /mail/messages/{seq}` — client acknowledges receipt of a mail message (removes from pending queue).

### Storage Vault

Content-addressed blob storage for mail attachments. Small files are delivered inline with the mail envelope; large files are uploaded to the sender's vault and referenced by SAID (SHA-256 content hash):

- `PUT /vault/{said}` — upload a blob (authenticated). The SAID in the URL must match the SHA-256 hash of the content.
- `GET /vault/{said}` — download a blob by SAID (publicly accessible — knowing the SAID is authorization).

## Possible messages
Messages incoming in posted data has type that specify the sender intention. Possible types are:
- `exn` - for saving or updating data in messagebox,
- `qry` - for retrieving data.

## Usage

Messagebox can be run with `cargo run -p messagebox -- -c messagebox.yml`.

File `/tests/test_messagebox.rs` shows example of setting up messagebox for keri identifier.
