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

## Possible messages
Messages incoming in posted data has type that specify the sender intention. Possible types are:
- `exn` - for saving or updating data in messagebox,
- `qry` - for retrieving data.

## Usage

Messagebox can be run with `cargo run -p messagebox -- -c messagebox.yml`.

File `/tests/test_messagebox.rs` shows example of setting up messagebox for keri identifier.
