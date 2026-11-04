# ServiceSeal

ServiceSeal is a TypeScript protocol reference for a CKB-backed prepaid service session. A registered terminal signs each measured debit; the session state accepts only the next valid receipt and stores a compact, deterministic Cell-data representation.

## Features

- Ed25519 device receipt signing and verification
- Strict sequence and balance enforcement
- Fixed-size 100-byte Cell-data encoding (`SS01`)
- Rejection tests for replay, forged signatures, altered use, unexpected fields, mismatched terminal/session, skipped sequence and overdraw

## Run Tests and Build

```sh
npm test
npm run build
```

## Protocol Specifications

See [docs/protocol.md](docs/protocol.md) for the byte-level cell layout and receipt verification rules.
