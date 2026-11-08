# ServiceSeal

ServiceSeal is an early reference implementation in TypeScript for a CKB-backed prepaid service session. A registered terminal signs each measured debit; the session state accepts only the next valid receipt and stores a compact, deterministic Cell-data representation.

It is intended for device-attested services where the event can be signed by a terminal: water dispensing, shared solar charging, battery charging, cold-storage time, or paid equipment use. It is not an escrow product, a payment gateway, or a claim that a blockchain can prove physical delivery.

## Current release (`v0.1.0`)

`v0.1.0` contains the protocol core:

- Ed25519 device receipt signing and verification
- Strict sequence and balance enforcement
- Fixed-size 100-byte Cell-data encoding (`SS01`)
- CKB Type Script witness packaging (`encodeSessionWitness`)
- Sequential batch transition support (`applyReceiptBatch`)
- 14 adversarial rejection and invariant tests
- Executable demonstration

## Quick Start

Requires Node.js 20 or later.

```sh
npm install
npm test
npm run demo
npm run build
```

## CKB Model

A service session is represented by one live Cell. To consume the Cell and produce its successor, a transaction must carry the machine receipt and public key in its witness and output a successor whose balance and sequence match that receipt:

```text
Session Cell (100 units, sequence 0)
        + signed device receipt: 25 units, sequence 1
        |
        v
Successor Cell (75 units, sequence 1)
```

## Trust Boundaries

The device remains the physical trust boundary. A compromised terminal key or manipulated sensor can still produce a valid signature over false usage. ServiceSeal ensures that digital state transitions are tamper-evident and auditable on CKB without depending on an operator's private database.

## License

MIT. Copyright 2026 Hardik Azmi.
