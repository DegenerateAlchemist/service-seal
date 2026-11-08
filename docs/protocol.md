# ServiceSeal Protocol Note

ServiceSeal models a prepaid service session as a CKB Cell. A registered terminal is permitted to decrement session credit only by producing an authorized, numbered usage receipt.

## Actors

- **Customer** owns the session Cell and funds service credit.
- **Operator** provisions a terminal and its public key.
- **Terminal** holds the private device key and signs consumption receipts.
- **Verifier** validates a state transition without trusting the operator's database.

## State Layout

The Cell data format is a fixed 100-byte structure:

| Offset | Length | Field | Description |
| --- | ---: | --- | --- |
| 0 | 4 | `SS01` | Protocol magic marker |
| 4 | 32 | terminal ID | Hex-encoded terminal identifier |
| 36 | 16 | session ID | Unique customer session identifier |
| 52 | 32 | device key hash | SHA-256 of the terminal public key |
| 84 | 8 | credit units | Remaining credits, u64 little-endian |
| 92 | 8 | last sequence | Last accepted sequence, u64 little-endian |

## Receipt Verification

The terminal signs canonical JSON containing:
`version`, `terminalId`, `sessionId`, `sequence`, `usedUnits`, `issuedAt`.
The signature is Ed25519 encoded in base64.

State transitions reject any receipt that:
- Fails signature verification
- Mismatches the registered terminal ID or session ID
- Skips or replays sequence numbers
- Overdraws remaining credit units
- Contains unrecognised fields

## CKB Witness Packaging

The consumption transaction provides a witness containing:
1. `version`: witness schema version (1)
2. `receipt`: the full signed receipt JSON
3. `publicKeyDerHex`: DER-encoded terminal public key

The on-chain Type Script checks that the public key hashes to the Cell's `deviceKeyHash`, validates the signature against the receipt payload, and confirms that the successor Cell increments `lastSequence` by 1 and reduces `creditUnits` by `usedUnits`.

## Batch Transitions

Consecutive sequential receipts can be verified in a single batch transition (`applyReceiptBatch`), guaranteeing atomic validation across an unbroken sequence of debits.
