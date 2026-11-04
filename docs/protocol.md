# ServiceSeal Protocol Note

ServiceSeal models a prepaid service session as a CKB Cell. A registered terminal is permitted to decrement session credit only by producing an authorized, numbered usage receipt.

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

The terminal signs canonical JSON with the following fields:
`version`, `terminalId`, `sessionId`, `sequence`, `usedUnits`, `issuedAt`.

State transitions reject any receipt that:
- Fails signature verification
- Mismatches the registered terminal ID or session ID
- Skips or replays sequence numbers
- Overdraws remaining credit units
- Contains unrecognised fields
