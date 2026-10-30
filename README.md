# ServiceSeal

ServiceSeal is a TypeScript protocol reference for prepaid service sessions backed by device-signed consumption receipts.

## Overview

A customer opens a session with prepaid credit. When service is consumed, a registered device signs an incremental receipt that authorises the debit.

## Setup and Tests

```sh
npm install
npm test
npm run build
```

## Protocol Concept

- Device receipt signing via Ed25519
- Strict next-sequence enforcement
- Non-negative balance constraints
