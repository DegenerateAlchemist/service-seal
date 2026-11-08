import type { KeyObject } from 'node:crypto';
import { canonicalJson } from './canonical.js';
import { receiptPayload } from './receipt.js';
import type { SessionWitness, SignedReceipt } from './types.js';

export function encodeSessionWitness(receipt: SignedReceipt, devicePublicKey: KeyObject): SessionWitness {
  // Verifies the payload portion and structure
  receiptPayload(receipt);
  if (!receipt.signature || typeof receipt.signature !== 'string') {
    throw new Error('signed receipt must include a valid signature');
  }

  const publicKeyDerHex = devicePublicKey.export({ type: 'spki', format: 'der' }).toString('hex');
  const payload = {
    version: 1,
    receipt,
    publicKeyDerHex
  };

  const witnessBytes = Buffer.from(canonicalJson(payload), 'utf-8');
  return {
    version: 1,
    receipt,
    publicKeyDerHex,
    witnessBytes
  };
}

export function decodeSessionWitness(raw: Buffer | Uint8Array): { version: number; receipt: SignedReceipt; publicKeyDerHex: string } {
  const jsonStr = Buffer.from(raw).toString('utf-8');
  const parsed = JSON.parse(jsonStr);

  if (!parsed || typeof parsed !== 'object' || parsed.version !== 1) {
    throw new Error('invalid or unsupported session witness format');
  }
  if (!parsed.receipt || typeof parsed.receipt !== 'object') {
    throw new Error('witness missing receipt');
  }
  receiptPayload(parsed.receipt);
  if (typeof parsed.publicKeyDerHex !== 'string' || !/^[0-9a-f]+$/i.test(parsed.publicKeyDerHex)) {
    throw new Error('witness missing valid public key DER hex');
  }

  return {
    version: parsed.version,
    receipt: parsed.receipt,
    publicKeyDerHex: parsed.publicKeyDerHex
  };
}
