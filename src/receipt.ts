import { sign, verify, type KeyObject } from 'node:crypto';
import { canonicalJson, sha256Hex } from './canonical.js';
import type { ReceiptPayload, SignedReceipt } from './types.js';

export function assertReceiptPayload(payload: unknown): asserts payload is ReceiptPayload {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    throw new Error('receipt payload must be an object');
  }
  const p = payload as Record<string, unknown>;
  if (typeof p.terminalId !== 'string' || typeof p.sessionId !== 'string') {
    throw new Error('receipt payload missing identifiers');
  }
  if (typeof p.sequence !== 'number' || typeof p.usedUnits !== 'number') {
    throw new Error('receipt sequence and usedUnits must be numbers');
  }
}

export function receiptPayload(receipt: SignedReceipt): Buffer {
  const { signature, ...payload } = receipt;
  assertReceiptPayload(payload);
  return Buffer.from(canonicalJson(payload));
}

export function signReceipt(payload: ReceiptPayload, privateKey: KeyObject | string): SignedReceipt {
  assertReceiptPayload(payload);
  const signature = sign(null, Buffer.from(canonicalJson(payload)), privateKey).toString('base64');
  return { ...payload, signature };
}

export function verifyReceipt(receipt: SignedReceipt, publicKey: KeyObject | string): boolean {
  try {
    if (!receipt || typeof receipt.signature !== 'string') return false;
    return verify(null, receiptPayload(receipt), publicKey, Buffer.from(receipt.signature, 'base64'));
  } catch {
    return false;
  }
}

export function receiptId(receipt: SignedReceipt): string {
  return sha256Hex(receiptPayload(receipt));
}
