import { sign, verify, type KeyObject } from 'node:crypto';
import { canonicalJson, sha256Hex } from './canonical.js';
import type { ReceiptPayload, SignedReceipt } from './types.js';

const RECEIPT_FIELDS = ['issuedAt', 'sequence', 'sessionId', 'terminalId', 'usedUnits', 'version'];

function requireHex(value: unknown, bytes: number, field: string): asserts value is string {
  if (typeof value !== 'string' || !new RegExp(`^[0-9a-f]{${bytes * 2}}$`, 'i').test(value)) {
    throw new Error(`${field} must be ${bytes} bytes of hexadecimal`);
  }
}

export function assertReceiptPayload(payload: unknown): asserts payload is ReceiptPayload {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    throw new Error('receipt payload must be an object');
  }
  const obj = payload as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  if (keys.length !== RECEIPT_FIELDS.length || keys.some((key, index) => key !== RECEIPT_FIELDS[index])) {
    throw new Error('receipt payload has an unexpected field');
  }
  if (obj.version !== 1) {
    throw new Error('unsupported receipt version');
  }
  requireHex(obj.terminalId, 32, 'terminalId');
  requireHex(obj.sessionId, 16, 'sessionId');
  for (const field of ['sequence', 'usedUnits', 'issuedAt']) {
    const val = obj[field];
    if (typeof val !== 'number' || !Number.isSafeInteger(val) || val <= 0) {
      throw new Error(`${field} must be a positive safe integer`);
    }
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
