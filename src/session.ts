import { createHash, type KeyObject } from 'node:crypto';
import { receiptId, verifyReceipt } from './receipt.js';
import type { CreateSessionParams, SessionState, SignedReceipt, TransitionResult } from './types.js';

export function publicKeyHash(publicKey: KeyObject): string {
  return createHash('sha256').update(publicKey.export({ type: 'spki', format: 'der' })).digest('hex');
}

function requireId(value: unknown, bytes: number, field: string): asserts value is string {
  if (typeof value !== 'string' || !new RegExp(`^[0-9a-f]{${bytes * 2}}$`, 'i').test(value)) {
    throw new Error(`${field} must be ${bytes} bytes of hexadecimal`);
  }
}

export function assertSessionState(state: unknown): asserts state is SessionState {
  if (!state || typeof state !== 'object' || Array.isArray(state)) {
    throw new Error('session state must be an object');
  }
  const s = state as Record<string, unknown>;
  requireId(s.terminalId, 32, 'terminalId');
  requireId(s.sessionId, 16, 'sessionId');
  requireId(s.deviceKeyHash, 32, 'deviceKeyHash');
  for (const field of ['creditUnits', 'lastSequence']) {
    const val = s[field];
    if (typeof val !== 'number' || !Number.isSafeInteger(val) || val < 0) {
      throw new Error(`${field} must be a non-negative safe integer`);
    }
  }
}

export function createSessionState({ terminalId, sessionId, devicePublicKey, creditUnits }: CreateSessionParams): SessionState {
  requireId(terminalId, 32, 'terminalId');
  requireId(sessionId, 16, 'sessionId');
  if (!Number.isSafeInteger(creditUnits) || creditUnits < 0) {
    throw new Error('creditUnits must be a non-negative safe integer');
  }

  return {
    terminalId: terminalId.toLowerCase(),
    sessionId: sessionId.toLowerCase(),
    deviceKeyHash: publicKeyHash(devicePublicKey),
    creditUnits,
    lastSequence: 0
  };
}

export function applyReceipt(state: SessionState, receipt: SignedReceipt, devicePublicKey: KeyObject): TransitionResult {
  assertSessionState(state);
  if (!verifyReceipt(receipt, devicePublicKey)) {
    throw new Error('invalid device signature');
  }
  if (publicKeyHash(devicePublicKey) !== state.deviceKeyHash) {
    throw new Error('unrecognized device key');
  }
  if (receipt.terminalId !== state.terminalId) {
    throw new Error('wrong terminal');
  }
  if (receipt.sessionId !== state.sessionId) {
    throw new Error('wrong session');
  }
  if (!Number.isSafeInteger(receipt.sequence) || receipt.sequence !== state.lastSequence + 1) {
    throw new Error('receipt sequence is not next');
  }
  if (receipt.usedUnits > state.creditUnits) {
    throw new Error('insufficient service credit');
  }

  return {
    state: {
      ...state,
      creditUnits: state.creditUnits - receipt.usedUnits,
      lastSequence: receipt.sequence
    },
    receiptId: receiptId(receipt)
  };
}
