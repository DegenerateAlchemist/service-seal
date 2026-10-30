import { createHash, type KeyObject } from 'node:crypto';
import { receiptId, verifyReceipt } from './receipt.js';
import type { CreateSessionParams, SessionState, SignedReceipt, TransitionResult } from './types.js';

export function publicKeyHash(publicKey: KeyObject): string {
  return createHash('sha256').update(publicKey.export({ type: 'spki', format: 'der' })).digest('hex');
}

export function createSessionState({ terminalId, sessionId, devicePublicKey, creditUnits }: CreateSessionParams): SessionState {
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
  if (!verifyReceipt(receipt, devicePublicKey)) {
    throw new Error('invalid device signature');
  }
  if (publicKeyHash(devicePublicKey) !== state.deviceKeyHash) {
    throw new Error('unrecognized device key');
  }
  if (receipt.sequence !== state.lastSequence + 1) {
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
