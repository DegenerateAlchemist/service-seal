import type { KeyObject } from 'node:crypto';

export interface SessionState {
  terminalId: string;
  sessionId: string;
  deviceKeyHash: string;
  creditUnits: number;
  lastSequence: number;
}

export interface ReceiptPayload {
  version: number;
  terminalId: string;
  sessionId: string;
  sequence: number;
  usedUnits: number;
  issuedAt: number;
}

export interface SignedReceipt extends ReceiptPayload {
  signature: string;
}

export interface TransitionResult {
  state: SessionState;
  receiptId: string;
}

export interface BatchTransitionResult {
  state: SessionState;
  receiptIds: string[];
  totalUsedUnits: number;
}

export interface CreateSessionParams {
  terminalId: string;
  sessionId: string;
  devicePublicKey: KeyObject;
  creditUnits: number;
}

export interface SessionWitness {
  version: number;
  receipt: SignedReceipt;
  publicKeyDerHex: string;
  witnessBytes: Buffer;
}
