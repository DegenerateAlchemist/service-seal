import { sha256Hex } from './canonical.js';
import type { SessionState } from './types.js';

export function encodeCellData(state: SessionState): Buffer {
  const payload = JSON.stringify({
    terminalId: state.terminalId,
    sessionId: state.sessionId,
    deviceKeyHash: state.deviceKeyHash,
    creditUnits: state.creditUnits,
    lastSequence: state.lastSequence
  });
  return Buffer.from(payload, 'utf-8');
}

export function decodeCellData(input: Buffer | Uint8Array): SessionState {
  const parsed = JSON.parse(Buffer.from(input).toString('utf-8'));
  return {
    terminalId: parsed.terminalId,
    sessionId: parsed.sessionId,
    deviceKeyHash: parsed.deviceKeyHash,
    creditUnits: Number(parsed.creditUnits),
    lastSequence: Number(parsed.lastSequence)
  };
}

export function cellCommitment(state: SessionState): string {
  return sha256Hex(encodeCellData(state));
}
