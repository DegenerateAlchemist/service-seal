import { sha256Hex } from './canonical.js';
import type { SessionState } from './types.js';

const MAGIC = Buffer.from('SS01');
const CELL_DATA_BYTES = 4 + 32 + 16 + 32 + 8 + 8;

function requireHex(value: string, bytes: number, field: string): void {
  if (typeof value !== 'string' || !new RegExp(`^[0-9a-f]{${bytes * 2}}$`, 'i').test(value)) {
    throw new Error(`${field} must be ${bytes} bytes of hexadecimal`);
  }
}

function writeU64(buffer: Buffer, offset: number, value: number, field: string): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`${field} must be a non-negative safe integer`);
  }
  buffer.writeBigUInt64LE(BigInt(value), offset);
}

export function encodeCellData(state: SessionState): Buffer {
  requireHex(state.terminalId, 32, 'terminalId');
  requireHex(state.sessionId, 16, 'sessionId');
  requireHex(state.deviceKeyHash, 32, 'deviceKeyHash');

  const output = Buffer.alloc(CELL_DATA_BYTES);
  MAGIC.copy(output, 0);
  Buffer.from(state.terminalId, 'hex').copy(output, 4);
  Buffer.from(state.sessionId, 'hex').copy(output, 36);
  Buffer.from(state.deviceKeyHash, 'hex').copy(output, 52);
  writeU64(output, 84, state.creditUnits, 'creditUnits');
  writeU64(output, 92, state.lastSequence, 'lastSequence');
  return output;
}

export function decodeCellData(input: Buffer | Uint8Array): SessionState {
  const data = Buffer.from(input);
  if (data.length !== CELL_DATA_BYTES) {
    throw new Error(`cell data must be ${CELL_DATA_BYTES} bytes`);
  }
  if (!data.subarray(0, 4).equals(MAGIC)) {
    throw new Error('unknown service cell data format');
  }

  const creditUnits = Number(data.readBigUInt64LE(84));
  const lastSequence = Number(data.readBigUInt64LE(92));
  if (!Number.isSafeInteger(creditUnits) || !Number.isSafeInteger(lastSequence)) {
    throw new Error('cell integer exceeds JavaScript safe range');
  }

  return {
    terminalId: data.subarray(4, 36).toString('hex'),
    sessionId: data.subarray(36, 52).toString('hex'),
    deviceKeyHash: data.subarray(52, 84).toString('hex'),
    creditUnits,
    lastSequence
  };
}

export function cellCommitment(state: SessionState): string {
  return sha256Hex(encodeCellData(state));
}
