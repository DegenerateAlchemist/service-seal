import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import test from 'node:test';
import {
  applyReceipt,
  createSessionState,
  signReceipt
} from '../src/index.js';

function fixture() {
  const keys = generateKeyPairSync('ed25519');
  const terminalId = randomBytes(32).toString('hex');
  const sessionId = randomBytes(16).toString('hex');
  const state = createSessionState({ terminalId, sessionId, devicePublicKey: keys.publicKey, creditUnits: 80 });
  const receipt = (overrides = {}) => signReceipt({
    version: 1,
    terminalId,
    sessionId,
    sequence: 1,
    usedUnits: 20,
    issuedAt: 1_794_000_000,
    ...overrides
  }, keys.privateKey);
  return { ...keys, terminalId, sessionId, state, receipt };
}

test('accepts the next signed receipt and reduces credit', () => {
  const { state, publicKey, receipt } = fixture();
  const result = applyReceipt(state, receipt(), publicKey);
  assert.equal(result.state.creditUnits, 60);
  assert.equal(result.state.lastSequence, 1);
  assert.match(result.receiptId, /^[0-9a-f]{64}$/);
});

test('rejects a replayed receipt', () => {
  const { state, publicKey, receipt } = fixture();
  const once = applyReceipt(state, receipt(), publicKey).state;
  assert.throws(() => applyReceipt(once, receipt(), publicKey), /sequence/);
});

test('rejects a receipt signed by another device', () => {
  const { state, receipt } = fixture();
  const other = generateKeyPairSync('ed25519');
  assert.throws(() => applyReceipt(state, receipt(), other.publicKey), /signature/);
});

test('rejects overdrawn usage', () => {
  const { state, publicKey, receipt } = fixture();
  assert.throws(() => applyReceipt(state, receipt({ usedUnits: 81 }), publicKey), /insufficient/);
});
