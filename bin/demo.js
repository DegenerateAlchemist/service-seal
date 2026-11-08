#!/usr/bin/env node
import { existsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const distIndex = resolve(__dirname, '../dist/index.js');
const demoTs = resolve(__dirname, './demo.ts');

if (!existsSync(distIndex)) {
  const res = spawnSync('npx', ['tsx', demoTs], { stdio: 'inherit' });
  process.exit(res.status ?? 0);
}

const {
  applyReceipt,
  applyReceiptBatch,
  cellCommitment,
  createSessionState,
  decodeCellData,
  encodeCellData,
  encodeSessionWitness,
  signReceipt
} = await import(distIndex);

const { generateKeyPairSync, randomBytes } = await import('node:crypto');

const { privateKey, publicKey } = generateKeyPairSync('ed25519');
const terminalId = randomBytes(32).toString('hex');
const sessionId = randomBytes(16).toString('hex');
const opened = createSessionState({ terminalId, sessionId, devicePublicKey: publicKey, creditUnits: 100 });

const receipt1 = signReceipt({
  version: 1,
  terminalId,
  sessionId,
  sequence: 1,
  usedUnits: 25,
  issuedAt: Math.floor(Date.now() / 1000)
}, privateKey);

const { state: state1, receiptId } = applyReceipt(opened, receipt1, publicKey);
const cellData = encodeCellData(state1);
const witness = encodeSessionWitness(receipt1, publicKey);

const receipt2 = signReceipt({
  version: 1,
  terminalId,
  sessionId,
  sequence: 2,
  usedUnits: 50,
  issuedAt: Math.floor(Date.now() / 1000) + 10
}, privateKey);

const batchResult = applyReceiptBatch(state1, [receipt2], publicKey);

console.log(JSON.stringify({
  acceptedReceipt: receiptId,
  nextState: decodeCellData(cellData),
  cellDataHex: cellData.toString('hex'),
  cellCommitment: cellCommitment(state1),
  witness: {
    version: witness.version,
    rawBytesLength: witness.witnessBytes.length
  },
  batchProgression: {
    finalCredit: batchResult.state.creditUnits,
    finalSequence: batchResult.state.lastSequence,
    totalBatchUsage: batchResult.totalUsedUnits
  }
}, null, 2));
