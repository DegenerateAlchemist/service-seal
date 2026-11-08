import { generateKeyPairSync, randomBytes } from 'node:crypto';
import {
  applyReceipt,
  applyReceiptBatch,
  cellCommitment,
  createSessionState,
  decodeCellData,
  encodeCellData,
  encodeSessionWitness,
  signReceipt
} from '../src/index.js';

export function runDemo() {
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

  return {
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
  };
}

if (process.argv[1] && process.argv[1].endsWith('demo.ts')) {
  console.log(JSON.stringify(runDemo(), null, 2));
}
