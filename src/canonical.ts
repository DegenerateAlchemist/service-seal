import { createHash } from 'node:crypto';

function canonicalize(value: unknown): unknown {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') {
    return value;
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw new Error('canonical JSON does not support non-finite numbers');
    }
    return value;
  }
  if (Array.isArray(value)) {
    return value.map(canonicalize);
  }
  if (typeof value !== 'object') {
    throw new Error('canonical JSON supports only JSON values');
  }

  const ordered: Record<string, unknown> = {};
  for (const key of Object.keys(value as Record<string, unknown>).sort()) {
    ordered[key] = canonicalize((value as Record<string, unknown>)[key]);
  }
  return ordered;
}

export function canonicalJson(value: unknown): string {
  return JSON.stringify(canonicalize(value));
}

export function sha256Hex(value: string | Buffer | Uint8Array): string {
  return createHash('sha256').update(value).digest('hex');
}
