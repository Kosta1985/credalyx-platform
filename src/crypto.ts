import {
  createHash,
  createHmac,
  createPublicKey,
  randomBytes,
  timingSafeEqual,
  verify,
} from 'node:crypto';

export function uuidv7(nowMs = Date.now()): string {
  if (!Number.isSafeInteger(nowMs) || nowMs < 0 || nowMs > 0xffffffffffff) {
    throw new Error('timestamp is outside UUIDv7 range');
  }
  const bytes = randomBytes(16);
  const ms = BigInt(nowMs);
  bytes[0] = Number((ms >> 40n) & 0xffn);
  bytes[1] = Number((ms >> 32n) & 0xffn);
  bytes[2] = Number((ms >> 24n) & 0xffn);
  bytes[3] = Number((ms >> 16n) & 0xffn);
  bytes[4] = Number((ms >> 8n) & 0xffn);
  bytes[5] = Number(ms & 0xffn);
  bytes[6] = (bytes[6]! & 0x0f) | 0x70;
  bytes[8] = (bytes[8]! & 0x3f) | 0x80;
  const hex = bytes.toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

export function canonicalize(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  if (value && typeof value === 'object') {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${canonicalize(record[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

export function assertEd25519PublicKey(publicKeyPem: string): void {
  const key = createPublicKey(publicKeyPem);
  if (key.asymmetricKeyType !== 'ed25519') throw new Error('agent public key must be Ed25519');
}

export function agentKeyId(publicKeyPem: string): string {
  const key = createPublicKey(publicKeyPem);
  if (key.asymmetricKeyType !== 'ed25519') throw new Error('agent public key must be Ed25519');
  const der = key.export({ format: 'der', type: 'spki' });
  const fingerprint = createHash('sha256').update(der).digest('base64url');
  return `key_ed25519_${fingerprint}`;
}

export function createChallenge(): string {
  return randomBytes(32).toString('base64url');
}

export function challengeDigest(challenge: string): string {
  return createHash('sha256').update(challenge).digest('hex');
}

export function agentControlMessage(agentPublicId: string, challenge: string, keyId?: string): string {
  const keyLine = keyId ? `\nkey_id=${keyId}` : '';
  return `CREDALYX_AGENT_CONTROL_V1\nagent_id=${agentPublicId}${keyLine}\nchallenge=${challenge}`;
}

export function keyRotationMessage(input: {
  agentPublicId: string;
  rotationId: string;
  oldKeyId: string;
  newKeyId: string;
  challenge: string;
}): string {
  return [
    'CREDALYX_AGENT_KEY_ROTATION_V1',
    `agent_id=${input.agentPublicId}`,
    `rotation_id=${input.rotationId}`,
    `old_key_id=${input.oldKeyId}`,
    `new_key_id=${input.newKeyId}`,
    `challenge=${input.challenge}`,
  ].join('\n');
}

export function verifyEd25519Signature(publicKeyPem: string, message: string, signatureBase64Url: string): boolean {
  try {
    assertEd25519PublicKey(publicKeyPem);
    return verify(null, Buffer.from(message, 'utf8'), publicKeyPem, Buffer.from(signatureBase64Url, 'base64url'));
  } catch {
    return false;
  }
}

export function verifyAgentControlSignature(
  publicKeyPem: string,
  agentPublicId: string,
  challenge: string,
  signatureBase64Url: string,
  keyId?: string,
): boolean {
  return verifyEd25519Signature(publicKeyPem, agentControlMessage(agentPublicId, challenge, keyId), signatureBase64Url);
}

export function signSandboxWebhook(secret: string, timestampSeconds: number, body: unknown): string {
  const digest = createHmac('sha256', secret)
    .update(`${timestampSeconds}.${canonicalize(body)}`)
    .digest('hex');
  return `v1=${digest}`;
}

export function verifySandboxWebhook(
  secret: string,
  timestampHeader: string | undefined,
  signatureHeader: string | undefined,
  body: unknown,
  nowMs = Date.now(),
  toleranceSeconds = 300,
): boolean {
  if (!timestampHeader || !signatureHeader || !/^\d+$/.test(timestampHeader)) return false;
  const timestamp = Number(timestampHeader);
  if (!Number.isSafeInteger(timestamp)) return false;
  const age = Math.abs(Math.floor(nowMs / 1000) - timestamp);
  if (age > toleranceSeconds) return false;
  const expected = signSandboxWebhook(secret, timestamp, body);
  const actualBuffer = Buffer.from(signatureHeader);
  const expectedBuffer = Buffer.from(expected);
  if (actualBuffer.length !== expectedBuffer.length) return false;
  return timingSafeEqual(actualBuffer, expectedBuffer);
}
