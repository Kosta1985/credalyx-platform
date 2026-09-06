import { createPublicKey, generateKeyPairSync, sign } from 'node:crypto';
import { issuerKeyId } from '../crypto.js';

export type IssuerKeyStatus = 'active' | 'retired' | 'revoked';

export interface IssuerPublicJwk {
  kty: 'OKP';
  crv: 'Ed25519';
  x: string;
  kid: string;
  alg: 'EdDSA';
  use: 'sig';
}

export interface IssuerPublicKey {
  keyId: string;
  algorithm: 'Ed25519';
  publicKeyPem: string;
  publicJwk: IssuerPublicJwk;
  status: IssuerKeyStatus;
  provider: string;
  providerKeyReference?: string;
  activatedAt: string;
  retiredAt?: string;
  revokedAt?: string;
}

export interface IssuerSigningBackend {
  getActiveKey(): Promise<IssuerPublicKey>;
  getKey(keyId: string): Promise<IssuerPublicKey | null>;
  listKeys(): Promise<IssuerPublicKey[]>;
  sign(keyId: string, payload: Uint8Array): Promise<string>;
  close(): Promise<void>;
}

interface LocalPrivateKeyRecord {
  public: IssuerPublicKey;
  privateKeyPem: string;
}

/**
 * Local/dev implementation of the managed signing boundary.
 *
 * This backend is intentionally replaceable by a cloud KMS/HSM adapter. Its
 * public interface never exposes a private key and callers request signatures
 * by key ID only. Do not use this backend as the production custody model.
 */
export class LocalEd25519IssuerBackend implements IssuerSigningBackend {
  private readonly keys = new Map<string, LocalPrivateKeyRecord>();
  private activeKeyId: string;

  constructor(input: {
    active: { privateKeyPem: string; publicKeyPem: string; activatedAt?: Date; providerKeyReference?: string };
    retired?: Array<{ privateKeyPem: string; publicKeyPem: string; activatedAt?: Date; retiredAt?: Date; providerKeyReference?: string }>;
  }) {
    const active = this.add({ ...input.active, status: 'active' });
    this.activeKeyId = active.public.keyId;
    for (const retired of input.retired ?? []) this.add({ ...retired, status: 'retired' });
  }

  static ephemeral(): LocalEd25519IssuerBackend {
    const pair = generateKeyPairSync('ed25519');
    return new LocalEd25519IssuerBackend({
      active: {
        publicKeyPem: pair.publicKey.export({ format: 'pem', type: 'spki' }).toString(),
        privateKeyPem: pair.privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
      },
    });
  }

  static fromPem(input: { privateKeyPem: string; publicKeyPem: string; providerKeyReference?: string }): LocalEd25519IssuerBackend {
    return new LocalEd25519IssuerBackend({ active: input });
  }

  private add(input: {
    privateKeyPem: string;
    publicKeyPem: string;
    status: 'active' | 'retired';
    activatedAt?: Date;
    retiredAt?: Date;
    providerKeyReference?: string;
  }): LocalPrivateKeyRecord {
    const keyId = issuerKeyId(input.publicKeyPem);
    const record: LocalPrivateKeyRecord = {
      public: {
        keyId,
        algorithm: 'Ed25519',
        publicKeyPem: input.publicKeyPem,
        publicJwk: publicEd25519Jwk(input.publicKeyPem, keyId),
        status: input.status,
        provider: 'local-pem',
        activatedAt: (input.activatedAt ?? new Date()).toISOString(),
        ...(input.retiredAt ? { retiredAt: input.retiredAt.toISOString() } : {}),
        ...(input.providerKeyReference ? { providerKeyReference: input.providerKeyReference } : {}),
      },
      privateKeyPem: input.privateKeyPem,
    };
    this.keys.set(keyId, record);
    return record;
  }

  async getActiveKey(): Promise<IssuerPublicKey> {
    const record = this.keys.get(this.activeKeyId);
    if (!record || record.public.status !== 'active') throw new Error('issuer has no active signing key');
    return structuredClone(record.public);
  }

  async getKey(keyId: string): Promise<IssuerPublicKey | null> {
    const record = this.keys.get(keyId);
    return record ? structuredClone(record.public) : null;
  }

  async listKeys(): Promise<IssuerPublicKey[]> {
    return [...this.keys.values()]
      .map((record) => structuredClone(record.public))
      .sort((a, b) => b.activatedAt.localeCompare(a.activatedAt));
  }

  async sign(keyId: string, payload: Uint8Array): Promise<string> {
    const record = this.keys.get(keyId);
    if (!record || record.public.status !== 'active') throw new Error('issuer signing key is not active');
    return sign(null, Buffer.from(payload), record.privateKeyPem).toString('base64url');
  }

  /** Test/dev rotation helper. Production rotation belongs in a managed backend. */
  rotateTo(input: { privateKeyPem: string; publicKeyPem: string; activatedAt?: Date }): IssuerPublicKey {
    const now = input.activatedAt ?? new Date();
    const current = this.keys.get(this.activeKeyId);
    if (current) {
      current.public.status = 'retired';
      current.public.retiredAt = now.toISOString();
    }
    const replacement = this.add({ ...input, status: 'active', activatedAt: now });
    this.activeKeyId = replacement.public.keyId;
    return structuredClone(replacement.public);
  }

  revoke(keyId: string, revokedAt = new Date()): boolean {
    const record = this.keys.get(keyId);
    if (!record) return false;
    record.public.status = 'revoked';
    record.public.revokedAt = revokedAt.toISOString();
    if (this.activeKeyId === keyId) this.activeKeyId = '';
    return true;
  }

  async close(): Promise<void> {}
}

export function publicEd25519Jwk(publicKeyPem: string, keyId = issuerKeyId(publicKeyPem)): IssuerPublicJwk {
  const key = createPublicKey(publicKeyPem);
  if (key.asymmetricKeyType !== 'ed25519') throw new Error('issuer public key must be Ed25519');
  const jwk = key.export({ format: 'jwk' });
  if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || typeof jwk.x !== 'string') {
    throw new Error('unable to export Ed25519 issuer public JWK');
  }
  return {
    kty: 'OKP',
    crv: 'Ed25519',
    x: jwk.x,
    kid: keyId,
    alg: 'EdDSA',
    use: 'sig',
  };
}
