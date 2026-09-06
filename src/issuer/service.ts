import { verify } from 'node:crypto';
import { agentKeyId, canonicalize, uuidv7 } from '../crypto.js';
import type { AgentPassportClaims, AgentRecord, SignedPassport } from '../domain.js';
import type { IssuerPublicKey, IssuerSigningBackend } from './backend.js';
import type { IssuerKeyRegistryStore } from './store.js';

export class PassportIssuerService {
  readonly issuer: string;

  constructor(
    issuer: string,
    private readonly backend: IssuerSigningBackend,
    private readonly registry: IssuerKeyRegistryStore,
  ) {
    this.issuer = issuer.replace(/\/$/, '');
  }

  async initialize(actorSubject = 'system:issuer-startup', now = new Date()): Promise<void> {
    const backendKeys = await this.backend.listKeys();
    if (backendKeys.filter((key) => key.status === 'active').length !== 1) {
      throw new Error('issuer backend must expose exactly one active signing key');
    }
    await this.registry.syncKeys(backendKeys, actorSubject, now);
    const activeBackend = await this.backend.getActiveKey();
    const activeRegistry = await this.registry.getActiveKey();
    if (!activeRegistry || activeRegistry.keyId !== activeBackend.keyId) {
      throw new Error('issuer registry active key does not match signing backend');
    }
  }

  async issue(
    agent: AgentRecord,
    ttlDays = 30,
    passportVersion = 1,
    preserveExpiresAt?: Date,
  ): Promise<SignedPassport> {
    if (agent.verificationLevel < 1 || !agent.controlVerifiedAt) {
      throw new Error('agent control must be verified before passport issuance');
    }
    if (agent.status === 'revoked' || agent.status === 'suspended') throw new Error('agent is not eligible for passport issuance');
    if (!Number.isInteger(passportVersion) || passportVersion < 1) throw new Error('passport version must be a positive integer');

    const issuerKey = await this.backend.getActiveKey();
    const registered = await this.registry.getKey(issuerKey.keyId);
    if (!registered || registered.status !== 'active' || registered.publicKeyPem !== issuerKey.publicKeyPem) {
      throw new Error('active issuer signing key is not registered consistently');
    }

    const issued = new Date();
    const expires = preserveExpiresAt ?? new Date(issued.getTime() + ttlDays * 86_400_000);
    if (expires.getTime() <= issued.getTime()) throw new Error('passport expiry must be in the future');
    const passportId = uuidv7();
    const claims: AgentPassportClaims = {
      passport_id: passportId,
      passport_version: passportVersion,
      agent_id: agent.publicId,
      issuer: this.issuer,
      issuer_key_id: issuerKey.keyId,
      subject: `agent:${agent.publicId}`,
      verification_level: agent.verificationLevel,
      capabilities: [...agent.capabilities].sort(),
      issued_at: issued.toISOString(),
      expires_at: expires.toISOString(),
      public_key_reference: `${this.issuer}/v1/agents/${agent.publicId}/keys/${encodeURIComponent(agentKeyId(agent.publicKeyPem))}`,
      status_reference: `${this.issuer}/v1/passports/${passportId}/status`,
      schema_version: '1.1',
    };
    const signature = await this.backend.sign(issuerKey.keyId, Buffer.from(canonicalize(claims)));
    return { claims, signature, status: 'active' };
  }

  async verify(passport: SignedPassport, nowMs = Date.now()): Promise<boolean> {
    if (passport.status !== 'active') return false;
    if (Date.parse(passport.claims.expires_at) <= nowMs) return false;
    if (passport.claims.issuer !== this.issuer) return false;

    const payload = Buffer.from(canonicalize(passport.claims));
    const signature = Buffer.from(passport.signature, 'base64url');
    if (passport.claims.issuer_key_id) {
      const key = await this.registry.getKey(passport.claims.issuer_key_id);
      if (!key || key.status === 'revoked') return false;
      return verify(null, payload, key.publicKeyPem, signature);
    }

    // Backward compatibility for schema 1.0 passports issued before issuer_key_id
    // was a signed claim. Try every non-revoked historical issuer verification key.
    const candidates = await this.registry.listVerificationKeys();
    return candidates.some((key) => verify(null, payload, key.publicKeyPem, signature));
  }

  async getKey(keyId: string): Promise<IssuerPublicKey | null> {
    return this.registry.getKey(keyId);
  }

  async getActiveKey(): Promise<IssuerPublicKey> {
    const key = await this.registry.getActiveKey();
    if (!key) throw new Error('issuer registry has no active key');
    return key;
  }

  async listVerificationKeys(): Promise<IssuerPublicKey[]> {
    return this.registry.listVerificationKeys();
  }

  async jwks(): Promise<{ keys: IssuerPublicKey['publicJwk'][] }> {
    const keys = await this.registry.listVerificationKeys();
    return { keys: keys.map((key) => structuredClone(key.publicJwk)) };
  }

  async close(): Promise<void> {
    await Promise.all([this.backend.close(), this.registry.close()]);
  }
}
