import {
  agentKeyId,
  challengeDigest,
  createChallenge,
  uuidv7,
} from '../crypto.js';
import type { AgentRecord, SignedPassport } from '../domain.js';
import type { MemoryPlatformStore } from '../store.js';

export interface AgentKeyRecord {
  internalId: string;
  keyId: string;
  algorithm: 'Ed25519';
  publicKeyPem: string;
  activatedAt: string;
  revokedAt?: string;
}

export interface KeyRotationRecord {
  rotationId: string;
  agentId: string;
  oldKey: AgentKeyRecord;
  newKeyId: string;
  newPublicKeyPem: string;
  challengeDigest: string;
  expiresAt: string;
  completedAt?: string;
  cancelledAt?: string;
}

export interface StartKeyRotationResult extends KeyRotationRecord {
  challenge: string;
}

export interface CompleteKeyRotationInput {
  agent: AgentRecord;
  rotationId: string;
  challengeDigest: string;
  completedAt: Date;
  actorSubject: string;
  replacementPassport?: SignedPassport;
}

export interface CompleteKeyRotationResult {
  newKeyId: string;
  reissuedPassportId?: string;
}

export interface EmergencyKeyRevocationResult {
  found: boolean;
  revoked: boolean;
  passportRevoked: boolean;
}

export interface CredentialLifecycleStore {
  getCurrentKey(agent: AgentRecord): Promise<AgentKeyRecord>;
  getKey(agent: AgentRecord, keyId: string): Promise<AgentKeyRecord | null>;
  createControlChallenge(agent: AgentRecord, digest: string, expiresAt: Date): Promise<AgentKeyRecord>;
  confirmAgentControl(agent: AgentRecord, keyId: string, digest: string, verifiedAt: Date): Promise<boolean>;
  startKeyRotation(agent: AgentRecord, newPublicKeyPem: string, now: Date, ttlMs: number): Promise<StartKeyRotationResult>;
  getKeyRotation(agent: AgentRecord, rotationId: string): Promise<KeyRotationRecord | null>;
  completeKeyRotation(input: CompleteKeyRotationInput): Promise<CompleteKeyRotationResult>;
  emergencyRevokeKey(
    agent: AgentRecord,
    keyId: string,
    reasonCode: string,
    actorSubject: string,
    revokedAt: Date,
  ): Promise<EmergencyKeyRevocationResult>;
  close(): Promise<void>;
}

type MemoryKey = AgentKeyRecord;
type MemoryChallenge = {
  digest: string;
  keyId: string;
  expiresAt: number;
  consumed: boolean;
};

export class MemoryCredentialLifecycleStore implements CredentialLifecycleStore {
  private readonly keys = new Map<string, MemoryKey[]>();
  private readonly challenges = new Map<string, MemoryChallenge>();
  private readonly rotations = new Map<string, KeyRotationRecord>();

  constructor(private readonly platform: MemoryPlatformStore) {}

  private ensureKeyHistory(agent: AgentRecord): MemoryKey[] {
    let values = this.keys.get(agent.id);
    if (!values) {
      values = [{
        internalId: uuidv7(),
        keyId: agentKeyId(agent.publicKeyPem),
        algorithm: 'Ed25519',
        publicKeyPem: agent.publicKeyPem,
        activatedAt: new Date().toISOString(),
      }];
      this.keys.set(agent.id, values);
    }
    return values;
  }

  async getCurrentKey(agent: AgentRecord): Promise<AgentKeyRecord> {
    const active = this.ensureKeyHistory(agent)
      .filter((key) => !key.revokedAt)
      .sort((a, b) => b.activatedAt.localeCompare(a.activatedAt))[0];
    if (!active) throw new Error('agent has no active key');
    return structuredClone(active);
  }

  async getKey(agent: AgentRecord, keyId: string): Promise<AgentKeyRecord | null> {
    const key = this.ensureKeyHistory(agent).find((item) => item.keyId === keyId);
    return key ? structuredClone(key) : null;
  }

  async createControlChallenge(agent: AgentRecord, digest: string, expiresAt: Date): Promise<AgentKeyRecord> {
    const key = await this.getCurrentKey(agent);
    this.challenges.set(agent.id, {
      digest,
      keyId: key.keyId,
      expiresAt: expiresAt.getTime(),
      consumed: false,
    });
    return key;
  }

  async confirmAgentControl(agent: AgentRecord, keyId: string, digest: string, verifiedAt: Date): Promise<boolean> {
    const challenge = this.challenges.get(agent.id);
    if (!challenge || challenge.consumed || challenge.keyId !== keyId || challenge.digest !== digest) return false;
    if (challenge.expiresAt <= verifiedAt.getTime()) return false;
    const current = await this.getCurrentKey(agent);
    if (current.keyId !== keyId) return false;
    challenge.consumed = true;
    const stored = this.platform.agents.get(agent.publicId);
    if (!stored) return false;
    stored.verificationLevel = Math.max(stored.verificationLevel, 1) as 1 | 2 | 3;
    stored.controlVerifiedAt = verifiedAt.toISOString();
    stored.version += 1;
    return true;
  }

  async startKeyRotation(agent: AgentRecord, newPublicKeyPem: string, now: Date, ttlMs: number): Promise<StartKeyRotationResult> {
    const pending = [...this.rotations.values()].find((item) => item.agentId === agent.id && !item.completedAt && !item.cancelledAt);
    if (pending) throw new Error('agent already has a pending key rotation');
    const oldKey = await this.getCurrentKey(agent);
    const newKeyId = agentKeyId(newPublicKeyPem);
    if (newKeyId === oldKey.keyId) throw new Error('new key must differ from current key');
    const challenge = createChallenge();
    const rotation: KeyRotationRecord = {
      rotationId: uuidv7(),
      agentId: agent.id,
      oldKey,
      newKeyId,
      newPublicKeyPem,
      challengeDigest: challengeDigest(challenge),
      expiresAt: new Date(now.getTime() + ttlMs).toISOString(),
    };
    this.rotations.set(rotation.rotationId, structuredClone(rotation));
    return { ...structuredClone(rotation), challenge };
  }

  async getKeyRotation(agent: AgentRecord, rotationId: string): Promise<KeyRotationRecord | null> {
    const rotation = this.rotations.get(rotationId);
    if (!rotation || rotation.agentId !== agent.id) return null;
    return structuredClone(rotation);
  }

  async completeKeyRotation(input: CompleteKeyRotationInput): Promise<CompleteKeyRotationResult> {
    const rotation = this.rotations.get(input.rotationId);
    if (!rotation || rotation.agentId !== input.agent.id) throw new Error('key rotation not found');
    if (rotation.completedAt || rotation.cancelledAt) throw new Error('key rotation is not pending');
    if (rotation.challengeDigest !== input.challengeDigest) throw new Error('key rotation challenge mismatch');
    if (Date.parse(rotation.expiresAt) <= input.completedAt.getTime()) throw new Error('key rotation challenge expired');

    const keys = this.ensureKeyHistory(input.agent);
    const oldKey = keys.find((key) => key.keyId === rotation.oldKey.keyId);
    if (!oldKey || oldKey.revokedAt) throw new Error('old key is no longer active');
    const activePassport = [...this.platform.passports.values()]
      .find((passport) => passport.claims.agent_id === input.agent.publicId && passport.status === 'active');
    if (activePassport && !input.replacementPassport) throw new Error('active passport must be replaced during key rotation');

    oldKey.revokedAt = input.completedAt.toISOString();
    keys.push({
      internalId: uuidv7(),
      keyId: rotation.newKeyId,
      algorithm: 'Ed25519',
      publicKeyPem: rotation.newPublicKeyPem,
      activatedAt: input.completedAt.toISOString(),
    });

    const storedAgent = this.platform.agents.get(input.agent.publicId);
    if (!storedAgent) throw new Error('agent not found');
    storedAgent.publicKeyPem = rotation.newPublicKeyPem;
    storedAgent.version += 1;

    let reissuedPassportId: string | undefined;
    if (activePassport && input.replacementPassport) {
      activePassport.status = 'revoked';
      this.platform.passports.set(activePassport.claims.passport_id, activePassport);
      this.platform.passports.set(input.replacementPassport.claims.passport_id, structuredClone(input.replacementPassport));
      reissuedPassportId = input.replacementPassport.claims.passport_id;
    }

    rotation.completedAt = input.completedAt.toISOString();
    this.rotations.set(rotation.rotationId, rotation);
    return {
      newKeyId: rotation.newKeyId,
      ...(reissuedPassportId ? { reissuedPassportId } : {}),
    };
  }

  async emergencyRevokeKey(
    agent: AgentRecord,
    keyId: string,
    _reasonCode: string,
    _actorSubject: string,
    revokedAt: Date,
  ): Promise<EmergencyKeyRevocationResult> {
    const key = this.ensureKeyHistory(agent).find((item) => item.keyId === keyId);
    if (!key) return { found: false, revoked: false, passportRevoked: false };
    if (key.revokedAt) return { found: true, revoked: false, passportRevoked: false };
    const current = await this.getCurrentKey(agent);
    const wasCurrent = current.keyId === keyId;
    key.revokedAt = revokedAt.toISOString();

    let passportRevoked = false;
    if (wasCurrent) {
      const storedAgent = this.platform.agents.get(agent.publicId);
      if (storedAgent) {
        storedAgent.status = 'suspended';
        storedAgent.version += 1;
      }
      for (const passport of this.platform.passports.values()) {
        if (passport.claims.agent_id === agent.publicId && passport.status === 'active') {
          passport.status = 'revoked';
          passportRevoked = true;
        }
      }
    }
    return { found: true, revoked: true, passportRevoked };
  }

  async close(): Promise<void> {}
}
