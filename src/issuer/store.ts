import type { IssuerPublicKey, IssuerKeyStatus } from './backend.js';

export interface IssuerKeyRegistryStore {
  syncKeys(keys: readonly IssuerPublicKey[], actorSubject: string, now: Date): Promise<void>;
  getKey(keyId: string): Promise<IssuerPublicKey | null>;
  getActiveKey(): Promise<IssuerPublicKey | null>;
  listVerificationKeys(): Promise<IssuerPublicKey[]>;
  setStatus(
    keyId: string,
    status: Exclude<IssuerKeyStatus, 'active'>,
    reasonCode: string,
    actorSubject: string,
    occurredAt: Date,
  ): Promise<boolean>;
  close(): Promise<void>;
}

export class MemoryIssuerKeyRegistryStore implements IssuerKeyRegistryStore {
  private readonly keys = new Map<string, IssuerPublicKey>();

  async syncKeys(keys: readonly IssuerPublicKey[], _actorSubject: string, _now: Date): Promise<void> {
    const incomingActive = keys.filter((key) => key.status === 'active');
    if (incomingActive.length > 1) throw new Error('issuer registry cannot contain multiple active keys');
    for (const key of keys) {
      const existing = this.keys.get(key.keyId);
      if (existing && existing.publicKeyPem !== key.publicKeyPem) throw new Error('issuer key ID collision');
      if (existing?.status === 'revoked' && key.status !== 'revoked') {
        throw new Error('revoked issuer key cannot be reactivated by backend synchronization');
      }
      this.keys.set(key.keyId, structuredClone(key));
    }
    if (incomingActive[0]) {
      for (const [keyId, key] of this.keys) {
        if (keyId === incomingActive[0].keyId || key.status !== 'active') continue;
        key.status = 'retired';
        key.retiredAt = incomingActive[0].activatedAt;
      }
    }
  }

  async getKey(keyId: string): Promise<IssuerPublicKey | null> {
    const value = this.keys.get(keyId);
    return value ? structuredClone(value) : null;
  }

  async getActiveKey(): Promise<IssuerPublicKey | null> {
    const values = [...this.keys.values()].filter((key) => key.status === 'active');
    if (values.length > 1) throw new Error('issuer registry has multiple active keys');
    return values[0] ? structuredClone(values[0]) : null;
  }

  async listVerificationKeys(): Promise<IssuerPublicKey[]> {
    return [...this.keys.values()]
      .filter((key) => key.status !== 'revoked')
      .map((key) => structuredClone(key))
      .sort((a, b) => b.activatedAt.localeCompare(a.activatedAt));
  }

  async setStatus(
    keyId: string,
    status: Exclude<IssuerKeyStatus, 'active'>,
    _reasonCode: string,
    _actorSubject: string,
    occurredAt: Date,
  ): Promise<boolean> {
    const key = this.keys.get(keyId);
    if (!key) return false;
    if (key.status === 'revoked' && status !== 'revoked') {
      throw new Error('revoked issuer key cannot transition to another status');
    }
    key.status = status;
    if (status === 'retired') {
      key.retiredAt = occurredAt.toISOString();
      delete key.revokedAt;
    } else {
      key.revokedAt = occurredAt.toISOString();
    }
    return true;
  }

  async close(): Promise<void> {}
}
