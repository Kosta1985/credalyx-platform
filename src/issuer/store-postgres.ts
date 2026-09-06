import postgres from 'postgres';
import { uuidv7 } from '../crypto.js';
import type { IssuerKeyStatus, IssuerPublicJwk, IssuerPublicKey } from './backend.js';
import type { IssuerKeyRegistryStore } from './store.js';

type IssuerKeyRow = {
  key_id: string;
  algorithm: string;
  public_key_pem: string;
  public_jwk: IssuerPublicJwk;
  provider: string;
  provider_key_reference: string | null;
  status: IssuerKeyStatus;
  activated_at: Date;
  retired_at: Date | null;
  revoked_at: Date | null;
};

export class PostgresIssuerKeyRegistryStore implements IssuerKeyRegistryStore {
  private readonly sql: ReturnType<typeof postgres>;

  constructor(databaseUrl: string) {
    this.sql = postgres(databaseUrl, {
      max: 4,
      idle_timeout: 20,
      connect_timeout: 10,
      prepare: false,
    });
  }

  async syncKeys(keys: readonly IssuerPublicKey[], actorSubject: string, now: Date): Promise<void> {
    const activeKeys = keys.filter((key) => key.status === 'active');
    if (activeKeys.length !== 1) throw new Error('issuer backend must expose exactly one active key');
    const activeKey = activeKeys[0]!;

    await this.sql.begin(async (tx) => {
      type ActiveRow = { id: string; key_id: string };
      const currentActive = await tx<ActiveRow[]>`
        select id, key_id
        from issuer_signing_keys
        where status = 'active'
        for update
      `;
      for (const current of currentActive) {
        if (current.key_id === activeKey.keyId) continue;
        await tx`
          update issuer_signing_keys
          set status = 'retired', retired_at = ${now}, updated_at = ${now}
          where id = ${current.id} and status = 'active'
        `;
        await tx`
          insert into issuer_key_status_history (
            id, issuer_key_id, from_status, to_status, reason_code, actor_subject, occurred_at
          ) values (
            ${uuidv7()}, ${current.id}, 'active', 'retired', 'backend_active_key_changed',
            ${actorSubject}, ${now}
          )
        `;
      }

      for (const key of keys) {
        type ExistingRow = { id: string; public_key_pem: string; status: IssuerKeyStatus };
        const existingRows = await tx<ExistingRow[]>`
          select id, public_key_pem, status
          from issuer_signing_keys
          where key_id = ${key.keyId}
          limit 1
          for update
        `;
        const existing = existingRows[0];
        if (existing && existing.public_key_pem !== key.publicKeyPem) throw new Error('issuer key ID collision');
        if (!existing) {
          const id = uuidv7();
          await tx`
            insert into issuer_signing_keys (
              id, key_id, algorithm, public_key_pem, public_jwk, provider,
              provider_key_reference, status, activated_at, retired_at, revoked_at,
              created_at, updated_at
            ) values (
              ${id}, ${key.keyId}, ${key.algorithm}, ${key.publicKeyPem}, ${JSON.stringify(key.publicJwk)}::jsonb,
              ${key.provider}, ${key.providerKeyReference ?? null}, ${key.status}, ${new Date(key.activatedAt)},
              ${key.retiredAt ? new Date(key.retiredAt) : null}, ${key.revokedAt ? new Date(key.revokedAt) : null},
              ${now}, ${now}
            )
          `;
          await tx`
            insert into issuer_key_status_history (
              id, issuer_key_id, from_status, to_status, reason_code, actor_subject, occurred_at
            ) values (
              ${uuidv7()}, ${id}, null, ${key.status}, 'issuer_key_registered', ${actorSubject}, ${now}
            )
          `;
          continue;
        }

        if (existing.status !== key.status) {
          await tx`
            update issuer_signing_keys
            set algorithm = ${key.algorithm}, public_jwk = ${JSON.stringify(key.publicJwk)}::jsonb,
                provider = ${key.provider}, provider_key_reference = ${key.providerKeyReference ?? null},
                status = ${key.status}, activated_at = ${new Date(key.activatedAt)},
                retired_at = ${key.retiredAt ? new Date(key.retiredAt) : null},
                revoked_at = ${key.revokedAt ? new Date(key.revokedAt) : null}, updated_at = ${now}
            where id = ${existing.id}
          `;
          await tx`
            insert into issuer_key_status_history (
              id, issuer_key_id, from_status, to_status, reason_code, actor_subject, occurred_at
            ) values (
              ${uuidv7()}, ${existing.id}, ${existing.status}, ${key.status},
              'issuer_backend_status_sync', ${actorSubject}, ${now}
            )
          `;
        } else {
          await tx`
            update issuer_signing_keys
            set public_jwk = ${JSON.stringify(key.publicJwk)}::jsonb, provider = ${key.provider},
                provider_key_reference = ${key.providerKeyReference ?? null}, updated_at = ${now}
            where id = ${existing.id}
          `;
        }
      }
    });
  }

  async getKey(keyId: string): Promise<IssuerPublicKey | null> {
    const rows = await this.sql<IssuerKeyRow[]>`
      select key_id, algorithm, public_key_pem, public_jwk, provider, provider_key_reference,
        status, activated_at, retired_at, revoked_at
      from issuer_signing_keys
      where key_id = ${keyId}
      limit 1
    `;
    return rows[0] ? view(rows[0]) : null;
  }

  async getActiveKey(): Promise<IssuerPublicKey | null> {
    const rows = await this.sql<IssuerKeyRow[]>`
      select key_id, algorithm, public_key_pem, public_jwk, provider, provider_key_reference,
        status, activated_at, retired_at, revoked_at
      from issuer_signing_keys
      where status = 'active'
      limit 2
    `;
    if (rows.length > 1) throw new Error('issuer registry contains multiple active keys');
    return rows[0] ? view(rows[0]) : null;
  }

  async listVerificationKeys(): Promise<IssuerPublicKey[]> {
    const rows = await this.sql<IssuerKeyRow[]>`
      select key_id, algorithm, public_key_pem, public_jwk, provider, provider_key_reference,
        status, activated_at, retired_at, revoked_at
      from issuer_signing_keys
      where status in ('active', 'retired')
      order by activated_at desc
    `;
    return rows.map(view);
  }

  async setStatus(
    keyId: string,
    status: Exclude<IssuerKeyStatus, 'active'>,
    reasonCode: string,
    actorSubject: string,
    occurredAt: Date,
  ): Promise<boolean> {
    return this.sql.begin(async (tx) => {
      type Existing = { id: string; status: IssuerKeyStatus };
      const rows = await tx<Existing[]>`
        select id, status from issuer_signing_keys where key_id = ${keyId} limit 1 for update
      `;
      const row = rows[0];
      if (!row) return false;
      if (row.status === status) return true;
      await tx`
        update issuer_signing_keys
        set status = ${status},
            retired_at = ${status === 'retired' ? occurredAt : null},
            revoked_at = ${status === 'revoked' ? occurredAt : null},
            updated_at = ${occurredAt}
        where id = ${row.id}
      `;
      await tx`
        insert into issuer_key_status_history (
          id, issuer_key_id, from_status, to_status, reason_code, actor_subject, occurred_at
        ) values (
          ${uuidv7()}, ${row.id}, ${row.status}, ${status}, ${reasonCode}, ${actorSubject}, ${occurredAt}
        )
      `;
      return true;
    });
  }

  async close(): Promise<void> {
    await this.sql.end();
  }
}

function view(row: IssuerKeyRow): IssuerPublicKey {
  if (row.algorithm !== 'Ed25519') throw new Error('unsupported issuer key algorithm');
  return {
    keyId: row.key_id,
    algorithm: 'Ed25519',
    publicKeyPem: row.public_key_pem,
    publicJwk: row.public_jwk,
    status: row.status,
    provider: row.provider,
    activatedAt: row.activated_at.toISOString(),
    ...(row.provider_key_reference ? { providerKeyReference: row.provider_key_reference } : {}),
    ...(row.retired_at ? { retiredAt: row.retired_at.toISOString() } : {}),
    ...(row.revoked_at ? { revokedAt: row.revoked_at.toISOString() } : {}),
  };
}
