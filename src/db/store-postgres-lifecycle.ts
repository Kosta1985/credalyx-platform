import postgres from 'postgres';
import type { AgentRecord } from '../domain.js';
import { PostgresPlatformStore } from './store-postgres.js';

type FallbackAgentRow = {
  id: string;
  public_id: string;
  organization_id: string | null;
  referrer_agent_id: string | null;
  referral_code: string;
  verification_level: number;
  status: AgentRecord['status'];
  control_verified_at: Date | null;
  version: number;
  owner_subject: string;
  public_key_pem: string | null;
  endpoint: string | null;
};

/**
 * Runtime platform store with credential-lifecycle-aware agent lookup.
 *
 * The base commerce store intentionally resolves an active key through an inner
 * join. After emergency revocation there is no active key, but the suspended
 * agent must remain addressable for status, historical key lookup, audit and
 * future high-assurance recovery. This adapter falls back to the most recent
 * historical key while preserving the agent's suspended/revoked state.
 */
export class PostgresLifecyclePlatformStore extends PostgresPlatformStore {
  private readonly lookupSql: ReturnType<typeof postgres>;

  constructor(databaseUrl: string) {
    super(databaseUrl);
    this.lookupSql = postgres(databaseUrl, {
      max: 3,
      idle_timeout: 20,
      connect_timeout: 10,
      prepare: false,
    });
  }

  override async getAgent(publicId: string): Promise<AgentRecord | null> {
    const active = await super.getAgent(publicId);
    if (active) return active;

    const rows = await this.lookupSql<FallbackAgentRow[]>`
      select
        a.id,
        a.public_id,
        a.organization_id,
        a.referrer_agent_id,
        a.referral_code,
        a.verification_level,
        a.status::text as status,
        a.control_verified_at,
        a.version,
        u.external_subject as owner_subject,
        k.public_key_pem,
        e.url as endpoint
      from agents a
      join users u on u.id = a.owner_user_id
      left join lateral (
        select ak.public_key_pem
        from agent_keys ak
        where ak.agent_id = a.id
        order by
          (ak.revoked_at is null) desc,
          ak.activated_at desc nulls last,
          ak.created_at desc
        limit 1
      ) k on true
      left join lateral (
        select ae.url
        from agent_endpoints ae
        where ae.agent_id = a.id and ae.disabled_at is null
        order by ae.created_at desc
        limit 1
      ) e on true
      where a.public_id = ${publicId}
        and a.deleted_at is null
      limit 1
    `;
    const row = rows[0];
    if (!row || !row.public_key_pem || !row.endpoint) return null;

    const capabilities = await this.lookupSql<{ capability: string }[]>`
      select capability
      from agent_capabilities
      where agent_id = ${row.id}
      order by capability
    `;
    return {
      id: row.id,
      publicId: row.public_id,
      ownerSubject: row.owner_subject,
      publicKeyPem: row.public_key_pem,
      endpoint: row.endpoint,
      capabilities: capabilities.map((item) => item.capability),
      verificationLevel: row.verification_level as 0 | 1 | 2 | 3,
      status: row.status,
      referralCode: row.referral_code,
      version: row.version,
      ...(row.organization_id ? { organizationId: row.organization_id } : {}),
      ...(row.referrer_agent_id ? { referrerAgentId: row.referrer_agent_id } : {}),
      ...(row.control_verified_at ? { controlVerifiedAt: row.control_verified_at.toISOString() } : {}),
    };
  }

  override async close(): Promise<void> {
    await Promise.all([
      super.close(),
      this.lookupSql.end(),
    ]);
  }
}
