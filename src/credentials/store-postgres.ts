import postgres from 'postgres';
import {
  agentKeyId,
  challengeDigest,
  createChallenge,
  uuidv7,
} from '../crypto.js';
import type { AgentRecord } from '../domain.js';
import type {
  AgentKeyRecord,
  CompleteKeyRotationInput,
  CompleteKeyRotationResult,
  CredentialLifecycleStore,
  EmergencyKeyRevocationResult,
  KeyRotationRecord,
  StartKeyRotationResult,
} from './store.js';

type KeyRow = {
  id: string;
  public_key_pem: string;
  activated_at: Date;
  revoked_at: Date | null;
};

type RotationRow = {
  rotation_id: string;
  agent_id: string;
  old_key_internal_id: string;
  old_public_key_pem: string;
  old_activated_at: Date;
  old_revoked_at: Date | null;
  new_key_fingerprint: string;
  new_public_key_pem: string;
  challenge_digest: string;
  expires_at: Date;
  completed_at: Date | null;
  cancelled_at: Date | null;
};

export class PostgresCredentialLifecycleStore implements CredentialLifecycleStore {
  private readonly sql: ReturnType<typeof postgres>;

  constructor(databaseUrl: string) {
    this.sql = postgres(databaseUrl, {
      max: 5,
      idle_timeout: 20,
      connect_timeout: 10,
      prepare: false,
    });
  }

  async getCurrentKey(agent: AgentRecord): Promise<AgentKeyRecord> {
    const rows = await this.sql<KeyRow[]>`
      select id, public_key_pem, activated_at, revoked_at
      from agent_keys
      where agent_id = ${agent.id}
        and activated_at is not null
        and revoked_at is null
      order by activated_at desc, created_at desc
      limit 1
    `;
    const row = rows[0];
    if (!row) throw new Error('agent has no active key');
    return keyView(row);
  }

  async getKey(agent: AgentRecord, keyId: string): Promise<AgentKeyRecord | null> {
    const rows = await this.sql<KeyRow[]>`
      select id, public_key_pem, activated_at, revoked_at
      from agent_keys
      where agent_id = ${agent.id}
      order by activated_at desc, created_at desc
    `;
    const row = rows.find((item) => agentKeyId(item.public_key_pem) === keyId);
    return row ? keyView(row) : null;
  }

  async createControlChallenge(agent: AgentRecord, digest: string, expiresAt: Date): Promise<AgentKeyRecord> {
    return this.sql.begin(async (tx) => {
      const rows = await tx<KeyRow[]>`
        select id, public_key_pem, activated_at, revoked_at
        from agent_keys
        where agent_id = ${agent.id}
          and activated_at is not null
          and revoked_at is null
        order by activated_at desc, created_at desc
        limit 1
        for share
      `;
      const row = rows[0];
      if (!row) throw new Error('agent has no active key');
      await tx`
        insert into agent_challenges (id, agent_id, agent_key_id, digest, expires_at)
        values (${uuidv7()}, ${agent.id}, ${row.id}, ${digest}, ${expiresAt})
      `;
      return keyView(row);
    });
  }

  async confirmAgentControl(agent: AgentRecord, keyId: string, digest: string, verifiedAt: Date): Promise<boolean> {
    return this.sql.begin(async (tx) => {
      type ChallengeRow = KeyRow & { challenge_id: string };
      const rows = await tx<ChallengeRow[]>`
        select c.id as challenge_id, k.id, k.public_key_pem, k.activated_at, k.revoked_at
        from agent_challenges c
        join agent_keys k on k.id = c.agent_key_id
        where c.agent_id = ${agent.id}
          and c.digest = ${digest}
          and c.consumed_at is null
          and c.expires_at > ${verifiedAt}
        limit 1
        for update of c
      `;
      const row = rows[0];
      if (!row || row.revoked_at || agentKeyId(row.public_key_pem) !== keyId) return false;
      const current = await tx<KeyRow[]>`
        select id, public_key_pem, activated_at, revoked_at
        from agent_keys
        where agent_id = ${agent.id}
          and activated_at is not null
          and revoked_at is null
        order by activated_at desc, created_at desc
        limit 1
      `;
      if (!current[0] || current[0].id !== row.id) return false;

      const consumed = await tx<{ id: string }[]>`
        update agent_challenges
        set consumed_at = ${verifiedAt}
        where id = ${row.challenge_id} and consumed_at is null
        returning id
      `;
      if (!consumed[0]) return false;
      await tx`
        update agents
        set verification_level = greatest(verification_level, 1),
            control_verified_at = ${verifiedAt},
            version = version + 1,
            updated_at = ${verifiedAt}
        where id = ${agent.id}
      `;
      await tx`
        update agent_endpoints
        set verified_at = ${verifiedAt}
        where agent_id = ${agent.id} and disabled_at is null
      `;
      await tx`
        insert into audit_events (id, actor_type, actor_subject, action, target_type, target_id, occurred_at)
        values (${uuidv7()}, 'agent', ${agent.publicId}, 'agent.control_verified', 'agent', ${agent.publicId}, ${verifiedAt})
      `;
      return true;
    });
  }

  async startKeyRotation(agent: AgentRecord, newPublicKeyPem: string, now: Date, ttlMs: number): Promise<StartKeyRotationResult> {
    const newKeyId = agentKeyId(newPublicKeyPem);
    const challenge = createChallenge();
    const digest = challengeDigest(challenge);
    const expiresAt = new Date(now.getTime() + ttlMs);
    return this.sql.begin(async (tx) => {
      const rows = await tx<KeyRow[]>`
        select id, public_key_pem, activated_at, revoked_at
        from agent_keys
        where agent_id = ${agent.id}
          and activated_at is not null
          and revoked_at is null
        order by activated_at desc, created_at desc
        limit 1
        for update
      `;
      const old = rows[0];
      if (!old) throw new Error('agent has no active key');
      const oldKey = keyView(old);
      if (oldKey.keyId === newKeyId) throw new Error('new key must differ from current key');
      const rotationId = uuidv7();
      await tx`
        insert into agent_key_rotations (
          id, agent_id, old_key_id, new_key_fingerprint, new_public_key_pem,
          challenge_digest, expires_at, created_at
        ) values (
          ${rotationId}, ${agent.id}, ${old.id}, ${newKeyId}, ${newPublicKeyPem},
          ${digest}, ${expiresAt}, ${now}
        )
      `;
      return {
        rotationId,
        agentId: agent.id,
        oldKey,
        newKeyId,
        newPublicKeyPem,
        challengeDigest: digest,
        expiresAt: expiresAt.toISOString(),
        challenge,
      };
    });
  }

  async getKeyRotation(agent: AgentRecord, rotationId: string): Promise<KeyRotationRecord | null> {
    const rows = await this.sql<RotationRow[]>`
      select r.id as rotation_id, r.agent_id, r.old_key_id as old_key_internal_id,
        k.public_key_pem as old_public_key_pem, k.activated_at as old_activated_at,
        k.revoked_at as old_revoked_at, r.new_key_fingerprint, r.new_public_key_pem,
        r.challenge_digest, r.expires_at, r.completed_at, r.cancelled_at
      from agent_key_rotations r
      join agent_keys k on k.id = r.old_key_id
      where r.id = ${rotationId} and r.agent_id = ${agent.id}
      limit 1
    `;
    return rows[0] ? rotationView(rows[0]) : null;
  }

  async completeKeyRotation(input: CompleteKeyRotationInput): Promise<CompleteKeyRotationResult> {
    return this.sql.begin(async (tx) => {
      const rows = await tx<RotationRow[]>`
        select r.id as rotation_id, r.agent_id, r.old_key_id as old_key_internal_id,
          k.public_key_pem as old_public_key_pem, k.activated_at as old_activated_at,
          k.revoked_at as old_revoked_at, r.new_key_fingerprint, r.new_public_key_pem,
          r.challenge_digest, r.expires_at, r.completed_at, r.cancelled_at
        from agent_key_rotations r
        join agent_keys k on k.id = r.old_key_id
        where r.id = ${input.rotationId} and r.agent_id = ${input.agent.id}
        limit 1
        for update of r, k
      `;
      const rotation = rows[0];
      if (!rotation) throw new Error('key rotation not found');
      if (rotation.completed_at || rotation.cancelled_at) throw new Error('key rotation is not pending');
      if (rotation.challenge_digest !== input.challengeDigest) throw new Error('key rotation challenge mismatch');
      if (rotation.expires_at.getTime() <= input.completedAt.getTime()) throw new Error('key rotation challenge expired');
      if (rotation.old_revoked_at) throw new Error('old key is no longer active');

      const activeKeys = await tx<KeyRow[]>`
        select id, public_key_pem, activated_at, revoked_at
        from agent_keys
        where agent_id = ${input.agent.id}
          and activated_at is not null
          and revoked_at is null
        for update
      `;
      if (activeKeys.length !== 1 || activeKeys[0]!.id !== rotation.old_key_internal_id) {
        throw new Error('active key changed during rotation');
      }

      await tx`
        update agent_keys
        set revoked_at = ${input.completedAt}
        where id = ${rotation.old_key_internal_id} and revoked_at is null
      `;
      await tx`
        insert into agent_keys (id, agent_id, key_id, algorithm, public_key_pem, activated_at, created_at)
        values (
          ${uuidv7()}, ${input.agent.id}, ${rotation.new_key_fingerprint}, 'Ed25519',
          ${rotation.new_public_key_pem}, ${input.completedAt}, ${input.completedAt}
        )
      `;
      await tx`
        update agents
        set version = version + 1, updated_at = ${input.completedAt}
        where id = ${input.agent.id}
      `;

      type PassportRow = {
        id: string;
        passport_id: string;
        purchase_id: string | null;
        passport_version: number;
        expires_at: Date;
      };
      const activePassports = await tx<PassportRow[]>`
        select id, passport_id, purchase_id, passport_version, expires_at
        from agent_passports
        where agent_id = ${input.agent.id}
          and status = 'active'
          and expires_at > ${input.completedAt}
        order by issued_at desc
        limit 1
        for update
      `;
      const activePassport = activePassports[0];
      if (activePassport && !input.replacementPassport) {
        throw new Error('active passport must be replaced during key rotation');
      }
      if (!activePassport && input.replacementPassport) {
        throw new Error('active passport changed during key rotation');
      }

      let reissuedPassportId: string | undefined;
      if (activePassport && input.replacementPassport) {
        if (input.replacementPassport.claims.agent_id !== input.agent.publicId) throw new Error('replacement passport agent mismatch');
        if (input.replacementPassport.claims.passport_version !== activePassport.passport_version + 1) {
          throw new Error('replacement passport version mismatch');
        }
        if (new Date(input.replacementPassport.claims.expires_at).getTime() !== activePassport.expires_at.getTime()) {
          throw new Error('replacement passport must preserve expiry');
        }
        await tx`
          update agent_passports set status = 'revoked' where id = ${activePassport.id}
        `;
        await tx`
          insert into passport_status_history (
            id, passport_id, from_status, to_status, reason_code, actor_subject, created_at
          ) values (
            ${uuidv7()}, ${activePassport.id}, 'active', 'revoked', 'agent_key_rotated',
            ${input.actorSubject}, ${input.completedAt}
          )
        `;
        const replacementInternalId = uuidv7();
        await tx`
          insert into agent_passports (
            id, passport_id, agent_id, purchase_id, passport_version, schema_version,
            claims, signature, status, issued_at, expires_at, created_at
          ) values (
            ${replacementInternalId}, ${input.replacementPassport.claims.passport_id}, ${input.agent.id},
            ${activePassport.purchase_id}, ${input.replacementPassport.claims.passport_version},
            ${input.replacementPassport.claims.schema_version},
            ${JSON.stringify(input.replacementPassport.claims)}::jsonb, ${input.replacementPassport.signature},
            ${input.replacementPassport.status}, ${new Date(input.replacementPassport.claims.issued_at)},
            ${new Date(input.replacementPassport.claims.expires_at)}, ${input.completedAt}
          )
        `;
        await tx`
          insert into passport_status_history (id, passport_id, to_status, reason_code, actor_subject, created_at)
          values (
            ${uuidv7()}, ${replacementInternalId}, 'active', 'reissued_after_key_rotation',
            ${input.actorSubject}, ${input.completedAt}
          )
        `;
        reissuedPassportId = input.replacementPassport.claims.passport_id;
      }

      await tx`
        update agent_key_rotations
        set completed_at = ${input.completedAt}
        where id = ${input.rotationId}
      `;
      await tx`
        insert into audit_events (id, actor_type, actor_subject, action, target_type, target_id, metadata, occurred_at)
        values (
          ${uuidv7()}, 'owner', ${input.actorSubject}, 'agent.key_rotated', 'agent', ${input.agent.publicId},
          ${JSON.stringify({
            rotation_id: input.rotationId,
            old_key_id: agentKeyId(rotation.old_public_key_pem),
            new_key_id: rotation.new_key_fingerprint,
            reissued_passport_id: reissuedPassportId ?? null,
          })}::jsonb,
          ${input.completedAt}
        )
      `;
      return {
        newKeyId: rotation.new_key_fingerprint,
        ...(reissuedPassportId ? { reissuedPassportId } : {}),
      };
    });
  }

  async emergencyRevokeKey(
    agent: AgentRecord,
    keyId: string,
    reasonCode: string,
    actorSubject: string,
    revokedAt: Date,
  ): Promise<EmergencyKeyRevocationResult> {
    return this.sql.begin(async (tx) => {
      const keys = await tx<KeyRow[]>`
        select id, public_key_pem, activated_at, revoked_at
        from agent_keys
        where agent_id = ${agent.id}
        order by activated_at desc, created_at desc
        for update
      `;
      const key = keys.find((item) => agentKeyId(item.public_key_pem) === keyId);
      if (!key) return { found: false, revoked: false, passportRevoked: false };
      if (key.revoked_at) return { found: true, revoked: false, passportRevoked: false };
      const wasCurrent = keys.filter((item) => !item.revoked_at)[0]?.id === key.id;
      await tx`update agent_keys set revoked_at = ${revokedAt} where id = ${key.id} and revoked_at is null`;

      let passportRevoked = false;
      if (wasCurrent) {
        await tx`
          update agents
          set status = 'suspended', version = version + 1, updated_at = ${revokedAt}
          where id = ${agent.id}
        `;
        const passports = await tx<{ id: string; passport_id: string }[]>`
          update agent_passports
          set status = 'revoked'
          where agent_id = ${agent.id} and status = 'active'
          returning id, passport_id
        `;
        for (const passport of passports) {
          await tx`
            insert into passport_status_history (
              id, passport_id, from_status, to_status, reason_code, actor_subject, created_at
            ) values (
              ${uuidv7()}, ${passport.id}, 'active', 'revoked', ${reasonCode}, ${actorSubject}, ${revokedAt}
            )
          `;
        }
        passportRevoked = passports.length > 0;
      }
      await tx`
        insert into audit_events (id, actor_type, actor_subject, action, target_type, target_id, metadata, occurred_at)
        values (
          ${uuidv7()}, 'owner', ${actorSubject}, 'agent.key_emergency_revoked', 'agent_key', ${keyId},
          ${JSON.stringify({ agent_id: agent.publicId, reason_code: reasonCode, suspended_agent: wasCurrent })}::jsonb,
          ${revokedAt}
        )
      `;
      return { found: true, revoked: true, passportRevoked };
    });
  }

  async close(): Promise<void> {
    await this.sql.end();
  }
}

function keyView(row: KeyRow): AgentKeyRecord {
  return {
    internalId: row.id,
    keyId: agentKeyId(row.public_key_pem),
    algorithm: 'Ed25519',
    publicKeyPem: row.public_key_pem,
    activatedAt: row.activated_at.toISOString(),
    ...(row.revoked_at ? { revokedAt: row.revoked_at.toISOString() } : {}),
  };
}

function rotationView(row: RotationRow): KeyRotationRecord {
  return {
    rotationId: row.rotation_id,
    agentId: row.agent_id,
    oldKey: {
      internalId: row.old_key_internal_id,
      keyId: agentKeyId(row.old_public_key_pem),
      algorithm: 'Ed25519',
      publicKeyPem: row.old_public_key_pem,
      activatedAt: row.old_activated_at.toISOString(),
      ...(row.old_revoked_at ? { revokedAt: row.old_revoked_at.toISOString() } : {}),
    },
    newKeyId: row.new_key_fingerprint,
    newPublicKeyPem: row.new_public_key_pem,
    challengeDigest: row.challenge_digest,
    expiresAt: row.expires_at.toISOString(),
    ...(row.completed_at ? { completedAt: row.completed_at.toISOString() } : {}),
    ...(row.cancelled_at ? { cancelledAt: row.cancelled_at.toISOString() } : {}),
  };
}
