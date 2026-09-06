import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { z } from 'zod';
import { canManageOrganization, type AuthPrincipal, type Authenticator } from '../auth.js';
import {
  agentKeyId,
  assertEd25519PublicKey,
  challengeDigest,
  keyRotationMessage,
  verifyEd25519Signature,
} from '../crypto.js';
import type { AgentRecord, SignedPassport } from '../domain.js';
import type { PlatformStore } from '../store.js';
import type { CredentialLifecycleStore } from './store.js';

export interface CredentialRouteDependencies {
  app: FastifyInstance;
  store: PlatformStore;
  credentials: CredentialLifecycleStore;
  issuePassport: (
    agent: AgentRecord,
    ttlDays: number,
    passportVersion: number,
    preserveExpiresAt?: Date,
  ) => Promise<SignedPassport>;
  authenticate: Authenticator;
  passportTtlDays: number;
}

const startRotationSchema = z.object({
  new_public_key_pem: z.string().min(40).max(16_000),
});

const completeRotationSchema = z.object({
  rotation_id: z.string().uuid(),
  challenge: z.string().min(20).max(256),
  current_key_signature: z.string().min(40).max(512),
  new_key_signature: z.string().min(40).max(512),
});

const emergencyRevokeSchema = z.object({
  reason_code: z.string().min(3).max(128),
});

export function registerCredentialRoutes(deps: CredentialRouteDependencies): void {
  const { app } = deps;

  async function principalOrReply(request: FastifyRequest, reply: FastifyReply): Promise<AuthPrincipal | null> {
    try {
      return await deps.authenticate(request);
    } catch {
      await reply.code(401).send({ code: 'AUTH_REQUIRED' });
      return null;
    }
  }

  function canManageAgent(principal: AuthPrincipal, agent: AgentRecord): boolean {
    if (agent.organizationId) return canManageOrganization(principal, agent.organizationId);
    return principal.subject === agent.ownerSubject;
  }

  app.get('/v1/agents/:agentId/keys/:keyId', async (request, reply) => {
    const { agentId, keyId } = request.params as { agentId: string; keyId: string };
    const agent = await deps.store.getAgent(agentId);
    if (!agent) return reply.code(404).send({ code: 'AGENT_NOT_FOUND' });
    const key = await deps.credentials.getKey(agent, keyId);
    if (!key) return reply.code(404).send({ code: 'AGENT_KEY_NOT_FOUND' });
    return {
      agent_id: agent.publicId,
      key_id: key.keyId,
      algorithm: key.algorithm,
      public_key_pem: key.publicKeyPem,
      activated_at: key.activatedAt,
      revoked_at: key.revokedAt ?? null,
      active: !key.revokedAt,
    };
  });

  app.post('/v1/agents/:agentId/keys/rotation-challenge', {
    config: { rateLimit: { max: 10, timeWindow: '1 minute' } },
  }, async (request, reply) => {
    const principal = await principalOrReply(request, reply);
    if (!principal) return;
    const { agentId } = request.params as { agentId: string };
    const agent = await deps.store.getAgent(agentId);
    if (!agent) return reply.code(404).send({ code: 'AGENT_NOT_FOUND' });
    if (!canManageAgent(principal, agent)) return reply.code(403).send({ code: 'TENANT_ACCESS_DENIED' });
    if (agent.status === 'suspended' || agent.status === 'revoked') {
      return reply.code(409).send({ code: 'AGENT_NOT_ELIGIBLE_FOR_KEY_ROTATION', status: agent.status });
    }
    const parsed = startRotationSchema.safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ code: 'VALIDATION_ERROR', details: parsed.error.flatten() });
    try {
      assertEd25519PublicKey(parsed.data.new_public_key_pem);
      const rotation = await deps.credentials.startKeyRotation(
        agent,
        parsed.data.new_public_key_pem,
        new Date(),
        120_000,
      );
      const signingPayload = keyRotationMessage({
        agentPublicId: agent.publicId,
        rotationId: rotation.rotationId,
        oldKeyId: rotation.oldKey.keyId,
        newKeyId: rotation.newKeyId,
        challenge: rotation.challenge,
      });
      return reply.code(201).send({
        rotation_id: rotation.rotationId,
        challenge: rotation.challenge,
        signing_payload: signingPayload,
        old_key_id: rotation.oldKey.keyId,
        new_key_id: rotation.newKeyId,
        algorithm: 'Ed25519',
        required_signatures: ['current_key', 'new_key'],
        expires_at: rotation.expiresAt,
      });
    } catch (error) {
      request.log.warn({ err: error }, 'key rotation challenge rejected');
      return reply.code(409).send({ code: 'KEY_ROTATION_REJECTED' });
    }
  });

  app.post('/v1/agents/:agentId/keys/rotation-complete', {
    config: { rateLimit: { max: 10, timeWindow: '1 minute' } },
  }, async (request, reply) => {
    const principal = await principalOrReply(request, reply);
    if (!principal) return;
    const { agentId } = request.params as { agentId: string };
    const agent = await deps.store.getAgent(agentId);
    if (!agent) return reply.code(404).send({ code: 'AGENT_NOT_FOUND' });
    if (!canManageAgent(principal, agent)) return reply.code(403).send({ code: 'TENANT_ACCESS_DENIED' });
    if (agent.status === 'suspended' || agent.status === 'revoked') {
      return reply.code(409).send({ code: 'AGENT_NOT_ELIGIBLE_FOR_KEY_ROTATION', status: agent.status });
    }
    const parsed = completeRotationSchema.safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ code: 'VALIDATION_ERROR', details: parsed.error.flatten() });
    const rotation = await deps.credentials.getKeyRotation(agent, parsed.data.rotation_id);
    if (!rotation) return reply.code(404).send({ code: 'KEY_ROTATION_NOT_FOUND' });
    if (rotation.completedAt || rotation.cancelledAt) return reply.code(409).send({ code: 'KEY_ROTATION_NOT_PENDING' });
    if (Date.parse(rotation.expiresAt) <= Date.now()) return reply.code(401).send({ code: 'KEY_ROTATION_EXPIRED' });
    if (challengeDigest(parsed.data.challenge) !== rotation.challengeDigest) {
      return reply.code(401).send({ code: 'KEY_ROTATION_CHALLENGE_MISMATCH' });
    }
    const signingPayload = keyRotationMessage({
      agentPublicId: agent.publicId,
      rotationId: rotation.rotationId,
      oldKeyId: rotation.oldKey.keyId,
      newKeyId: rotation.newKeyId,
      challenge: parsed.data.challenge,
    });
    if (!verifyEd25519Signature(rotation.oldKey.publicKeyPem, signingPayload, parsed.data.current_key_signature)) {
      return reply.code(401).send({ code: 'INVALID_CURRENT_KEY_SIGNATURE' });
    }
    if (!verifyEd25519Signature(rotation.newPublicKeyPem, signingPayload, parsed.data.new_key_signature)) {
      return reply.code(401).send({ code: 'INVALID_NEW_KEY_SIGNATURE' });
    }

    const activePassport = await deps.store.getActivePassportForAgent(agent.id);
    let replacementPassport: SignedPassport | undefined;
    if (activePassport) {
      const currentVersion = activePassport.claims.passport_version ?? 1;
      replacementPassport = await deps.issuePassport(
        { ...agent, publicKeyPem: rotation.newPublicKeyPem },
        deps.passportTtlDays,
        currentVersion + 1,
        new Date(activePassport.claims.expires_at),
      );
    }
    try {
      const result = await deps.credentials.completeKeyRotation({
        agent,
        rotationId: rotation.rotationId,
        challengeDigest: rotation.challengeDigest,
        completedAt: new Date(),
        actorSubject: principal.subject,
        ...(replacementPassport ? { replacementPassport } : {}),
      });
      return {
        rotated: true,
        agent_id: agent.publicId,
        old_key_id: rotation.oldKey.keyId,
        new_key_id: result.newKeyId,
        reissued_passport_id: result.reissuedPassportId ?? null,
      };
    } catch (error) {
      request.log.warn({ err: error }, 'key rotation completion rejected');
      return reply.code(409).send({ code: 'KEY_ROTATION_COMPLETION_REJECTED' });
    }
  });

  app.post('/v1/agents/:agentId/keys/:keyId/revoke', {
    config: { rateLimit: { max: 10, timeWindow: '1 minute' } },
  }, async (request, reply) => {
    const principal = await principalOrReply(request, reply);
    if (!principal) return;
    const { agentId, keyId } = request.params as { agentId: string; keyId: string };
    const agent = await deps.store.getAgent(agentId);
    if (!agent) return reply.code(404).send({ code: 'AGENT_NOT_FOUND' });
    if (!canManageAgent(principal, agent)) return reply.code(403).send({ code: 'TENANT_ACCESS_DENIED' });
    const parsed = emergencyRevokeSchema.safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ code: 'VALIDATION_ERROR', details: parsed.error.flatten() });
    const key = await deps.credentials.getKey(agent, keyId);
    if (!key) return reply.code(404).send({ code: 'AGENT_KEY_NOT_FOUND' });
    const result = await deps.credentials.emergencyRevokeKey(
      agent,
      key.keyId,
      parsed.data.reason_code,
      principal.subject,
      new Date(),
    );
    if (!result.found) return reply.code(404).send({ code: 'AGENT_KEY_NOT_FOUND' });
    return {
      revoked: result.revoked,
      key_id: key.keyId,
      agent_suspended: !key.revokedAt && result.revoked,
      passport_revoked: result.passportRevoked,
    };
  });
}

export function currentKeyId(agent: AgentRecord): string {
  return agentKeyId(agent.publicKeyPem);
}
