import helmet from '@fastify/helmet';
import rateLimit from '@fastify/rate-limit';
import Fastify, { type FastifyReply, type FastifyRequest } from 'fastify';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { z } from 'zod';
import { createJwtAuthenticator, canManageOrganization, type AuthPrincipal, type Authenticator } from './auth.js';
import { loadConfig, type AppConfig } from './config.js';
import {
  agentControlMessage,
  assertEd25519PublicKey,
  canonicalize,
  challengeDigest,
  createChallenge,
  uuidv7,
  verifyAgentControlSignature,
  verifySandboxWebhook,
} from './crypto.js';
import { assertReferralAllowed, passportSaleEntries, PassportSigner, type AgentRecord } from './domain.js';
import { PostgresPlatformStore } from './db/store-postgres.js';
import type { PlatformStore } from './store.js';

export interface RuntimeConfig {
  nodeEnv: 'development' | 'test' | 'production';
  publicBaseUrl: string;
  passportPriceMinor: bigint;
  referralCommissionMinor: bigint;
  referralHoldDays: number;
  passportTtlDays: number;
  sandboxWebhookSecret: string;
}

export interface AppDependencies {
  store: PlatformStore;
  signer: PassportSigner;
  authenticate: Authenticator;
  config: RuntimeConfig;
}

const agentCreateSchema = z.object({
  organization_id: z.string().uuid().optional(),
  public_key_pem: z.string().min(40).max(16_000),
  endpoint: z.string().url(),
  capabilities: z.array(z.string().min(1).max(128)).max(50).default([]),
  referral_code: z.string().min(4).max(128).optional(),
});

const verifyControlSchema = z.object({
  challenge: z.string().min(20).max(256),
  signature: z.string().min(40).max(512),
});

const paymentEventSchema = z.object({
  event_id: z.string().min(1).max(255),
  type: z.literal('payment.succeeded'),
  purchase_id: z.string().min(1).max(255),
  agent_id: z.string().min(1).max(255),
  amount_minor: z.number().int().positive(),
  currency: z.literal('USD'),
});

export async function buildApp(deps: AppDependencies) {
  const app = Fastify({
    logger: {
      redact: [
        'req.headers.authorization',
        'req.headers.cookie',
        'req.headers.x-sandbox-signature',
        'req.body.public_key_pem',
        'req.body.signature',
      ],
    },
    bodyLimit: 1_048_576,
  });
  await app.register(helmet, { contentSecurityPolicy: false });
  await app.register(rateLimit, { max: 100, timeWindow: '1 minute' });

  app.addHook('onRequest', async (request, reply) => {
    const correlationId = request.headers['x-correlation-id']?.toString() ?? randomUUID();
    request.headers['x-correlation-id'] = correlationId;
    reply.header('x-correlation-id', correlationId);
  });

  app.setErrorHandler((error, _request, reply) => {
    app.log.error({ err: error }, 'request failed');
    if (reply.sent) return;
    void reply.code(500).send({ code: 'INTERNAL_ERROR' });
  });

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

  app.get('/healthz', async () => ({ status: 'ok' }));

  app.post('/v1/agents', async (request, reply) => {
    const principal = await principalOrReply(request, reply);
    if (!principal) return;
    const parsed = agentCreateSchema.safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ code: 'VALIDATION_ERROR', details: parsed.error.flatten() });
    if (parsed.data.organization_id && !canManageOrganization(principal, parsed.data.organization_id)) {
      return reply.code(403).send({ code: 'TENANT_ACCESS_DENIED' });
    }
    if (!isAllowedEndpoint(parsed.data.endpoint, deps.config.nodeEnv)) {
      return reply.code(400).send({ code: 'HTTPS_ENDPOINT_REQUIRED' });
    }
    try {
      assertEd25519PublicKey(parsed.data.public_key_pem);
    } catch {
      return reply.code(400).send({ code: 'INVALID_AGENT_PUBLIC_KEY', expected: 'Ed25519 SPKI PEM' });
    }

    let referrer: AgentRecord | undefined;
    if (parsed.data.referral_code) {
      referrer = (await deps.store.getAgentByReferralCode(parsed.data.referral_code)) ?? undefined;
      if (!referrer || referrer.status !== 'active') return reply.code(400).send({ code: 'INVALID_REFERRAL_CODE' });
    }

    const id = uuidv7();
    const publicId = `apn_${uuidv7().replaceAll('-', '')}`;
    try {
      assertReferralAllowed({ newAgentPublicId: publicId, ownerSubject: principal.subject, ...(referrer ? { referrer } : {}) });
    } catch {
      return reply.code(409).send({ code: 'SELF_REFERRAL_FORBIDDEN' });
    }
    const referralCode = `ref_${randomBytes(12).toString('base64url')}`;
    const agent: AgentRecord = {
      id,
      publicId,
      ownerSubject: principal.subject,
      publicKeyPem: parsed.data.public_key_pem,
      endpoint: parsed.data.endpoint,
      capabilities: [...new Set(parsed.data.capabilities)].sort(),
      verificationLevel: 0,
      status: 'pending',
      referralCode,
      version: 1,
      ...(parsed.data.organization_id ? { organizationId: parsed.data.organization_id } : {}),
      ...(referrer ? { referrerAgentId: referrer.id } : {}),
    };
    try {
      await deps.store.createAgent(agent);
    } catch (error) {
      request.log.warn({ err: error }, 'agent creation rejected');
      return reply.code(409).send({ code: 'AGENT_CREATION_REJECTED' });
    }
    return reply.code(201).send({ agent_id: publicId, verification_level: 0, referral_code: referralCode });
  });

  app.get('/v1/agents/:agentId', async (request, reply) => {
    const { agentId } = request.params as { agentId: string };
    const agent = await deps.store.getAgent(agentId);
    if (!agent) return reply.code(404).send({ code: 'AGENT_NOT_FOUND' });
    return {
      agent_id: agent.publicId,
      endpoint: agent.endpoint,
      capabilities: agent.capabilities,
      verification_level: agent.verificationLevel,
      status: agent.status,
    };
  });

  app.get('/v1/agents/:agentId/keys/current', async (request, reply) => {
    const { agentId } = request.params as { agentId: string };
    const agent = await deps.store.getAgent(agentId);
    if (!agent) return reply.code(404).send({ code: 'AGENT_NOT_FOUND' });
    return { agent_id: agent.publicId, key_id: 'primary', algorithm: 'Ed25519', public_key_pem: agent.publicKeyPem };
  });

  app.post('/v1/agents/:agentId/challenge', { config: { rateLimit: { max: 20, timeWindow: '1 minute' } } }, async (request, reply) => {
    const principal = await principalOrReply(request, reply);
    if (!principal) return;
    const { agentId } = request.params as { agentId: string };
    const agent = await deps.store.getAgent(agentId);
    if (!agent) return reply.code(404).send({ code: 'AGENT_NOT_FOUND' });
    if (!canManageAgent(principal, agent)) return reply.code(403).send({ code: 'TENANT_ACCESS_DENIED' });
    const challenge = createChallenge();
    const expiresAt = new Date(Date.now() + 120_000);
    await deps.store.createChallenge({ agentId: agent.id, digest: challengeDigest(challenge), expiresAt });
    return {
      challenge,
      signing_payload: agentControlMessage(agent.publicId, challenge),
      algorithm: 'Ed25519',
      expires_at: expiresAt.toISOString(),
    };
  });

  app.post('/v1/agents/:agentId/verify-control', { config: { rateLimit: { max: 20, timeWindow: '1 minute' } } }, async (request, reply) => {
    const principal = await principalOrReply(request, reply);
    if (!principal) return;
    const { agentId } = request.params as { agentId: string };
    const agent = await deps.store.getAgent(agentId);
    if (!agent) return reply.code(404).send({ code: 'AGENT_NOT_FOUND' });
    if (!canManageAgent(principal, agent)) return reply.code(403).send({ code: 'TENANT_ACCESS_DENIED' });
    const body = verifyControlSchema.safeParse(request.body);
    if (!body.success) return reply.code(400).send({ code: 'VALIDATION_ERROR' });
    if (!verifyAgentControlSignature(agent.publicKeyPem, agent.publicId, body.data.challenge, body.data.signature)) {
      return reply.code(401).send({ code: 'INVALID_AGENT_SIGNATURE' });
    }
    const confirmed = await deps.store.confirmAgentControl(agent, challengeDigest(body.data.challenge), new Date());
    if (!confirmed) return reply.code(401).send({ code: 'INVALID_EXPIRED_OR_REPLAYED_CHALLENGE' });
    return { verified: true, verification_level: 1 };
  });

  app.post('/v1/webhooks/payment-provider', { config: { rateLimit: { max: 300, timeWindow: '1 minute' } } }, async (request, reply) => {
    const timestampHeader = headerValue(request.headers['x-sandbox-timestamp']);
    const signatureHeader = headerValue(request.headers['x-sandbox-signature']);
    if (!verifySandboxWebhook(deps.config.sandboxWebhookSecret, timestampHeader, signatureHeader, request.body)) {
      return reply.code(401).send({ code: 'INVALID_WEBHOOK_SIGNATURE' });
    }
    const parsed = paymentEventSchema.safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ code: 'INVALID_EVENT' });
    if (BigInt(parsed.data.amount_minor) !== deps.config.passportPriceMinor) {
      return reply.code(409).send({ code: 'PAYMENT_AMOUNT_MISMATCH' });
    }
    const agent = await deps.store.getAgent(parsed.data.agent_id);
    if (!agent) return reply.code(404).send({ code: 'AGENT_NOT_FOUND' });
    if (agent.verificationLevel < 1 || !agent.controlVerifiedAt) return reply.code(409).send({ code: 'AGENT_CONTROL_NOT_VERIFIED' });

    const passport = deps.signer.issue(agent, deps.config.passportTtlDays);
    const ledgerEntries = passportSaleEntries(deps.config.passportPriceMinor, deps.config.referralCommissionMinor, agent.referrerAgentId);
    const result = await deps.store.finalizePassportPurchase({
      provider: 'sandbox',
      eventId: parsed.data.event_id,
      eventType: parsed.data.type,
      payloadHash: createHash('sha256').update(canonicalize(parsed.data)).digest('hex'),
      purchaseId: parsed.data.purchase_id,
      agent,
      passport,
      priceMinor: deps.config.passportPriceMinor,
      referralCommissionMinor: agent.referrerAgentId ? deps.config.referralCommissionMinor : 0n,
      holdUntil: new Date(Date.now() + deps.config.referralHoldDays * 86_400_000),
      ledgerEntries,
    });
    if (result.duplicate) return reply.code(200).send({ duplicate: true });
    return reply.code(201).send({ passport_id: passport.claims.passport_id, status: passport.status });
  });

  app.get('/v1/passports/:passportId', async (request, reply) => {
    const { passportId } = request.params as { passportId: string };
    const passport = await deps.store.getPassport(passportId);
    if (!passport) return reply.code(404).send({ code: 'PASSPORT_NOT_FOUND' });
    return { ...passport.claims, status: passport.status, signature: passport.signature };
  });

  app.get('/v1/passports/:passportId/status', async (request, reply) => {
    const { passportId } = request.params as { passportId: string };
    const passport = await deps.store.getPassport(passportId);
    if (!passport) return reply.code(404).send({ code: 'PASSPORT_NOT_FOUND' });
    return { passport_id: passportId, status: passport.status, expires_at: passport.claims.expires_at };
  });

  app.post('/v1/passports/:passportId/verify', async (request, reply) => {
    const { passportId } = request.params as { passportId: string };
    const passport = await deps.store.getPassport(passportId);
    if (!passport) return reply.code(404).send({ code: 'PASSPORT_NOT_FOUND' });
    return { valid: deps.signer.verify(passport), status: passport.status, agent_id: passport.claims.agent_id };
  });

  app.post('/v1/passports/:passportId/revoke', async (request, reply) => {
    const principal = await principalOrReply(request, reply);
    if (!principal) return;
    const { passportId } = request.params as { passportId: string };
    const passport = await deps.store.getPassport(passportId);
    if (!passport) return reply.code(404).send({ code: 'PASSPORT_NOT_FOUND' });
    const agent = await deps.store.getAgent(passport.claims.agent_id);
    if (!agent) return reply.code(409).send({ code: 'PASSPORT_AGENT_NOT_FOUND' });
    if (!canManageAgent(principal, agent)) return reply.code(403).send({ code: 'TENANT_ACCESS_DENIED' });
    const body = z.object({ reason_code: z.string().min(3).max(128) }).safeParse(request.body);
    if (!body.success) return reply.code(400).send({ code: 'VALIDATION_ERROR' });
    await deps.store.revokePassport(passportId, body.data.reason_code, principal.subject);
    return { revoked: true };
  });

  app.get('/.well-known/agent-card.json', async () => ({
    name: 'CREDALYX Agent Passport Network',
    description: 'Cryptographic agent identity, passport status and trust verification service.',
    version: '0.2.0',
    supportedInterfaces: [{
      url: `${deps.config.publicBaseUrl.replace(/\/$/, '')}/a2a`,
      protocolBinding: 'HTTP+JSON',
      protocolVersion: '1.0',
    }],
    capabilities: { streaming: false, extendedAgentCard: false },
    defaultInputModes: ['application/json'],
    defaultOutputModes: ['application/json'],
    skills: [{
      id: 'agent-passport-verification',
      name: 'Agent Passport Verification',
      description: 'Verify the signature and current status of a CREDALYX Agent Passport.',
      tags: ['identity', 'verification', 'agent-passport'],
      inputModes: ['application/json'],
      outputModes: ['application/json'],
    }],
  }));

  app.addHook('onClose', async () => deps.store.close());
  return app;
}

function headerValue(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

function isAllowedEndpoint(value: string, nodeEnv: RuntimeConfig['nodeEnv']): boolean {
  const url = new URL(value);
  if (url.protocol === 'https:') return true;
  return nodeEnv !== 'production' && url.protocol === 'http:' && ['localhost', '127.0.0.1', '::1'].includes(url.hostname);
}

function runtimeConfig(config: AppConfig): RuntimeConfig {
  return {
    nodeEnv: config.NODE_ENV,
    publicBaseUrl: config.PUBLIC_BASE_URL,
    passportPriceMinor: BigInt(config.PASSPORT_PRICE_MINOR),
    referralCommissionMinor: BigInt(config.REFERRAL_COMMISSION_MINOR),
    referralHoldDays: config.REFERRAL_HOLD_DAYS,
    passportTtlDays: config.PASSPORT_TTL_DAYS,
    sandboxWebhookSecret: config.SANDBOX_WEBHOOK_SECRET,
  };
}

async function startServer(): Promise<void> {
  const config = loadConfig();
  if (!config.DATABASE_URL) throw new Error('DATABASE_URL is required to start the API; in-memory storage is test-only');
  if (!config.AUTH_JWT_PUBLIC_KEY_PEM || !config.AUTH_JWT_ISSUER || !config.AUTH_JWT_AUDIENCE) {
    throw new Error('JWT auth configuration is required to start the API');
  }
  const signer = config.PASSPORT_ISSUER_PRIVATE_KEY_PEM && config.PASSPORT_ISSUER_PUBLIC_KEY_PEM
    ? new PassportSigner({
        privateKeyPem: config.PASSPORT_ISSUER_PRIVATE_KEY_PEM,
        publicKeyPem: config.PASSPORT_ISSUER_PUBLIC_KEY_PEM,
        issuer: config.PUBLIC_BASE_URL,
      })
    : PassportSigner.ephemeral(config.PUBLIC_BASE_URL);
  if (config.NODE_ENV === 'production' && (!config.PASSPORT_ISSUER_PRIVATE_KEY_PEM || !config.PASSPORT_ISSUER_PUBLIC_KEY_PEM)) {
    throw new Error('ephemeral issuer keys are forbidden in production');
  }
  const authenticate = await createJwtAuthenticator({
    publicKeyPem: config.AUTH_JWT_PUBLIC_KEY_PEM,
    algorithm: config.AUTH_JWT_ALG,
    issuer: config.AUTH_JWT_ISSUER,
    audience: config.AUTH_JWT_AUDIENCE,
  });
  const app = await buildApp({
    store: new PostgresPlatformStore(config.DATABASE_URL),
    signer,
    authenticate,
    config: runtimeConfig(config),
  });
  await app.listen({ host: '0.0.0.0', port: config.PORT });
}

if (process.env.NODE_ENV !== 'test' && import.meta.url === `file://${process.argv[1]}`) {
  await startServer();
}
