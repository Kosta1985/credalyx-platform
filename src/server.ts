import Fastify from 'fastify';
import rateLimit from '@fastify/rate-limit';
import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import { ChallengeService, Ledger, PassportSigner, assertReferralAllowed, recordPassportSale, type AgentRecord, type SignedPassport } from './domain.js';

const app = Fastify({ logger: { redact: ['req.headers.authorization', 'req.headers.cookie'] } });
await app.register(rateLimit, { max: 100, timeWindow: '1 minute' });

const agents = new Map<string, AgentRecord>();
const passports = new Map<string, SignedPassport>();
const challenges = new ChallengeService();
const ledger = new Ledger();
const signer = new PassportSigner();
const processedPaymentEvents = new Set<string>();

const agentCreateSchema = z.object({
  ownerId: z.string().min(1),
  organizationId: z.string().min(1).optional(),
  publicKeyPem: z.string().min(20),
  endpoint: z.string().url().startsWith('https://'),
  capabilities: z.array(z.string().min(1)).max(50).default([]),
  referrerAgentId: z.string().optional(),
});

app.addHook('onRequest', async (request, reply) => {
  const correlationId = request.headers['x-correlation-id']?.toString() ?? randomUUID();
  reply.header('x-correlation-id', correlationId);
});

app.get('/healthz', async () => ({ status: 'ok' }));

app.post('/v1/agents', async (request, reply) => {
  const parsed = agentCreateSchema.safeParse(request.body);
  if (!parsed.success) return reply.code(400).send({ code: 'VALIDATION_ERROR', details: parsed.error.flatten() });

  const id = randomUUID();
  assertReferralAllowed(id, parsed.data.referrerAgentId);
  const agent: AgentRecord = {
    id,
    publicId: `apn_${randomUUID().replaceAll('-', '')}`,
    ownerId: parsed.data.ownerId,
    publicKeyPem: parsed.data.publicKeyPem,
    endpoint: parsed.data.endpoint,
    capabilities: parsed.data.capabilities,
    verificationLevel: 0,
    ...(parsed.data.organizationId ? { organizationId: parsed.data.organizationId } : {}),
    ...(parsed.data.referrerAgentId ? { referrerAgentId: parsed.data.referrerAgentId } : {}),
  };
  agents.set(agent.publicId, agent);
  return reply.code(201).send({ agent_id: agent.publicId, verification_level: 0 });
});

app.get('/v1/agents/:agentId', async (request, reply) => {
  const { agentId } = request.params as { agentId: string };
  const agent = agents.get(agentId);
  if (!agent) return reply.code(404).send({ code: 'AGENT_NOT_FOUND' });
  return { agent_id: agent.publicId, endpoint: agent.endpoint, capabilities: agent.capabilities, verification_level: agent.verificationLevel };
});

app.post('/v1/agents/:agentId/challenge', async (request, reply) => {
  const { agentId } = request.params as { agentId: string };
  const agent = agents.get(agentId);
  if (!agent) return reply.code(404).send({ code: 'AGENT_NOT_FOUND' });
  return { challenge: challenges.create(agent.id), expires_in_seconds: 120 };
});

app.post('/v1/agents/:agentId/verify-control', async (request, reply) => {
  const { agentId } = request.params as { agentId: string };
  const agent = agents.get(agentId);
  if (!agent) return reply.code(404).send({ code: 'AGENT_NOT_FOUND' });
  const body = z.object({ challenge: z.string().min(20) }).safeParse(request.body);
  if (!body.success) return reply.code(400).send({ code: 'VALIDATION_ERROR' });
  if (!challenges.consume(agent.id, body.data.challenge)) return reply.code(401).send({ code: 'INVALID_OR_REPLAYED_CHALLENGE' });

  // MVP seam: cryptographic signature verification is the next adapter step; challenge replay protection is already enforced.
  agent.verificationLevel = 1;
  agent.controlVerifiedAt = new Date().toISOString();
  return { verified: true, verification_level: 1 };
});

app.post('/v1/webhooks/payment-provider', async (request, reply) => {
  const signature = request.headers['x-sandbox-signature'];
  if (signature !== process.env.SANDBOX_WEBHOOK_SECRET) return reply.code(401).send({ code: 'INVALID_WEBHOOK_SIGNATURE' });

  const parsed = z.object({
    event_id: z.string().min(1),
    type: z.literal('payment.succeeded'),
    purchase_id: z.string().min(1),
    agent_id: z.string().min(1),
    amount_minor: z.literal(200),
  }).safeParse(request.body);
  if (!parsed.success) return reply.code(400).send({ code: 'INVALID_EVENT' });
  if (processedPaymentEvents.has(parsed.data.event_id)) return reply.code(200).send({ duplicate: true });

  const agent = agents.get(parsed.data.agent_id);
  if (!agent) return reply.code(404).send({ code: 'AGENT_NOT_FOUND' });
  if (agent.verificationLevel < 1) return reply.code(409).send({ code: 'AGENT_CONTROL_NOT_VERIFIED' });

  const passport = signer.issue(agent);
  passports.set(passport.claims.passport_id, passport);
  recordPassportSale(ledger, parsed.data.purchase_id, 200n, 100n, Boolean(agent.referrerAgentId));
  processedPaymentEvents.add(parsed.data.event_id);
  return reply.code(201).send({ passport_id: passport.claims.passport_id, status: passport.status });
});

app.get('/v1/passports/:passportId', async (request, reply) => {
  const { passportId } = request.params as { passportId: string };
  const passport = passports.get(passportId);
  if (!passport) return reply.code(404).send({ code: 'PASSPORT_NOT_FOUND' });
  return { ...passport.claims, status: passport.status };
});

app.post('/v1/passports/:passportId/verify', async (request, reply) => {
  const { passportId } = request.params as { passportId: string };
  const passport = passports.get(passportId);
  if (!passport) return reply.code(404).send({ code: 'PASSPORT_NOT_FOUND' });
  return { valid: signer.verify(passport), status: passport.status };
});

app.post('/v1/passports/:passportId/revoke', async (request, reply) => {
  const { passportId } = request.params as { passportId: string };
  const passport = passports.get(passportId);
  if (!passport) return reply.code(404).send({ code: 'PASSPORT_NOT_FOUND' });
  passport.status = 'revoked';
  return { revoked: true };
});

app.get('/.well-known/agent-card.json', async () => ({
  name: 'CREDALYX Agent Passport Network',
  description: 'Agent identity, trust and passport verification service',
  protocolVersion: '0.1-sandbox',
  url: 'https://credalyx.example/a2a',
  capabilities: { agentPassportVerification: true },
}));

const port = Number(process.env.PORT ?? 3000);
if (process.env.NODE_ENV !== 'test') {
  await app.listen({ host: '0.0.0.0', port });
}

export { app, ledger, signer };
