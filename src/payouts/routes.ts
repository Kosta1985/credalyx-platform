import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { createHash } from 'node:crypto';
import { z } from 'zod';
import { canManageOrganization, type AuthPrincipal, type Authenticator } from '../auth.js';
import { canonicalize, verifySandboxWebhook } from '../crypto.js';
import type { AgentRecord } from '../domain.js';
import type { PlatformStore } from '../store.js';
import type { PayoutProvider } from './provider.js';
import { assessPayoutRisk } from './risk.js';
import type { PayoutAccountRecord, PayoutRecord, PayoutStore } from './store.js';

export interface PayoutRouteConfig {
  publicBaseUrl: string;
  minPayoutMinor: bigint;
  autoApproveMaxMinor: bigint;
  maxPayoutsPer24h: number;
  sandboxPayoutWebhookSecret: string;
}

export interface PayoutRouteDependencies {
  app: FastifyInstance;
  platform: PlatformStore;
  store: PayoutStore;
  provider: PayoutProvider;
  authenticate: Authenticator;
  config: PayoutRouteConfig;
}

const onboardingSchema = z.object({ agent_id: z.string().min(1).max(255) });
const createPayoutSchema = z.object({
  agent_id: z.string().min(1).max(255),
  amount_minor: z.string().regex(/^[1-9][0-9]{0,17}$/),
});
const payoutListSchema = z.object({
  agent_id: z.string().min(1).max(255),
  limit: z.coerce.number().int().min(1).max(100).default(50),
});
const payoutEventSchema = z.discriminatedUnion('type', [
  z.object({
    event_id: z.string().min(1).max(255),
    type: z.literal('payout.paid'),
    payout_id: z.string().min(1).max(255),
    provider_payout_id: z.string().min(1).max(255),
    amount_minor: z.string().regex(/^[1-9][0-9]{0,17}$/),
    currency: z.literal('USD'),
  }),
  z.object({
    event_id: z.string().min(1).max(255),
    type: z.literal('payout.failed'),
    payout_id: z.string().min(1).max(255),
    provider_payout_id: z.string().min(1).max(255),
    amount_minor: z.string().regex(/^[1-9][0-9]{0,17}$/),
    currency: z.literal('USD'),
    reason_code: z.string().min(3).max(128),
  }),
]);

export function registerPayoutRoutes(deps: PayoutRouteDependencies): void {
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
    return agent.organizationId
      ? canManageOrganization(principal, agent.organizationId)
      : principal.subject === agent.ownerSubject;
  }

  async function ownedAgent(request: FastifyRequest, reply: FastifyReply, publicId: string): Promise<AgentRecord | null> {
    const principal = await principalOrReply(request, reply);
    if (!principal) return null;
    const agent = await deps.platform.getAgent(publicId);
    if (!agent) {
      await reply.code(404).send({ code: 'AGENT_NOT_FOUND' });
      return null;
    }
    if (!canManageAgent(principal, agent)) {
      await reply.code(403).send({ code: 'TENANT_ACCESS_DENIED' });
      return null;
    }
    return agent;
  }

  async function submitReservedPayout(
    request: FastifyRequest,
    reply: FastifyReply,
    payout: PayoutRecord,
    account: PayoutAccountRecord,
    idempotencyKey: string,
  ): Promise<PayoutRecord | undefined> {
    if (payout.status !== 'pending') return payout;
    try {
      const providerPayout = await deps.provider.createPayout({
        payoutReference: payout.payoutReference,
        providerAccountId: account.providerAccountId,
        amountMinor: payout.amountMinor,
        currency: payout.currency,
        idempotencyKey,
      });
      return deps.store.markSubmitted(payout.payoutReference, providerPayout, new Date());
    } catch (error) {
      request.log.error({ err: error }, 'payout provider submission failed');
      const failed = await deps.store.failSubmission(payout.payoutReference, 'provider_submission_error', new Date());
      await reply.code(502).send({ code: 'PAYOUT_PROVIDER_SUBMISSION_FAILED', payout: serializePayout(failed) });
      return undefined;
    }
  }

  app.post('/v1/payouts/onboarding', async (request, reply) => {
    const parsed = onboardingSchema.safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ code: 'VALIDATION_ERROR' });
    const agent = await ownedAgent(request, reply, parsed.data.agent_id);
    if (!agent) return;
    if (agent.status !== 'active' || agent.verificationLevel < 1 || !agent.controlVerifiedAt) {
      return reply.code(409).send({ code: 'AGENT_NOT_ELIGIBLE_FOR_PAYOUTS' });
    }
    const clientKey = headerValue(request.headers['idempotency-key']);
    if (!clientKey || clientKey.length < 16 || clientKey.length > 128) {
      return reply.code(400).send({ code: 'IDEMPOTENCY_KEY_REQUIRED' });
    }
    const beneficiaryReference = agent.organizationId ? `org:${agent.organizationId}` : `owner:${agent.ownerSubject}`;
    const base = deps.config.publicBaseUrl.replace(/\/$/, '');
    const session = await deps.provider.createOnboardingSession({
      beneficiaryReference,
      idempotencyKey: namespaceKey(agent.id, clientKey, 'onboarding'),
      returnUrl: `${base}/payouts/onboarding/return`,
      refreshUrl: `${base}/payouts/onboarding/refresh`,
    });
    const account = await deps.store.upsertPayoutAccount(agent, session, new Date());
    return reply.code(201).send({
      provider: account.provider,
      onboarding_status: account.onboardingStatus,
      onboarding_url: account.onboardingUrl ?? null,
      expires_at: account.onboardingExpiresAt?.toISOString() ?? null,
    });
  });

  app.get('/v1/payouts/account', async (request, reply) => {
    const query = z.object({ agent_id: z.string().min(1).max(255) }).safeParse(request.query);
    if (!query.success) return reply.code(400).send({ code: 'VALIDATION_ERROR' });
    const agent = await ownedAgent(request, reply, query.data.agent_id);
    if (!agent) return;
    const account = await deps.store.getPayoutAccount(agent, deps.provider.name);
    if (!account) return reply.code(404).send({ code: 'PAYOUT_ACCOUNT_NOT_FOUND' });
    return {
      provider: account.provider,
      onboarding_status: account.onboardingStatus,
      onboarding_url: account.onboardingUrl ?? null,
      expires_at: account.onboardingExpiresAt?.toISOString() ?? null,
    };
  });

  app.post('/v1/payouts', async (request, reply) => {
    const parsed = createPayoutSchema.safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ code: 'VALIDATION_ERROR' });
    const agent = await ownedAgent(request, reply, parsed.data.agent_id);
    if (!agent) return;
    const amountMinor = BigInt(parsed.data.amount_minor);
    const clientKey = headerValue(request.headers['idempotency-key']);
    if (!clientKey || clientKey.length < 16 || clientKey.length > 128) {
      return reply.code(400).send({ code: 'IDEMPOTENCY_KEY_REQUIRED' });
    }
    const idempotencyKey = namespaceKey(agent.id, clientKey, 'payout');
    const payoutReference = createPayoutReference(agent.id, clientKey);

    // Resolve the deterministic idempotent result before evaluating the current
    // risk context. A retry must never be rejected merely because its original
    // payout is now the open payout that the risk engine observes.
    const existing = await deps.store.getPayout(payoutReference);
    if (existing) {
      if (existing.agentId !== agent.id || existing.amountMinor !== amountMinor || existing.currency !== 'USD') {
        return reply.code(409).send({ code: 'PAYOUT_IDEMPOTENCY_CONFLICT' });
      }
      const account = await deps.store.getPayoutAccount(agent, deps.provider.name);
      if (existing.status === 'pending') {
        if (!account || account.onboardingStatus !== 'complete') {
          return reply.code(409).send({ code: 'PAYOUT_ACCOUNT_UNAVAILABLE_FOR_RETRY' });
        }
        const submitted = await submitReservedPayout(request, reply, existing, account, idempotencyKey);
        if (!submitted) return;
        return reply.code(200).send({ payout: serializePayout(submitted) });
      }
      return reply.code(200).send({ payout: serializePayout(existing) });
    }

    const account = await deps.store.getPayoutAccount(agent, deps.provider.name);
    const context = await deps.store.getRiskContext(agent.id, new Date());
    const assessment = assessPayoutRisk({
      agentStatus: agent.status,
      verificationLevel: agent.verificationLevel,
      onboardingStatus: account?.onboardingStatus ?? 'pending',
      amountMinor,
      availableMinor: context.availableMinor,
      debtMinor: context.debtMinor,
      minPayoutMinor: deps.config.minPayoutMinor,
      openPayoutCount: context.openPayoutCount,
      payoutCount24h: context.payoutCount24h,
      reversalMinor30d: context.reversalMinor30d,
      autoApproveMaxMinor: deps.config.autoApproveMaxMinor,
      maxPayoutsPer24h: deps.config.maxPayoutsPer24h,
    });
    await deps.store.recordRiskAssessment(agent.id, idempotencyKey, amountMinor, 'USD', assessment, new Date());
    if (!account) return reply.code(409).send({ code: 'PAYOUT_ONBOARDING_REQUIRED', risk: assessment });
    if (assessment.decision === 'deny') return reply.code(409).send({ code: 'PAYOUT_DENIED', risk: assessment });
    if (assessment.decision === 'review') return reply.code(409).send({ code: 'PAYOUT_REQUIRES_REVIEW', risk: assessment });

    let reservation;
    try {
      reservation = await deps.store.reservePayout({
        agent,
        payoutAccount: account,
        payoutReference,
        idempotencyKey,
        amountMinor,
        currency: 'USD',
        assessment,
        reservedAt: new Date(),
      });
    } catch (error) {
      request.log.warn({ err: error }, 'payout reservation rejected');
      return reply.code(409).send({ code: 'PAYOUT_RESERVATION_REJECTED' });
    }

    const submitted = await submitReservedPayout(request, reply, reservation.payout, account, idempotencyKey);
    if (!submitted) return;
    return reply.code(reservation.duplicate ? 200 : 201).send({ payout: serializePayout(submitted) });
  });

  app.get('/v1/payouts/summary', async (request, reply) => {
    const query = z.object({ agent_id: z.string().min(1).max(255) }).safeParse(request.query);
    if (!query.success) return reply.code(400).send({ code: 'VALIDATION_ERROR' });
    const agent = await ownedAgent(request, reply, query.data.agent_id);
    if (!agent) return;
    const summary = await deps.store.getPayoutSummary(agent.id);
    return {
      currency: 'USD',
      reserved_minor: summary.reservedMinor.toString(),
      paid_minor: summary.paidMinor.toString(),
      open_payout_count: summary.openPayoutCount,
    };
  });

  app.get('/v1/payouts', async (request, reply) => {
    const query = payoutListSchema.safeParse(request.query);
    if (!query.success) return reply.code(400).send({ code: 'VALIDATION_ERROR' });
    const agent = await ownedAgent(request, reply, query.data.agent_id);
    if (!agent) return;
    const payouts = await deps.store.listPayouts(agent.id, query.data.limit);
    return { data: payouts.map(serializePayout), has_more: payouts.length === query.data.limit };
  });

  app.get('/v1/payouts/:payoutId', async (request, reply) => {
    const { payoutId } = request.params as { payoutId: string };
    const query = z.object({ agent_id: z.string().min(1).max(255) }).safeParse(request.query);
    if (!query.success) return reply.code(400).send({ code: 'VALIDATION_ERROR' });
    const agent = await ownedAgent(request, reply, query.data.agent_id);
    if (!agent) return;
    const payout = await deps.store.getPayout(payoutId);
    if (!payout || payout.agentId !== agent.id) return reply.code(404).send({ code: 'PAYOUT_NOT_FOUND' });
    return { payout: serializePayout(payout) };
  });

  app.post('/v1/webhooks/payout-provider', { config: { rateLimit: { max: 300, timeWindow: '1 minute' } } }, async (request, reply) => {
    const timestamp = headerValue(request.headers['x-sandbox-timestamp']);
    const signature = headerValue(request.headers['x-sandbox-signature']);
    if (!verifySandboxWebhook(deps.config.sandboxPayoutWebhookSecret, timestamp, signature, request.body)) {
      return reply.code(401).send({ code: 'INVALID_WEBHOOK_SIGNATURE' });
    }
    const parsed = payoutEventSchema.safeParse(request.body);
    if (!parsed.success) return reply.code(400).send({ code: 'INVALID_EVENT' });
    const event = parsed.data;
    const result = await deps.store.applyProviderEvent({
      provider: deps.provider.name,
      eventId: event.event_id,
      eventType: event.type,
      payloadHash: createHash('sha256').update(canonicalize(event)).digest('hex'),
      payoutReference: event.payout_id,
      providerPayoutId: event.provider_payout_id,
      amountMinor: BigInt(event.amount_minor),
      currency: event.currency,
      ...(event.type === 'payout.failed' ? { failureReason: event.reason_code } : {}),
      occurredAt: new Date(),
    });
    if (!result.found) return reply.code(404).send({ code: 'PAYOUT_NOT_FOUND' });
    return reply.code(200).send({ duplicate: result.duplicate, status: result.status });
  });
}

function namespaceKey(agentId: string, clientKey: string, purpose: string): string {
  return `${purpose}:${agentId}:${clientKey}`;
}

function createPayoutReference(agentId: string, clientKey: string): string {
  return `pay_${createHash('sha256').update(`${agentId}\n${clientKey}`).digest('hex').slice(0, 40)}`;
}

function headerValue(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

function serializePayout(payout: PayoutRecord) {
  return {
    payout_id: payout.payoutReference,
    provider: payout.provider,
    provider_payout_id: payout.providerPayoutId ?? null,
    amount_minor: payout.amountMinor.toString(),
    currency: payout.currency,
    status: payout.status,
    risk_decision: payout.riskDecision,
    risk_score: payout.riskScore,
    reserved_at: payout.reservedAt.toISOString(),
    submitted_at: payout.submittedAt?.toISOString() ?? null,
    processed_at: payout.processedAt?.toISOString() ?? null,
    failure_reason: payout.failureReason ?? null,
  };
}
