import { createHash } from 'node:crypto';
import type { CheckoutRequest, CheckoutSession, PaymentProvider } from './provider.js';

export class SandboxPaymentProvider implements PaymentProvider {
  readonly name = 'sandbox';

  async createCheckoutSession(input: CheckoutRequest): Promise<CheckoutSession> {
    const digest = createHash('sha256')
      .update(`${input.agentPublicId}\n${input.idempotencyKey}\n${input.purchaseReference}`)
      .digest('hex')
      .slice(0, 32);
    const providerSessionId = `cs_sandbox_${digest}`;
    return {
      provider: this.name,
      providerSessionId,
      purchaseReference: input.purchaseReference,
      checkoutUrl: `https://checkout.sandbox.credalyx.invalid/session/${providerSessionId}`,
      amountMinor: input.amountMinor,
      currency: input.currency,
      expiresAt: new Date(Date.now() + 30 * 60_000),
    };
  }
}
