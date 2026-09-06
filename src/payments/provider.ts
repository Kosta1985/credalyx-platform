import type { Currency } from '../domain.js';

export interface CheckoutRequest {
  purchaseReference: string;
  agentPublicId: string;
  amountMinor: bigint;
  currency: Currency;
  idempotencyKey: string;
  successUrl: string;
  cancelUrl: string;
}

export interface CheckoutSession {
  provider: string;
  providerSessionId: string;
  purchaseReference: string;
  checkoutUrl: string;
  amountMinor: bigint;
  currency: Currency;
  expiresAt: Date;
}

export interface PaymentProvider {
  readonly name: string;
  createCheckoutSession(input: CheckoutRequest): Promise<CheckoutSession>;
}
