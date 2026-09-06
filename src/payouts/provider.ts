import type { Currency } from '../domain.js';

export type PayoutOnboardingStatus = 'pending' | 'complete' | 'restricted';
export type ProviderPayoutStatus = 'processing' | 'paid' | 'failed';

export interface PayoutOnboardingRequest {
  beneficiaryReference: string;
  idempotencyKey: string;
  returnUrl: string;
  refreshUrl: string;
}

export interface PayoutOnboardingSession {
  provider: string;
  providerAccountId: string;
  onboardingUrl: string;
  status: PayoutOnboardingStatus;
  expiresAt: Date;
}

export interface CreateProviderPayoutRequest {
  payoutReference: string;
  providerAccountId: string;
  amountMinor: bigint;
  currency: Currency;
  idempotencyKey: string;
}

export interface ProviderPayout {
  provider: string;
  providerPayoutId: string;
  payoutReference: string;
  amountMinor: bigint;
  currency: Currency;
  status: ProviderPayoutStatus;
}

export interface PayoutProvider {
  readonly name: string;
  createOnboardingSession(input: PayoutOnboardingRequest): Promise<PayoutOnboardingSession>;
  createPayout(input: CreateProviderPayoutRequest): Promise<ProviderPayout>;
}
