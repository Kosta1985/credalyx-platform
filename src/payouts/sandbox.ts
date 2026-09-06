import { createHash } from 'node:crypto';
import type {
  CreateProviderPayoutRequest,
  PayoutOnboardingRequest,
  PayoutOnboardingSession,
  PayoutProvider,
  ProviderPayout,
} from './provider.js';

/** No-money provider used only for development and automated tests. */
export class SandboxPayoutProvider implements PayoutProvider {
  readonly name = 'sandbox-payout';

  async createOnboardingSession(input: PayoutOnboardingRequest): Promise<PayoutOnboardingSession> {
    const accountDigest = digest(`${input.beneficiaryReference}\n${input.idempotencyKey}`);
    return {
      provider: this.name,
      providerAccountId: `acct_sandbox_${accountDigest.slice(0, 32)}`,
      onboardingUrl: `https://payouts.sandbox.credalyx.invalid/onboard/${accountDigest.slice(0, 40)}`,
      // Sandbox onboarding is immediately complete; production providers own the KYC/KYB flow.
      status: 'complete',
      expiresAt: new Date(Date.now() + 30 * 60_000),
    };
  }

  async createPayout(input: CreateProviderPayoutRequest): Promise<ProviderPayout> {
    const payoutDigest = digest(`${input.providerAccountId}\n${input.payoutReference}\n${input.idempotencyKey}`);
    return {
      provider: this.name,
      providerPayoutId: `po_sandbox_${payoutDigest.slice(0, 32)}`,
      payoutReference: input.payoutReference,
      amountMinor: input.amountMinor,
      currency: input.currency,
      // Completion/failure is delivered through the signed sandbox payout webhook.
      status: 'processing',
    };
  }
}

function digest(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}
