import { createJwtAuthenticator } from './auth.js';
import { loadConfig } from './config.js';
import { PostgresCredentialLifecycleStore } from './credentials/store-postgres.js';
import { PostgresLifecyclePlatformStore } from './db/store-postgres-lifecycle.js';
import { LocalEd25519IssuerBackend } from './issuer/backend.js';
import { PassportIssuerService } from './issuer/service.js';
import { PostgresIssuerKeyRegistryStore } from './issuer/store-postgres.js';
import { SandboxPaymentProvider } from './payments/sandbox.js';
import { registerPayoutRoutes } from './payouts/routes.js';
import { SandboxPayoutProvider } from './payouts/sandbox.js';
import { PostgresPayoutStore } from './payouts/store-postgres.js';
import { buildApp } from './server.js';

async function start(): Promise<void> {
  const config = loadConfig();
  if (!config.DATABASE_URL) throw new Error('DATABASE_URL is required to start the API');
  if (!config.AUTH_JWT_PUBLIC_KEY_PEM || !config.AUTH_JWT_ISSUER || !config.AUTH_JWT_AUDIENCE) {
    throw new Error('JWT auth configuration is required to start the API');
  }
  // loadConfig already rejects unavailable managed adapters. This runtime only
  // composes the explicitly development/test local issuer + sandbox providers.
  if (config.NODE_ENV === 'production') {
    throw new Error('production provider adapters are not configured in this build');
  }

  const issuerBackend = config.PASSPORT_ISSUER_PRIVATE_KEY_PEM && config.PASSPORT_ISSUER_PUBLIC_KEY_PEM
    ? LocalEd25519IssuerBackend.fromPem({
        privateKeyPem: config.PASSPORT_ISSUER_PRIVATE_KEY_PEM,
        publicKeyPem: config.PASSPORT_ISSUER_PUBLIC_KEY_PEM,
        providerKeyReference: 'env:PASSPORT_ISSUER_PRIVATE_KEY_PEM',
      })
    : LocalEd25519IssuerBackend.ephemeral();
  const issuer = new PassportIssuerService(
    config.PUBLIC_BASE_URL,
    issuerBackend,
    new PostgresIssuerKeyRegistryStore(config.DATABASE_URL),
  );
  await issuer.initialize();

  const authenticate = await createJwtAuthenticator({
    publicKeyPem: config.AUTH_JWT_PUBLIC_KEY_PEM,
    algorithm: config.AUTH_JWT_ALG,
    issuer: config.AUTH_JWT_ISSUER,
    audience: config.AUTH_JWT_AUDIENCE,
  });
  const platformStore = new PostgresLifecyclePlatformStore(config.DATABASE_URL);
  const credentialStore = new PostgresCredentialLifecycleStore(config.DATABASE_URL);
  const app = await buildApp({
    store: platformStore,
    credentials: credentialStore,
    issuer,
    authenticate,
    paymentProvider: new SandboxPaymentProvider(),
    config: {
      nodeEnv: config.NODE_ENV,
      publicBaseUrl: config.PUBLIC_BASE_URL,
      passportPriceMinor: BigInt(config.PASSPORT_PRICE_MINOR),
      referralCommissionMinor: BigInt(config.REFERRAL_COMMISSION_MINOR),
      referralHoldDays: config.REFERRAL_HOLD_DAYS,
      minPayoutMinor: BigInt(config.MIN_PAYOUT_MINOR),
      passportTtlDays: config.PASSPORT_TTL_DAYS,
      sandboxWebhookSecret: config.SANDBOX_WEBHOOK_SECRET,
    },
  });

  const payoutStore = new PostgresPayoutStore(config.DATABASE_URL);
  const payoutProvider = new SandboxPayoutProvider();
  registerPayoutRoutes({
    app,
    platform: platformStore,
    store: payoutStore,
    provider: payoutProvider,
    authenticate,
    config: {
      publicBaseUrl: config.PUBLIC_BASE_URL,
      minPayoutMinor: BigInt(config.MIN_PAYOUT_MINOR),
      autoApproveMaxMinor: BigInt(config.PAYOUT_AUTO_APPROVE_MAX_MINOR),
      maxPayoutsPer24h: config.PAYOUT_MAX_PER_24H,
      sandboxPayoutWebhookSecret: config.SANDBOX_PAYOUT_WEBHOOK_SECRET,
    },
  });
  app.addHook('onClose', async () => payoutStore.close());

  await app.listen({ host: '0.0.0.0', port: config.PORT });
}

await start();
