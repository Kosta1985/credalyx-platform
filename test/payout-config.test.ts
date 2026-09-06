import assert from 'node:assert/strict';
import test from 'node:test';
import { loadConfig } from '../src/config.js';

const base = {
  NODE_ENV: 'test',
  SANDBOX_WEBHOOK_SECRET: '01234567890123456789012345678901',
  SANDBOX_PAYOUT_WEBHOOK_SECRET: '11234567890123456789012345678901',
};

test('managed payout provider selection fails closed until adapter exists', () => {
  assert.throws(() => loadConfig({ ...base, PAYOUT_PROVIDER_BACKEND: 'managed' }), /managed payout provider adapter is not configured/);
});

test('payout auto-approval ceiling cannot be below the minimum payout', () => {
  assert.throws(() => loadConfig({
    ...base,
    MIN_PAYOUT_MINOR: '2500',
    PAYOUT_AUTO_APPROVE_MAX_MINOR: '2499',
  }), /PAYOUT_AUTO_APPROVE_MAX_MINOR/);
});

test('production cannot run the sandbox payout provider', () => {
  assert.throws(() => loadConfig({
    ...base,
    NODE_ENV: 'production',
    DATABASE_URL: 'postgres://example.invalid/credalyx',
    PASSPORT_ISSUER_BACKEND: 'managed',
    PASSPORT_ISSUER_KEY_REFERENCE: 'kms://provider/key/version',
    PAYOUT_PROVIDER_BACKEND: 'sandbox',
    AUTH_JWT_PUBLIC_KEY_PEM: 'x'.repeat(80),
    AUTH_JWT_ISSUER: 'https://id.example',
    AUTH_JWT_AUDIENCE: 'credalyx-api',
  }), /production requires a managed payout provider backend/);
});
