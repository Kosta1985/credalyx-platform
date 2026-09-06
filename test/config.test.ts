import assert from 'node:assert/strict';
import test from 'node:test';
import { loadConfig } from '../src/config.js';

const base = {
  NODE_ENV: 'test',
  SANDBOX_WEBHOOK_SECRET: '01234567890123456789012345678901',
};

test('local issuer PEM values must be configured as a pair', () => {
  assert.throws(() => loadConfig({
    ...base,
    PASSPORT_ISSUER_BACKEND: 'local-pem',
    PASSPORT_ISSUER_PRIVATE_KEY_PEM: 'x'.repeat(80),
  }), /configured together/);
});

test('managed issuer requires an opaque provider key reference and fails closed without an adapter', () => {
  assert.throws(() => loadConfig({
    ...base,
    PASSPORT_ISSUER_BACKEND: 'managed',
  }), /KEY_REFERENCE/);

  assert.throws(() => loadConfig({
    ...base,
    PASSPORT_ISSUER_BACKEND: 'managed',
    PASSPORT_ISSUER_KEY_REFERENCE: 'kms:\/\/provider\/key\/version',
  }), /adapter is not configured/);
});

test('production rejects local PEM issuer custody', () => {
  assert.throws(() => loadConfig({
    ...base,
    NODE_ENV: 'production',
    DATABASE_URL: 'postgres://example.invalid/credalyx',
    PASSPORT_ISSUER_BACKEND: 'local-pem',
    AUTH_JWT_PUBLIC_KEY_PEM: 'x'.repeat(80),
    AUTH_JWT_ISSUER: 'https://id.example',
    AUTH_JWT_AUDIENCE: 'credalyx-api',
  }), /production requires a managed/);
});
