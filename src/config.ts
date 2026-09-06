import { z } from 'zod';

const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce.number().int().min(1).max(65535).default(3000),
  PUBLIC_BASE_URL: z.string().url().default('http://localhost:3000'),
  DATABASE_URL: z.string().min(1).optional(),
  PASSPORT_PRICE_MINOR: z.coerce.number().int().positive().default(200),
  REFERRAL_COMMISSION_MINOR: z.coerce.number().int().nonnegative().default(100),
  REFERRAL_HOLD_DAYS: z.coerce.number().int().min(0).max(180).default(30),
  PASSPORT_TTL_DAYS: z.coerce.number().int().min(1).max(365).default(30),
  SANDBOX_WEBHOOK_SECRET: z.string().min(32),
  PASSPORT_ISSUER_PRIVATE_KEY_PEM: z.string().min(40).optional(),
  PASSPORT_ISSUER_PUBLIC_KEY_PEM: z.string().min(40).optional(),
  AUTH_JWT_PUBLIC_KEY_PEM: z.string().min(40).optional(),
  AUTH_JWT_ALG: z.string().default('RS256'),
  AUTH_JWT_ISSUER: z.string().url().optional(),
  AUTH_JWT_AUDIENCE: z.string().min(1).optional(),
});

export type AppConfig = ReturnType<typeof loadConfig>;

export function loadConfig(env: NodeJS.ProcessEnv = process.env) {
  const parsed = envSchema.parse(env);
  if (parsed.REFERRAL_COMMISSION_MINOR >= parsed.PASSPORT_PRICE_MINOR) {
    throw new Error('REFERRAL_COMMISSION_MINOR must be lower than PASSPORT_PRICE_MINOR');
  }
  if (parsed.NODE_ENV === 'production') {
    if (!parsed.DATABASE_URL) throw new Error('DATABASE_URL is required in production');
    if (!parsed.PASSPORT_ISSUER_PRIVATE_KEY_PEM || !parsed.PASSPORT_ISSUER_PUBLIC_KEY_PEM) {
      throw new Error('stable passport issuer keys are required in production');
    }
    if (!parsed.AUTH_JWT_PUBLIC_KEY_PEM || !parsed.AUTH_JWT_ISSUER || !parsed.AUTH_JWT_AUDIENCE) {
      throw new Error('trusted JWT verification configuration is required in production');
    }
  }
  return parsed;
}
