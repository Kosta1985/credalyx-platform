import type { FastifyInstance } from 'fastify';
import type { PassportIssuerService } from './service.js';

export function registerIssuerRoutes(app: FastifyInstance, issuer: PassportIssuerService): void {
  app.get('/.well-known/agent-passport-issuer.json', async () => {
    const active = await issuer.getActiveKey();
    const base = issuer.issuer;
    return {
      issuer: base,
      credential_type: 'CREDALYX Agent Passport',
      schema_versions: ['1.0', '1.1'],
      signing_algorithms: ['EdDSA'],
      active_key_id: active.keyId,
      jwks_uri: `${base}/.well-known/jwks.json`,
      key_uri_template: `${base}/v1/issuer/keys/{key_id}`,
      status: 'operational',
    };
  });

  app.get('/.well-known/jwks.json', async () => issuer.jwks());

  app.get('/v1/issuer/keys/:keyId', async (request, reply) => {
    const { keyId } = request.params as { keyId: string };
    const key = await issuer.getKey(keyId);
    if (!key) return reply.code(404).send({ code: 'ISSUER_KEY_NOT_FOUND' });
    return {
      key_id: key.keyId,
      algorithm: key.algorithm,
      public_key_pem: key.publicKeyPem,
      public_jwk: key.publicJwk,
      status: key.status,
      provider: key.provider,
      activated_at: key.activatedAt,
      retired_at: key.retiredAt ?? null,
      revoked_at: key.revokedAt ?? null,
    };
  });
}
