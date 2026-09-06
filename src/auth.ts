import { importSPKI, jwtVerify } from 'jose';
import type { FastifyRequest } from 'fastify';

export type OrganizationRole = 'owner' | 'admin' | 'verifier' | 'developer' | 'viewer';

export interface AuthPrincipal {
  subject: string;
  organizationId?: string;
  roles: readonly OrganizationRole[];
}

export type Authenticator = (request: FastifyRequest) => Promise<AuthPrincipal>;

export function canManageOrganization(principal: AuthPrincipal, organizationId?: string): boolean {
  if (!organizationId) return true;
  return principal.organizationId === organizationId && principal.roles.some((role) => ['owner', 'admin', 'developer'].includes(role));
}

export function canPerformAdminAction(principal: AuthPrincipal): boolean {
  return principal.roles.some((role) => role === 'owner' || role === 'admin' || role === 'verifier');
}

export async function createJwtAuthenticator(input: {
  publicKeyPem: string;
  algorithm: string;
  issuer: string;
  audience: string;
}): Promise<Authenticator> {
  const publicKey = await importSPKI(input.publicKeyPem, input.algorithm);
  return async (request) => {
    const authorization = request.headers.authorization;
    if (!authorization?.startsWith('Bearer ')) throw new Error('AUTH_REQUIRED');
    const token = authorization.slice('Bearer '.length);
    const { payload } = await jwtVerify(token, publicKey, {
      issuer: input.issuer,
      audience: input.audience,
      algorithms: [input.algorithm],
    });
    if (!payload.sub) throw new Error('INVALID_SUBJECT');
    const rawRoles = Array.isArray(payload.roles) ? payload.roles : [];
    const roles = rawRoles.filter((value): value is OrganizationRole =>
      typeof value === 'string' && ['owner', 'admin', 'verifier', 'developer', 'viewer'].includes(value),
    );
    const organizationId = typeof payload.org_id === 'string' ? payload.org_id : undefined;
    return { subject: payload.sub, roles, ...(organizationId ? { organizationId } : {}) };
  };
}

export function testHeaderAuthenticator(): Authenticator {
  return async (request) => {
    const subject = request.headers['x-test-subject'];
    if (typeof subject !== 'string' || subject.length === 0) throw new Error('AUTH_REQUIRED');
    const organizationId = typeof request.headers['x-test-org'] === 'string' ? request.headers['x-test-org'] : undefined;
    return { subject, roles: ['owner'], ...(organizationId ? { organizationId } : {}) };
  };
}
