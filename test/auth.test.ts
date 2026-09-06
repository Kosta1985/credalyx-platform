import assert from 'node:assert/strict';
import test from 'node:test';
import { canManageOrganization, canPerformAdminAction, type AuthPrincipal } from '../src/auth.js';

const developer: AuthPrincipal = { subject: 'sub-a', organizationId: '01900000-0000-7000-8000-000000000010', roles: ['developer'] };
const viewer: AuthPrincipal = { subject: 'sub-b', organizationId: '01900000-0000-7000-8000-000000000010', roles: ['viewer'] };

test('tenant authorization rejects cross-organization access', () => {
  assert.equal(canManageOrganization(developer, '01900000-0000-7000-8000-000000000010'), true);
  assert.equal(canManageOrganization(developer, '01900000-0000-7000-8000-000000000011'), false);
});

test('viewer cannot mutate organization resources', () => {
  assert.equal(canManageOrganization(viewer, viewer.organizationId), false);
  assert.equal(canPerformAdminAction(viewer), false);
});
