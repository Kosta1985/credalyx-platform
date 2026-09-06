BEGIN;

DO $$ BEGIN CREATE TYPE organization_role AS ENUM ('owner','admin','verifier','developer','viewer'); EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN CREATE TYPE agent_status AS ENUM ('pending','active','suspended','revoked'); EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN CREATE TYPE passport_status AS ENUM ('active','suspended','revoked','expired'); EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN CREATE TYPE verification_status AS ENUM ('pending','approved','rejected','cancelled'); EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN CREATE TYPE commission_status AS ENUM ('pending','available','paid','reversed'); EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN CREATE TYPE payout_status AS ENUM ('pending','processing','paid','failed','cancelled'); EXCEPTION WHEN duplicate_object THEN NULL; END $$;

CREATE TABLE IF NOT EXISTS users (
  id uuid PRIMARY KEY,
  external_subject text NOT NULL UNIQUE,
  email text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz
);

CREATE TABLE IF NOT EXISTS organizations (
  id uuid PRIMARY KEY,
  name text NOT NULL,
  domain text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz
);
CREATE UNIQUE INDEX IF NOT EXISTS organizations_domain_unique ON organizations(domain) WHERE domain IS NOT NULL;

CREATE TABLE IF NOT EXISTS organization_members (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organizations(id),
  user_id uuid NOT NULL REFERENCES users(id),
  role organization_role NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz,
  UNIQUE (organization_id, user_id)
);
CREATE INDEX IF NOT EXISTS organization_members_user_idx ON organization_members(user_id);

CREATE TABLE IF NOT EXISTS agents (
  id uuid PRIMARY KEY,
  public_id text NOT NULL UNIQUE,
  owner_user_id uuid NOT NULL REFERENCES users(id),
  organization_id uuid REFERENCES organizations(id),
  referrer_agent_id uuid REFERENCES agents(id),
  referral_code text NOT NULL UNIQUE,
  verification_level integer NOT NULL DEFAULT 0 CHECK (verification_level BETWEEN 0 AND 3),
  status agent_status NOT NULL DEFAULT 'pending',
  control_verified_at timestamptz,
  version integer NOT NULL DEFAULT 1,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz,
  CONSTRAINT agents_not_self_referrer CHECK (referrer_agent_id IS NULL OR referrer_agent_id <> id)
);
CREATE INDEX IF NOT EXISTS agents_owner_idx ON agents(owner_user_id);
CREATE INDEX IF NOT EXISTS agents_org_idx ON agents(organization_id);

CREATE TABLE IF NOT EXISTS agent_keys (
  id uuid PRIMARY KEY,
  agent_id uuid NOT NULL REFERENCES agents(id),
  key_id text NOT NULL,
  algorithm text NOT NULL,
  public_key_pem text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz,
  revoked_at timestamptz,
  UNIQUE (agent_id, key_id)
);
CREATE INDEX IF NOT EXISTS agent_keys_active_idx ON agent_keys(agent_id, revoked_at);

CREATE TABLE IF NOT EXISTS agent_endpoints (
  id uuid PRIMARY KEY,
  agent_id uuid NOT NULL REFERENCES agents(id),
  url text NOT NULL,
  protocol_binding text NOT NULL DEFAULT 'HTTP+JSON',
  protocol_version text NOT NULL DEFAULT '1.0',
  verified_at timestamptz,
  disabled_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (agent_id, url)
);

CREATE TABLE IF NOT EXISTS agent_capabilities (
  id uuid PRIMARY KEY,
  agent_id uuid NOT NULL REFERENCES agents(id),
  capability text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (agent_id, capability)
);

CREATE TABLE IF NOT EXISTS agent_challenges (
  id uuid PRIMARY KEY,
  agent_id uuid NOT NULL REFERENCES agents(id),
  digest text NOT NULL,
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS agent_challenges_lookup_idx ON agent_challenges(agent_id, digest, expires_at);

CREATE TABLE IF NOT EXISTS agent_passports (
  id uuid PRIMARY KEY,
  passport_id text NOT NULL UNIQUE,
  agent_id uuid NOT NULL REFERENCES agents(id),
  schema_version text NOT NULL,
  claims jsonb NOT NULL,
  signature text NOT NULL,
  status passport_status NOT NULL DEFAULT 'active',
  issued_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS passport_status_history (
  id uuid PRIMARY KEY,
  passport_id uuid NOT NULL REFERENCES agent_passports(id),
  from_status passport_status,
  to_status passport_status NOT NULL,
  reason_code text NOT NULL,
  actor_subject text,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS passport_status_history_passport_idx ON passport_status_history(passport_id, created_at);

CREATE TABLE IF NOT EXISTS verification_requests (
  id uuid PRIMARY KEY,
  agent_id uuid NOT NULL REFERENCES agents(id),
  requested_level integer NOT NULL CHECK (requested_level BETWEEN 1 AND 3),
  status verification_status NOT NULL DEFAULT 'pending',
  provider text,
  created_at timestamptz NOT NULL DEFAULT now(),
  decided_at timestamptz
);
CREATE TABLE IF NOT EXISTS verification_evidence (
  id uuid PRIMARY KEY,
  verification_request_id uuid NOT NULL REFERENCES verification_requests(id),
  evidence_type text NOT NULL,
  storage_reference text,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS verification_decisions (
  id uuid PRIMARY KEY,
  verification_request_id uuid NOT NULL REFERENCES verification_requests(id),
  decision text NOT NULL,
  reason_code text NOT NULL,
  actor_subject text,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS referrals (
  id uuid PRIMARY KEY,
  referred_agent_id uuid NOT NULL UNIQUE REFERENCES agents(id),
  referrer_agent_id uuid NOT NULL REFERENCES agents(id),
  referral_code text NOT NULL,
  attributed_at timestamptz NOT NULL DEFAULT now(),
  locked_at timestamptz,
  CONSTRAINT referrals_not_self CHECK (referred_agent_id <> referrer_agent_id)
);
CREATE INDEX IF NOT EXISTS referrals_referrer_idx ON referrals(referrer_agent_id);

CREATE TABLE IF NOT EXISTS payment_customers (
  id uuid PRIMARY KEY,
  owner_user_id uuid NOT NULL REFERENCES users(id),
  provider text NOT NULL,
  provider_customer_id text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (provider, provider_customer_id)
);
CREATE TABLE IF NOT EXISTS payment_sessions (
  id uuid PRIMARY KEY,
  agent_id uuid NOT NULL REFERENCES agents(id),
  provider text NOT NULL,
  provider_session_id text NOT NULL,
  amount_minor bigint NOT NULL CHECK (amount_minor > 0),
  currency text NOT NULL,
  status text NOT NULL,
  expires_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (provider, provider_session_id)
);
CREATE TABLE IF NOT EXISTS payment_events (
  id uuid PRIMARY KEY,
  provider text NOT NULL,
  provider_event_id text NOT NULL,
  event_type text NOT NULL,
  payload_hash text NOT NULL,
  received_at timestamptz NOT NULL DEFAULT now(),
  processed_at timestamptz,
  UNIQUE (provider, provider_event_id)
);
CREATE TABLE IF NOT EXISTS purchases (
  id uuid PRIMARY KEY,
  external_reference text NOT NULL UNIQUE,
  agent_id uuid NOT NULL REFERENCES agents(id),
  payment_event_id uuid NOT NULL REFERENCES payment_events(id),
  amount_minor bigint NOT NULL CHECK (amount_minor > 0),
  currency text NOT NULL,
  status text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS ledger_accounts (
  id uuid PRIMARY KEY,
  code text NOT NULL,
  account_type text NOT NULL CHECK (account_type IN ('asset','liability','revenue','expense')),
  scope_type text NOT NULL CHECK (scope_type IN ('platform','agent')),
  scope_id text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (code, scope_type, scope_id)
);
CREATE TABLE IF NOT EXISTS ledger_transactions (
  id uuid PRIMARY KEY,
  idempotency_key text NOT NULL UNIQUE,
  external_reference text NOT NULL,
  transaction_type text NOT NULL,
  sealed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS ledger_entries (
  id uuid PRIMARY KEY,
  transaction_id uuid NOT NULL REFERENCES ledger_transactions(id),
  account_id uuid NOT NULL REFERENCES ledger_accounts(id),
  amount_minor bigint NOT NULL CHECK (amount_minor <> 0),
  currency text NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ledger_entries_transaction_idx ON ledger_entries(transaction_id);
CREATE INDEX IF NOT EXISTS ledger_entries_account_idx ON ledger_entries(account_id);

CREATE TABLE IF NOT EXISTS commissions (
  id uuid PRIMARY KEY,
  purchase_id uuid NOT NULL UNIQUE REFERENCES purchases(id),
  referrer_agent_id uuid NOT NULL REFERENCES agents(id),
  amount_minor bigint NOT NULL CHECK (amount_minor > 0),
  currency text NOT NULL,
  status commission_status NOT NULL DEFAULT 'pending',
  hold_until timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS payout_accounts (
  id uuid PRIMARY KEY,
  owner_user_id uuid NOT NULL REFERENCES users(id),
  provider text NOT NULL,
  provider_account_id text NOT NULL,
  onboarding_status text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (provider, provider_account_id)
);
CREATE TABLE IF NOT EXISTS payouts (
  id uuid PRIMARY KEY,
  payout_account_id uuid NOT NULL REFERENCES payout_accounts(id),
  amount_minor bigint NOT NULL CHECK (amount_minor > 0),
  currency text NOT NULL,
  status payout_status NOT NULL DEFAULT 'pending',
  provider_payout_id text,
  idempotency_key text NOT NULL UNIQUE,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS refunds (
  id uuid PRIMARY KEY,
  purchase_id uuid NOT NULL REFERENCES purchases(id),
  provider_refund_id text,
  amount_minor bigint NOT NULL CHECK (amount_minor > 0),
  currency text NOT NULL,
  status text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS disputes (
  id uuid PRIMARY KEY,
  purchase_id uuid NOT NULL REFERENCES purchases(id),
  provider_dispute_id text NOT NULL UNIQUE,
  amount_minor bigint NOT NULL CHECK (amount_minor > 0),
  currency text NOT NULL,
  status text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS webhook_events (
  id uuid PRIMARY KEY,
  provider text NOT NULL,
  provider_event_id text NOT NULL,
  payload_hash text NOT NULL,
  processing_status text NOT NULL,
  received_at timestamptz NOT NULL DEFAULT now(),
  processed_at timestamptz,
  UNIQUE (provider, provider_event_id)
);
CREATE TABLE IF NOT EXISTS api_clients (
  id uuid PRIMARY KEY,
  organization_id uuid REFERENCES organizations(id),
  name text NOT NULL,
  client_id text NOT NULL UNIQUE,
  secret_hash text,
  created_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz
);
CREATE TABLE IF NOT EXISTS access_tokens (
  id uuid PRIMARY KEY,
  api_client_id uuid NOT NULL REFERENCES api_clients(id),
  token_hash text NOT NULL UNIQUE,
  scopes jsonb NOT NULL DEFAULT '[]'::jsonb,
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS consents (
  id uuid PRIMARY KEY,
  subject_user_id uuid REFERENCES users(id),
  agent_id uuid REFERENCES agents(id),
  purpose text NOT NULL,
  scopes jsonb NOT NULL DEFAULT '[]'::jsonb,
  granted_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz
);
CREATE TABLE IF NOT EXISTS audit_events (
  id uuid PRIMARY KEY,
  occurred_at timestamptz NOT NULL DEFAULT now(),
  actor_type text NOT NULL,
  actor_subject text,
  organization_id uuid,
  action text NOT NULL,
  target_type text NOT NULL,
  target_id text NOT NULL,
  reason_code text,
  correlation_id text,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS audit_events_target_idx ON audit_events(target_type, target_id, occurred_at);
CREATE TABLE IF NOT EXISTS risk_signals (
  id uuid PRIMARY KEY,
  agent_id uuid REFERENCES agents(id),
  signal_type text NOT NULL,
  score integer,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS security_incidents (
  id uuid PRIMARY KEY,
  severity text NOT NULL,
  status text NOT NULL,
  title text NOT NULL,
  description text NOT NULL,
  detected_at timestamptz NOT NULL DEFAULT now(),
  resolved_at timestamptz
);

CREATE OR REPLACE FUNCTION credalyx_prevent_ledger_entry_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'ledger entries are immutable; create a compensating transaction instead';
END $$;
DROP TRIGGER IF EXISTS ledger_entries_immutable ON ledger_entries;
CREATE TRIGGER ledger_entries_immutable BEFORE UPDATE OR DELETE ON ledger_entries
FOR EACH ROW EXECUTE FUNCTION credalyx_prevent_ledger_entry_mutation();

CREATE OR REPLACE FUNCTION credalyx_reject_entry_on_sealed_transaction() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE current_sealed_at timestamptz;
BEGIN
  SELECT sealed_at INTO current_sealed_at FROM ledger_transactions WHERE id = NEW.transaction_id FOR SHARE;
  IF current_sealed_at IS NOT NULL THEN
    RAISE EXCEPTION 'ledger transaction % is sealed', NEW.transaction_id;
  END IF;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS ledger_entries_require_open_transaction ON ledger_entries;
CREATE TRIGGER ledger_entries_require_open_transaction BEFORE INSERT ON ledger_entries
FOR EACH ROW EXECUTE FUNCTION credalyx_reject_entry_on_sealed_transaction();

CREATE OR REPLACE FUNCTION credalyx_seal_ledger_transaction() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE entry_count integer; bad_currency text; bad_total numeric;
BEGIN
  IF OLD.sealed_at IS NOT NULL OR NEW.sealed_at IS NULL THEN
    RAISE EXCEPTION 'ledger transaction rows are immutable after creation';
  END IF;
  IF NEW.id <> OLD.id OR NEW.idempotency_key <> OLD.idempotency_key OR NEW.external_reference <> OLD.external_reference OR NEW.transaction_type <> OLD.transaction_type OR NEW.created_at <> OLD.created_at THEN
    RAISE EXCEPTION 'only sealed_at may change on a ledger transaction';
  END IF;
  SELECT COUNT(*) INTO entry_count FROM ledger_entries WHERE transaction_id = NEW.id;
  IF entry_count < 2 THEN
    RAISE EXCEPTION 'ledger transaction % requires at least two entries', NEW.id;
  END IF;
  SELECT currency, SUM(amount_minor) INTO bad_currency, bad_total
  FROM ledger_entries WHERE transaction_id = NEW.id
  GROUP BY currency HAVING SUM(amount_minor) <> 0 LIMIT 1;
  IF bad_currency IS NOT NULL THEN
    RAISE EXCEPTION 'unbalanced ledger transaction %, currency %, total %', NEW.id, bad_currency, bad_total;
  END IF;
  RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS ledger_transactions_seal_guard ON ledger_transactions;
CREATE TRIGGER ledger_transactions_seal_guard BEFORE UPDATE ON ledger_transactions
FOR EACH ROW EXECUTE FUNCTION credalyx_seal_ledger_transaction();

CREATE OR REPLACE FUNCTION credalyx_prevent_ledger_transaction_delete() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'ledger transaction rows are immutable; create a compensating transaction instead';
END $$;
DROP TRIGGER IF EXISTS ledger_transactions_no_delete ON ledger_transactions;
CREATE TRIGGER ledger_transactions_no_delete BEFORE DELETE ON ledger_transactions
FOR EACH ROW EXECUTE FUNCTION credalyx_prevent_ledger_transaction_delete();

COMMIT;
