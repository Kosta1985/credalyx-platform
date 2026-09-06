BEGIN;

ALTER TABLE payout_accounts ALTER COLUMN owner_user_id DROP NOT NULL;
ALTER TABLE payout_accounts ADD COLUMN IF NOT EXISTS organization_id uuid REFERENCES organizations(id);
ALTER TABLE payout_accounts ADD COLUMN IF NOT EXISTS onboarding_url text;
ALTER TABLE payout_accounts ADD COLUMN IF NOT EXISTS onboarding_expires_at timestamptz;
ALTER TABLE payout_accounts ADD COLUMN IF NOT EXISTS updated_at timestamptz NOT NULL DEFAULT now();

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'payout_accounts_owner_xor_org'
  ) THEN
    ALTER TABLE payout_accounts
      ADD CONSTRAINT payout_accounts_owner_xor_org CHECK (
        (owner_user_id IS NOT NULL AND organization_id IS NULL)
        OR (owner_user_id IS NULL AND organization_id IS NOT NULL)
      );
  END IF;
END $$;

CREATE UNIQUE INDEX IF NOT EXISTS payout_accounts_owner_provider_unique
  ON payout_accounts(owner_user_id, provider)
  WHERE owner_user_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS payout_accounts_org_provider_unique
  ON payout_accounts(organization_id, provider)
  WHERE organization_id IS NOT NULL;

ALTER TABLE payouts ADD COLUMN IF NOT EXISTS agent_id uuid REFERENCES agents(id);
ALTER TABLE payouts ADD COLUMN IF NOT EXISTS provider text;
ALTER TABLE payouts ADD COLUMN IF NOT EXISTS payout_reference text;
ALTER TABLE payouts ADD COLUMN IF NOT EXISTS reserved_at timestamptz;
ALTER TABLE payouts ADD COLUMN IF NOT EXISTS submitted_at timestamptz;
ALTER TABLE payouts ADD COLUMN IF NOT EXISTS processed_at timestamptz;
ALTER TABLE payouts ADD COLUMN IF NOT EXISTS failure_reason text;
ALTER TABLE payouts ADD COLUMN IF NOT EXISTS risk_decision text;
ALTER TABLE payouts ADD COLUMN IF NOT EXISTS risk_score integer;

CREATE UNIQUE INDEX IF NOT EXISTS payouts_reference_unique
  ON payouts(payout_reference)
  WHERE payout_reference IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS payouts_provider_payout_unique
  ON payouts(provider, provider_payout_id)
  WHERE provider IS NOT NULL AND provider_payout_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS payouts_one_open_per_agent
  ON payouts(agent_id)
  WHERE agent_id IS NOT NULL AND status IN ('pending', 'processing');

CREATE TABLE IF NOT EXISTS payout_events (
  id uuid PRIMARY KEY,
  provider text NOT NULL,
  provider_event_id text NOT NULL,
  payout_id uuid REFERENCES payouts(id),
  event_type text NOT NULL,
  payload_hash text NOT NULL,
  processing_status text NOT NULL,
  received_at timestamptz NOT NULL DEFAULT now(),
  processed_at timestamptz,
  UNIQUE(provider, provider_event_id)
);
CREATE INDEX IF NOT EXISTS payout_events_payout_idx
  ON payout_events(payout_id, received_at DESC);

CREATE TABLE IF NOT EXISTS payout_risk_assessments (
  id uuid PRIMARY KEY,
  agent_id uuid NOT NULL REFERENCES agents(id),
  payout_id uuid REFERENCES payouts(id),
  idempotency_key text NOT NULL,
  amount_minor bigint NOT NULL,
  currency text NOT NULL,
  decision text NOT NULL,
  score integer NOT NULL,
  reasons jsonb NOT NULL DEFAULT '[]'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT payout_risk_assessments_decision CHECK (decision IN ('approve', 'review', 'deny')),
  CONSTRAINT payout_risk_assessments_score CHECK (score BETWEEN 0 AND 100),
  CONSTRAINT payout_risk_assessments_amount CHECK (amount_minor > 0)
);
CREATE INDEX IF NOT EXISTS payout_risk_assessments_agent_idx
  ON payout_risk_assessments(agent_id, created_at DESC);

COMMIT;
