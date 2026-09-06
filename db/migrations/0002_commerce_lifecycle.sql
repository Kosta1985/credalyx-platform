BEGIN;

ALTER TABLE payment_sessions ADD COLUMN IF NOT EXISTS idempotency_key text;
ALTER TABLE payment_sessions ADD COLUMN IF NOT EXISTS purchase_reference text;
ALTER TABLE payment_sessions ADD COLUMN IF NOT EXISTS checkout_url text;
CREATE UNIQUE INDEX IF NOT EXISTS payment_sessions_idempotency_unique
  ON payment_sessions(provider, idempotency_key) WHERE idempotency_key IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS payment_sessions_purchase_reference_unique
  ON payment_sessions(purchase_reference) WHERE purchase_reference IS NOT NULL;

ALTER TABLE agent_passports ADD COLUMN IF NOT EXISTS purchase_id uuid;
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'agent_passports_purchase_id_fkey'
  ) THEN
    ALTER TABLE agent_passports
      ADD CONSTRAINT agent_passports_purchase_id_fkey FOREIGN KEY (purchase_id) REFERENCES purchases(id);
  END IF;
END $$;
CREATE UNIQUE INDEX IF NOT EXISTS agent_passports_purchase_unique
  ON agent_passports(purchase_id) WHERE purchase_id IS NOT NULL;

ALTER TABLE commissions ADD COLUMN IF NOT EXISTS released_at timestamptz;
ALTER TABLE commissions ADD COLUMN IF NOT EXISTS reversed_at timestamptz;
ALTER TABLE commissions ADD COLUMN IF NOT EXISTS reversal_reason text;

ALTER TABLE refunds ADD COLUMN IF NOT EXISTS provider text;
ALTER TABLE refunds ADD COLUMN IF NOT EXISTS provider_event_id text;
ALTER TABLE refunds ADD COLUMN IF NOT EXISTS reason_code text;
CREATE UNIQUE INDEX IF NOT EXISTS refunds_provider_event_unique
  ON refunds(provider, provider_event_id)
  WHERE provider IS NOT NULL AND provider_event_id IS NOT NULL;

ALTER TABLE disputes ADD COLUMN IF NOT EXISTS provider text;
ALTER TABLE disputes ADD COLUMN IF NOT EXISTS provider_event_id text;
ALTER TABLE disputes ADD COLUMN IF NOT EXISTS reason_code text;
CREATE UNIQUE INDEX IF NOT EXISTS disputes_provider_event_unique
  ON disputes(provider, provider_event_id)
  WHERE provider IS NOT NULL AND provider_event_id IS NOT NULL;

COMMIT;
