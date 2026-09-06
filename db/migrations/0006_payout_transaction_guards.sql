BEGIN;

CREATE OR REPLACE FUNCTION credalyx_validate_payout_beneficiary()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  agent_owner uuid;
  agent_org uuid;
  account_owner uuid;
  account_org uuid;
  account_provider text;
BEGIN
  IF NEW.agent_id IS NULL THEN
    RAISE EXCEPTION 'payout agent_id is required for payout lifecycle rows';
  END IF;

  SELECT owner_user_id, organization_id
    INTO agent_owner, agent_org
  FROM agents
  WHERE id = NEW.agent_id;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'payout agent does not exist';
  END IF;

  SELECT owner_user_id, organization_id, provider
    INTO account_owner, account_org, account_provider
  FROM payout_accounts
  WHERE id = NEW.payout_account_id;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'payout account does not exist';
  END IF;

  IF agent_org IS NOT NULL THEN
    IF account_org IS DISTINCT FROM agent_org OR account_owner IS NOT NULL THEN
      RAISE EXCEPTION 'payout account organization does not match agent organization';
    END IF;
  ELSE
    IF account_owner IS DISTINCT FROM agent_owner OR account_org IS NOT NULL THEN
      RAISE EXCEPTION 'payout account owner does not match agent owner';
    END IF;
  END IF;

  IF NEW.provider IS NOT NULL AND account_provider IS DISTINCT FROM NEW.provider THEN
    RAISE EXCEPTION 'payout provider does not match payout account provider';
  END IF;

  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS payouts_validate_beneficiary ON payouts;
CREATE TRIGGER payouts_validate_beneficiary
BEFORE INSERT OR UPDATE OF agent_id, payout_account_id, provider
ON payouts
FOR EACH ROW
EXECUTE FUNCTION credalyx_validate_payout_beneficiary();

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'payouts_amount_positive') THEN
    ALTER TABLE payouts ADD CONSTRAINT payouts_amount_positive CHECK (amount_minor > 0);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'payouts_risk_score_range') THEN
    ALTER TABLE payouts ADD CONSTRAINT payouts_risk_score_range CHECK (risk_score IS NULL OR risk_score BETWEEN 0 AND 100);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'payouts_risk_decision_valid') THEN
    ALTER TABLE payouts ADD CONSTRAINT payouts_risk_decision_valid CHECK (risk_decision IS NULL OR risk_decision IN ('approve', 'review', 'deny'));
  END IF;
END $$;

COMMIT;
