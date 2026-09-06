BEGIN;

CREATE OR REPLACE FUNCTION credalyx_emit_payout_risk_signal()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.score > 0 OR NEW.decision <> 'approve' THEN
    INSERT INTO risk_signals (id, agent_id, signal_type, score, metadata, created_at)
    VALUES (
      NEW.id,
      NEW.agent_id,
      'payout_risk_assessment',
      NEW.score,
      jsonb_build_object(
        'decision', NEW.decision,
        'reasons', NEW.reasons,
        'idempotency_key', NEW.idempotency_key,
        'amount_minor', NEW.amount_minor::text,
        'currency', NEW.currency,
        'payout_id', NEW.payout_id
      ),
      NEW.created_at
    )
    ON CONFLICT (id) DO NOTHING;
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS payout_risk_assessments_emit_signal ON payout_risk_assessments;
CREATE TRIGGER payout_risk_assessments_emit_signal
AFTER INSERT ON payout_risk_assessments
FOR EACH ROW
EXECUTE FUNCTION credalyx_emit_payout_risk_signal();

COMMIT;
