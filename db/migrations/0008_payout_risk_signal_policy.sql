BEGIN;

CREATE OR REPLACE FUNCTION credalyx_emit_payout_risk_signal()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  signal_reasons jsonb;
BEGIN
  SELECT coalesce(jsonb_agg(value), '[]'::jsonb)
    INTO signal_reasons
  FROM jsonb_array_elements_text(NEW.reasons) AS reason(value)
  WHERE value IN (
    'agent_not_active',
    'agent_control_not_verified',
    'wallet_has_debt',
    'open_payout_exists',
    'payout_velocity_24h',
    'recent_refund_or_chargeback_exposure',
    'amount_above_auto_approve_limit',
    'withdraws_nearly_all_available_balance'
  );

  IF jsonb_array_length(signal_reasons) > 0 THEN
    INSERT INTO risk_signals (id, agent_id, signal_type, score, metadata, created_at)
    VALUES (
      NEW.id,
      NEW.agent_id,
      'payout_risk_assessment',
      NEW.score,
      jsonb_build_object(
        'decision', NEW.decision,
        'reasons', signal_reasons,
        'all_reasons', NEW.reasons,
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

COMMIT;
