BEGIN;

CREATE TABLE IF NOT EXISTS issuer_signing_keys (
  id uuid PRIMARY KEY,
  key_id text NOT NULL UNIQUE,
  algorithm text NOT NULL,
  public_key_pem text NOT NULL,
  public_jwk jsonb NOT NULL,
  provider text NOT NULL,
  provider_key_reference text,
  status text NOT NULL,
  activated_at timestamptz NOT NULL,
  retired_at timestamptz,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT issuer_signing_keys_algorithm CHECK (algorithm = 'Ed25519'),
  CONSTRAINT issuer_signing_keys_status CHECK (status IN ('active', 'retired', 'revoked')),
  CONSTRAINT issuer_signing_keys_retired_consistency CHECK (
    (status = 'retired' AND retired_at IS NOT NULL AND revoked_at IS NULL)
    OR status <> 'retired'
  ),
  CONSTRAINT issuer_signing_keys_revoked_consistency CHECK (
    (status = 'revoked' AND revoked_at IS NOT NULL)
    OR status <> 'revoked'
  )
);
CREATE UNIQUE INDEX IF NOT EXISTS issuer_signing_keys_one_active
  ON issuer_signing_keys ((1))
  WHERE status = 'active';
CREATE INDEX IF NOT EXISTS issuer_signing_keys_status_idx
  ON issuer_signing_keys(status, activated_at DESC);

CREATE TABLE IF NOT EXISTS issuer_key_status_history (
  id uuid PRIMARY KEY,
  issuer_key_id uuid NOT NULL REFERENCES issuer_signing_keys(id),
  from_status text,
  to_status text NOT NULL,
  reason_code text NOT NULL,
  actor_subject text,
  occurred_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT issuer_key_status_history_from_status CHECK (
    from_status IS NULL OR from_status IN ('active', 'retired', 'revoked')
  ),
  CONSTRAINT issuer_key_status_history_to_status CHECK (
    to_status IN ('active', 'retired', 'revoked')
  )
);
CREATE INDEX IF NOT EXISTS issuer_key_status_history_key_idx
  ON issuer_key_status_history(issuer_key_id, occurred_at DESC);

COMMIT;
