BEGIN;

ALTER TABLE agent_keys ADD COLUMN IF NOT EXISTS activated_at timestamptz;
UPDATE agent_keys SET activated_at = created_at WHERE activated_at IS NULL AND revoked_at IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS agent_keys_one_active_per_agent
  ON agent_keys(agent_id)
  WHERE activated_at IS NOT NULL AND revoked_at IS NULL;

ALTER TABLE agent_challenges ADD COLUMN IF NOT EXISTS agent_key_id uuid;
UPDATE agent_challenges c
SET agent_key_id = k.id
FROM agent_keys k
WHERE c.agent_key_id IS NULL
  AND k.agent_id = c.agent_id
  AND k.activated_at IS NOT NULL
  AND k.revoked_at IS NULL;
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'agent_challenges_agent_key_id_fkey'
  ) THEN
    ALTER TABLE agent_challenges
      ADD CONSTRAINT agent_challenges_agent_key_id_fkey FOREIGN KEY (agent_key_id) REFERENCES agent_keys(id);
  END IF;
END $$;
CREATE INDEX IF NOT EXISTS agent_challenges_key_idx ON agent_challenges(agent_key_id, expires_at);

CREATE TABLE IF NOT EXISTS agent_key_rotations (
  id uuid PRIMARY KEY,
  agent_id uuid NOT NULL REFERENCES agents(id),
  old_key_id uuid NOT NULL REFERENCES agent_keys(id),
  new_key_id uuid NOT NULL UNIQUE REFERENCES agent_keys(id),
  challenge_digest text NOT NULL,
  expires_at timestamptz NOT NULL,
  completed_at timestamptz,
  cancelled_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT agent_key_rotations_distinct_keys CHECK (old_key_id <> new_key_id)
);
CREATE INDEX IF NOT EXISTS agent_key_rotations_agent_idx
  ON agent_key_rotations(agent_id, created_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS agent_key_rotations_one_pending_per_agent
  ON agent_key_rotations(agent_id)
  WHERE completed_at IS NULL AND cancelled_at IS NULL;

ALTER TABLE agent_passports ADD COLUMN IF NOT EXISTS passport_version integer NOT NULL DEFAULT 1;
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'agent_passports_version_positive'
  ) THEN
    ALTER TABLE agent_passports
      ADD CONSTRAINT agent_passports_version_positive CHECK (passport_version > 0);
  END IF;
END $$;
DROP INDEX IF EXISTS agent_passports_purchase_unique;
CREATE INDEX IF NOT EXISTS agent_passports_purchase_idx
  ON agent_passports(purchase_id)
  WHERE purchase_id IS NOT NULL;

COMMIT;
