-- rls-template.sql
-- Default-deny template for a new table. Copy and adapt.
-- Replace ${TABLE_NAME} and ${OWNER_COLUMN} with your values.

-- Step 1: enable + force RLS
ALTER TABLE ${TABLE_NAME} ENABLE ROW LEVEL SECURITY;
ALTER TABLE ${TABLE_NAME} FORCE ROW LEVEL SECURITY;   -- applies even to table owner

-- Step 2: revoke anything that might be broadly granted
REVOKE ALL ON ${TABLE_NAME} FROM PUBLIC;
REVOKE ALL ON ${TABLE_NAME} FROM anon;

-- Step 3: grant authenticated the operations they need (RLS does the row filtering)
GRANT SELECT, INSERT, UPDATE, DELETE ON ${TABLE_NAME} TO authenticated;
-- If this table uses a serial sequence, also:
-- GRANT USAGE, SELECT ON SEQUENCE ${TABLE_NAME}_id_seq TO authenticated;

-- Step 4: per-operation policies
-- Owner can read own rows
CREATE POLICY "${TABLE_NAME}_owner_select"
  ON ${TABLE_NAME} FOR SELECT
  TO authenticated
  USING (auth.uid() = ${OWNER_COLUMN});

-- Owner can insert rows where they set themselves as owner
CREATE POLICY "${TABLE_NAME}_owner_insert"
  ON ${TABLE_NAME} FOR INSERT
  TO authenticated
  WITH CHECK (auth.uid() = ${OWNER_COLUMN});

-- Owner can update own rows; result must still have them as owner (prevents ownership transfer)
CREATE POLICY "${TABLE_NAME}_owner_update"
  ON ${TABLE_NAME} FOR UPDATE
  TO authenticated
  USING (auth.uid() = ${OWNER_COLUMN})
  WITH CHECK (auth.uid() = ${OWNER_COLUMN});

-- Owner can delete own rows
CREATE POLICY "${TABLE_NAME}_owner_delete"
  ON ${TABLE_NAME} FOR DELETE
  TO authenticated
  USING (auth.uid() = ${OWNER_COLUMN});

-- Optional: admin override (uncomment if you have an admin role claim)
-- CREATE POLICY "${TABLE_NAME}_admin_all"
--   ON ${TABLE_NAME} FOR ALL
--   TO authenticated
--   USING (auth.jwt()->>'role' = 'admin')
--   WITH CHECK (auth.jwt()->>'role' = 'admin');

-- Step 5: verify
-- Run as a specific user to confirm scoping works:
--   SET ROLE authenticated;
--   SET request.jwt.claims = '{"sub": "USER-UUID", "role": "authenticated"}';
--   SELECT * FROM ${TABLE_NAME};
--   RESET ROLE;
--   RESET request.jwt.claims;
