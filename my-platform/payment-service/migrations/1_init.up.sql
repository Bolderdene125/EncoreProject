CREATE TABLE payments (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     TEXT NOT NULL,
  amount      DECIMAL(10,2) NOT NULL,
  status      TEXT NOT NULL DEFAULT 'pending',
  description TEXT NOT NULL DEFAULT '',
  created_by  TEXT NOT NULL,
  created_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE token_blacklist (
  user_id    TEXT PRIMARY KEY,
  revoked_at TIMESTAMPTZ DEFAULT NOW()
);
