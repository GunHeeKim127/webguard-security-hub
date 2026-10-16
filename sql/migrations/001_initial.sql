CREATE TABLE users (
 id uuid PRIMARY KEY, email text UNIQUE NOT NULL,
 password_hash text NOT NULL, role text NOT NULL CHECK (role IN ('admin','analyst','viewer'))
);
CREATE TABLE sessions (
 token_hash text PRIMARY KEY, user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 expires_at timestamptz NOT NULL
);
CREATE INDEX ON sessions(expires_at);
CREATE TABLE scans (
 id uuid PRIMARY KEY, user_id uuid NOT NULL REFERENCES users(id),
 hostname text NOT NULL, result jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE events (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 category text NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON events(created_at);
CREATE TABLE rate_limits (
 bucket text PRIMARY KEY, hits integer NOT NULL, reset_at timestamptz NOT NULL
);
