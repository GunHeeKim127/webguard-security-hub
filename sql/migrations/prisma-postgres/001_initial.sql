-- Prisma Postgres profile: credentials and database access are managed by the provider.
-- CREATE ROLE / GRANT / REVOKE are unsupported by this service and are not attempted.
-- This is a separate ledger/profile, not a modification of previously applied migrations.
CREATE TABLE public.users (
 id uuid PRIMARY KEY, email text UNIQUE NOT NULL,
 password_hash text NOT NULL, role text NOT NULL CHECK (role IN ('admin','analyst','viewer'))
);
CREATE TABLE public.sessions (
 token_hash text PRIMARY KEY, user_id uuid NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
 expires_at timestamptz NOT NULL
);
CREATE INDEX ON public.sessions(expires_at);
CREATE TABLE public.scans (
 id uuid PRIMARY KEY,user_id uuid NOT NULL REFERENCES public.users(id),
 hostname text NOT NULL CONSTRAINT scans_hostname_unique UNIQUE,
 result jsonb NOT NULL,created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE public.events (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,category text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON public.events(created_at);
CREATE TABLE public.rate_limits (bucket text PRIMARY KEY,hits integer NOT NULL,reset_at timestamptz NOT NULL);
CREATE TABLE public.ai_advice_cache (
 cache_key text PRIMARY KEY CHECK(cache_key ~ '^[0-9a-f]{64}$'),lease uuid NOT NULL,
 advice text CHECK(length(advice)<=16000),input_tokens integer NOT NULL DEFAULT 0 CHECK(input_tokens>=0),
 output_tokens integer NOT NULL DEFAULT 0 CHECK(output_tokens>=0),expires_at timestamptz NOT NULL
);
CREATE TABLE public.ip_blocks (
 address inet PRIMARY KEY,strikes integer NOT NULL CHECK(strikes BETWEEN 0 AND 6),
 blacklisted boolean NOT NULL DEFAULT false,blocked_until timestamptz,
 last_reason text NOT NULL CHECK(last_reason IN ('probe','injection','traversal','manual_reset')),
 first_seen timestamptz NOT NULL DEFAULT now(),last_seen timestamptz NOT NULL DEFAULT now()
);
CREATE FUNCTION public.register_viewer(p_id uuid,p_email text,p_hash text)
RETURNS void LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF char_length(p_email) NOT BETWEEN 3 AND 254 OR p_email<>lower(btrim(p_email))
 OR p_email !~ '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$'
 OR p_hash !~ '^[0-9a-f]{32}:[0-9a-f]{128}$'
 OR p_id IS NULL OR p_email IS NULL OR p_hash IS NULL THEN
  RAISE EXCEPTION 'Invalid registration';
 END IF;
 INSERT INTO public.users(id,email,password_hash,role)
 VALUES(p_id,p_email,p_hash,'viewer') ON CONFLICT(email) DO NOTHING;
END $$;
