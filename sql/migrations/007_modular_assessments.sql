-- Additive phase two storage; legacy scans, users and roles are preserved.
CREATE TABLE public.assessment_assets (
 id uuid PRIMARY KEY,user_id uuid NOT NULL REFERENCES public.users(id),
 module_id text NOT NULL CHECK(module_id IN ('web.compare','linux.ssh','windows.policy','application.pe','application.apk')),
 target_key text NOT NULL CHECK(length(target_key) BETWEEN 1 AND 253),
 label text NOT NULL CHECK(length(label) BETWEEN 1 AND 80),
 ingest_token_hash text CHECK(ingest_token_hash ~ '^[0-9a-f]{64}$'),
 created_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(user_id,module_id,target_key),UNIQUE(user_id,id)
);
CREATE TABLE public.assessment_runs (
 id uuid PRIMARY KEY,user_id uuid NOT NULL,asset_id uuid NOT NULL,
 report jsonb NOT NULL CHECK(jsonb_typeof(report)='object'),created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(user_id,asset_id) REFERENCES public.assessment_assets(user_id,id)
);
CREATE INDEX assessment_runs_owner_asset_idx ON public.assessment_runs(user_id,asset_id,created_at DESC);
CREATE TABLE public.assessment_traffic (
 user_id uuid NOT NULL,asset_id uuid NOT NULL,window_at timestamptz NOT NULL,
 requests bigint NOT NULL CHECK(requests>=0),login_failures bigint NOT NULL CHECK(login_failures>=0),
 probes bigint NOT NULL CHECK(probes>=0),server_errors bigint NOT NULL CHECK(server_errors>=0),
 PRIMARY KEY(user_id,asset_id,window_at),
 FOREIGN KEY(user_id,asset_id) REFERENCES public.assessment_assets(user_id,id)
);
