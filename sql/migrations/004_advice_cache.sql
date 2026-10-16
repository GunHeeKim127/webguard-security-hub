CREATE TABLE public.ai_advice_cache (
 cache_key text PRIMARY KEY CHECK(cache_key ~ '^[0-9a-f]{64}$'),
 lease uuid NOT NULL,
 advice text CHECK(length(advice)<=16000),
 input_tokens integer NOT NULL DEFAULT 0 CHECK(input_tokens>=0),
 output_tokens integer NOT NULL DEFAULT 0 CHECK(output_tokens>=0),
 expires_at timestamptz NOT NULL
);
REVOKE ALL ON public.ai_advice_cache FROM PUBLIC;
