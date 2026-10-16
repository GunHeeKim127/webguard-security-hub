CREATE TABLE public.ip_blocks (
 address inet PRIMARY KEY,
 strikes integer NOT NULL CHECK (strikes BETWEEN 0 AND 6),
 blacklisted boolean NOT NULL DEFAULT false,
 blocked_until timestamptz,
 last_reason text NOT NULL CHECK (last_reason IN ('probe','injection','traversal','manual_reset')),
 first_seen timestamptz NOT NULL DEFAULT now(),
 last_seen timestamptz NOT NULL DEFAULT now()
);
REVOKE ALL ON public.ip_blocks FROM PUBLIC;
