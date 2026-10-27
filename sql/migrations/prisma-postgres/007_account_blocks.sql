CREATE TABLE public.account_blocks (
 user_id uuid PRIMARY KEY REFERENCES public.users(id) ON DELETE CASCADE,
 strikes integer NOT NULL CHECK (strikes BETWEEN 0 AND 6),
 blacklisted boolean NOT NULL DEFAULT false,
 last_reason text NOT NULL CHECK (last_reason IN ('probe','injection','traversal','manual_reset')),
 first_seen timestamptz NOT NULL DEFAULT now(),
 last_seen timestamptz NOT NULL DEFAULT now(),
 CHECK (NOT blacklisted OR strikes=6)
);
-- Provider-managed credentials prohibit GRANT/REVOKE. Verify the resulting
-- table ACL through the provider before deployment; SQL role separation is
-- not guaranteed by this managed profile (see docs/BLACKLIST_MANAGEMENT.md).
