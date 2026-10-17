-- Provider-managed profile: no role/grant commands. Preserve current result owners.
ALTER TABLE public.scans ADD CONSTRAINT scans_user_hostname_unique UNIQUE(user_id,hostname);
ALTER TABLE public.scans DROP CONSTRAINT scans_hostname_unique;
ALTER TABLE public.events ADD COLUMN user_id uuid REFERENCES public.users(id) ON DELETE SET NULL;
CREATE INDEX events_user_created_idx ON public.events(user_id,created_at DESC);
-- Historical actor-less events remain NULL and are excluded from personal dashboards.
