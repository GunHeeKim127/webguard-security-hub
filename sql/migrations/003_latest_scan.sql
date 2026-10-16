-- Keep older duplicate rows in an owner-only archive before enforcing one result per host.
LOCK TABLE public.scans IN ACCESS EXCLUSIVE MODE;
CREATE TABLE IF NOT EXISTS public.scan_duplicate_archive (LIKE public.scans INCLUDING ALL);
REVOKE ALL ON public.scan_duplicate_archive FROM PUBLIC;
WITH ranked AS (
 SELECT id,row_number() OVER (PARTITION BY hostname ORDER BY created_at DESC,id DESC) AS position
 FROM public.scans
), removed AS (
 DELETE FROM public.scans USING ranked
 WHERE scans.id=ranked.id AND ranked.position>1
 RETURNING scans.*
)
INSERT INTO public.scan_duplicate_archive SELECT * FROM removed;
ALTER TABLE public.scans ADD CONSTRAINT scans_hostname_unique UNIQUE(hostname);
