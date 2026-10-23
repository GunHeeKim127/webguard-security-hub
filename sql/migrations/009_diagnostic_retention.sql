-- Cold diagnostic data is retained privately, never exposed to customer APIs.
CREATE SCHEMA IF NOT EXISTS webguard_archive;
REVOKE ALL ON SCHEMA webguard_archive FROM PUBLIC;
CREATE TABLE webguard_archive.diagnostic_records(
 kind text NOT NULL CHECK(kind IN ('web_scan','assessment_run','assessment_traffic','diagnostic_event')),
 source_id text NOT NULL,source_time timestamptz NOT NULL,user_id uuid NOT NULL,
 payload jsonb NOT NULL,archived_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(kind,source_id,source_time)
);
CREATE INDEX diagnostic_archive_owner_time_idx ON webguard_archive.diagnostic_records(user_id,source_time DESC);
CREATE INDEX scans_retention_time_idx ON public.scans(created_at);
CREATE INDEX assessment_runs_retention_time_idx ON public.assessment_runs(created_at);
CREATE INDEX assessment_traffic_retention_time_idx ON public.assessment_traffic(window_at);
REVOKE ALL ON webguard_archive.diagnostic_records FROM PUBLIC;
CREATE FUNCTION public.archive_diagnostics_30d() RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $archive$
DECLARE cutoff timestamptz:=statement_timestamp()-interval '30 days';item record;moved integer:=0;
BEGIN
 IF NOT pg_try_advisory_xact_lock(784294) THEN RETURN jsonb_build_object('skipped',true,'moved',0); END IF;

 FOR item IN SELECT *,id::text AS archive_id FROM public.scans
 WHERE created_at<cutoff ORDER BY created_at LIMIT 1000 FOR UPDATE SKIP LOCKED LOOP
  INSERT INTO webguard_archive.diagnostic_records(kind,source_id,source_time,user_id,payload)
  VALUES('web_scan',item.archive_id,item.created_at,item.user_id,to_jsonb(item)-'archive_id')
  ON CONFLICT(kind,source_id,source_time) DO NOTHING;
  DELETE FROM public.scans WHERE scans.created_at=item.created_at AND scans.id::text=item.archive_id;
  moved:=moved+1;
 END LOOP;

 FOR item IN SELECT *,id::text AS archive_id FROM public.assessment_runs
 WHERE created_at<cutoff ORDER BY created_at LIMIT 1000 FOR UPDATE SKIP LOCKED LOOP
  INSERT INTO webguard_archive.diagnostic_records(kind,source_id,source_time,user_id,payload)
  VALUES('assessment_run',item.archive_id,item.created_at,item.user_id,to_jsonb(item)-'archive_id')
  ON CONFLICT(kind,source_id,source_time) DO NOTHING;
  DELETE FROM public.assessment_runs WHERE assessment_runs.created_at=item.created_at AND assessment_runs.id::text=item.archive_id;
  moved:=moved+1;
 END LOOP;

 FOR item IN SELECT *,asset_id::text||':'||user_id::text AS archive_id FROM public.assessment_traffic
 WHERE window_at<cutoff ORDER BY window_at LIMIT 1000 FOR UPDATE SKIP LOCKED LOOP
  INSERT INTO webguard_archive.diagnostic_records(kind,source_id,source_time,user_id,payload)
  VALUES('assessment_traffic',item.archive_id,item.window_at,item.user_id,to_jsonb(item)-'archive_id')
  ON CONFLICT(kind,source_id,source_time) DO NOTHING;
  DELETE FROM public.assessment_traffic WHERE assessment_traffic.window_at=item.window_at AND (assessment_traffic.asset_id::text||':'||assessment_traffic.user_id::text)=item.archive_id;
  moved:=moved+1;
 END LOOP;

 FOR item IN SELECT *,id::text AS archive_id FROM public.events
 WHERE created_at<cutoff AND user_id IS NOT NULL AND category IN ('scan_completed','scan_rejected','assessment_completed','assessment_rejected','ai_advice','telemetry_key_rotated') ORDER BY created_at LIMIT 1000 FOR UPDATE SKIP LOCKED LOOP
  INSERT INTO webguard_archive.diagnostic_records(kind,source_id,source_time,user_id,payload)
  VALUES('diagnostic_event',item.archive_id,item.created_at,item.user_id,to_jsonb(item)-'archive_id')
  ON CONFLICT(kind,source_id,source_time) DO NOTHING;
  DELETE FROM public.events WHERE events.created_at=item.created_at AND events.id::text=item.archive_id;
  moved:=moved+1;
 END LOOP;
 RETURN jsonb_build_object('skipped',false,'moved',moved);
END $archive$;
REVOKE ALL ON FUNCTION public.archive_diagnostics_30d() FROM PUBLIC;

