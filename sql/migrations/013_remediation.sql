CREATE TABLE public.assessment_remediations(
 id uuid PRIMARY KEY,user_id uuid NOT NULL,asset_id uuid NOT NULL,run_id uuid NOT NULL,
 finding_id text NOT NULL CHECK(length(finding_id) BETWEEN 1 AND 180),
 state text NOT NULL CHECK(state IN ('open','in_progress','needs_retest','closed')),
 owner_label text NOT NULL CHECK(length(owner_label)<=80),note text NOT NULL CHECK(length(note)<=1000),
 version integer NOT NULL CHECK(version>0),baseline jsonb NOT NULL CHECK(jsonb_typeof(baseline)='object'),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(user_id,asset_id,finding_id),FOREIGN KEY(user_id,asset_id) REFERENCES public.assessment_assets(user_id,id)
);
CREATE TABLE public.assessment_remediation_events(
 id uuid PRIMARY KEY,user_id uuid NOT NULL,asset_id uuid NOT NULL,remediation_id uuid NOT NULL,
 snapshot jsonb NOT NULL CHECK(jsonb_typeof(snapshot)='object'),created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(user_id,asset_id) REFERENCES public.assessment_assets(user_id,id)
);
CREATE INDEX remediation_owner_asset_idx ON public.assessment_remediations(user_id,asset_id,updated_at DESC);
CREATE INDEX remediation_event_owner_asset_idx ON public.assessment_remediation_events(user_id,asset_id,created_at DESC);
REVOKE ALL ON public.assessment_remediations,public.assessment_remediation_events FROM PUBLIC;
ALTER TABLE webguard_archive.diagnostic_records DROP CONSTRAINT diagnostic_records_kind_check;
ALTER TABLE webguard_archive.diagnostic_records ADD CHECK(kind IN ('web_scan','assessment_run','assessment_traffic','diagnostic_event','remediation','remediation_event'));
ALTER FUNCTION public.archive_diagnostics_30d() RENAME TO archive_diagnostics_base_30d;
REVOKE ALL ON FUNCTION public.archive_diagnostics_base_30d() FROM PUBLIC;
CREATE FUNCTION public.archive_diagnostics_30d() RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $archive$
DECLARE summary jsonb;item record;moved integer:=0;cutoff timestamptz:=statement_timestamp()-interval '30 days';
BEGIN
 summary:=public.archive_diagnostics_base_30d();
 IF (summary->>'skipped')::boolean THEN RETURN summary; END IF;
 FOR item IN SELECT * FROM public.assessment_remediation_events WHERE created_at<cutoff ORDER BY created_at LIMIT 1000 FOR UPDATE SKIP LOCKED LOOP
  INSERT INTO webguard_archive.diagnostic_records(kind,source_id,source_time,user_id,payload) VALUES('remediation_event',item.id::text,item.created_at,item.user_id,to_jsonb(item)) ON CONFLICT DO NOTHING;
  DELETE FROM public.assessment_remediation_events WHERE id=item.id;moved:=moved+1;
 END LOOP;
 FOR item IN SELECT * FROM public.assessment_remediations WHERE updated_at<cutoff ORDER BY updated_at LIMIT 1000 FOR UPDATE SKIP LOCKED LOOP
  INSERT INTO webguard_archive.diagnostic_records(kind,source_id,source_time,user_id,payload) VALUES('remediation',item.id::text,item.updated_at,item.user_id,to_jsonb(item)) ON CONFLICT DO NOTHING;
  DELETE FROM public.assessment_remediations WHERE id=item.id;moved:=moved+1;
 END LOOP;
 RETURN jsonb_build_object('skipped',false,'moved',(summary->>'moved')::integer+moved);
END $archive$;
REVOKE ALL ON FUNCTION public.archive_diagnostics_30d() FROM PUBLIC;
