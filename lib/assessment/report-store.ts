import type {ReportRun} from './report-bundle';
import type {RemediationRecord} from './remediation';

export const REPORT_SNAPSHOT_SQL=`WITH owned AS (
 SELECT id,user_id FROM public.assessment_assets WHERE user_id=$1 AND id=$2 AND updated_at>=now()-interval '30 days'
), recent_runs AS (
 SELECT r.id,r.report,r.created_at FROM public.assessment_runs r JOIN owned a ON a.id=r.asset_id AND a.user_id=r.user_id
 WHERE r.user_id=$1 AND r.created_at>=now()-interval '30 days' ORDER BY r.created_at DESC,r.id DESC LIMIT 10
), actions AS (
 SELECT m.id,m.asset_id,m.run_id,m.finding_id,m.state,m.owner_label,m.note,m.version,m.baseline,m.created_at,m.updated_at
 FROM public.assessment_remediations m JOIN owned a ON a.id=m.asset_id AND a.user_id=m.user_id
 WHERE m.user_id=$1 AND m.updated_at>=now()-interval '30 days' ORDER BY m.updated_at DESC,m.id DESC LIMIT 500
)
SELECT (SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY r.created_at DESC,r.id DESC),'[]'::jsonb) FROM recent_runs r) AS runs,
 (SELECT coalesce(jsonb_agg(to_jsonb(m) ORDER BY m.updated_at DESC,m.id DESC),'[]'::jsonb) FROM actions m) AS actions
FROM owned`;

type Query=(sql:string,values:unknown[])=>Promise<{rows:{runs:ReportRun[];actions:RemediationRecord[]}[]}>;
/** loadReportSnapshot: 소유권·활성 기간·실행·조치를 단일 읽기 스냅샷과 바인딩된 계정 조건으로 가져옵니다. */
export async function loadReportSnapshot(query:Query,userId:string,assetId:string){
 const row=(await query(REPORT_SNAPSHOT_SQL,[userId,assetId])).rows[0];
 if(!row||!Array.isArray(row.runs)||!row.runs.length||!Array.isArray(row.actions))return null;
 return {runs:row.runs.map(/** map: JSON 집계와 일반 DB 응답의 시각 표시를 동일한 ISO 형식으로 정규화합니다. */ run=>({...run,created_at:new Date(run.created_at).toISOString()})),actions:row.actions};
}
