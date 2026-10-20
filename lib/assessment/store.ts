import {randomUUID} from 'node:crypto';
import type {AssessmentReport} from './types';
export type AssessmentQuery=(sql:string,values:unknown[])=>Promise<{rows:any[];rowCount?:number|null}>;
export async function saveAssessment(query:AssessmentQuery,userId:string,targetKey:string,label:string,report:AssessmentReport){
 const result=await query(`WITH asset AS (
 INSERT INTO public.assessment_assets(id,user_id,module_id,target_key,label) VALUES($1,$2,$3,$4,$5)
 ON CONFLICT(user_id,module_id,target_key) DO UPDATE SET label=EXCLUDED.label,updated_at=clock_timestamp()
 RETURNING id,user_id
 ), saved AS (
 INSERT INTO public.assessment_runs(id,user_id,asset_id,report) SELECT $6,asset.user_id,asset.id,$7::jsonb FROM asset RETURNING id,asset_id,created_at
 ), logged AS (
 INSERT INTO public.events(category,user_id) SELECT 'assessment_completed',$2 FROM saved RETURNING id
 ) SELECT saved.id,saved.asset_id,saved.created_at FROM saved CROSS JOIN logged`,[randomUUID(),userId,report.moduleId,targetKey,label,randomUUID(),JSON.stringify(report)]);
 return result.rows[0];
}
export function trafficSignals(row:{requests:number;login_failures:number;probes:number;server_errors:number}){
 return {loginFailures:Number(row.login_failures)>=5,probes:Number(row.probes)>=3,serverErrors:Number(row.server_errors)>=5,highVolume:Number(row.requests)>=1000};
}
