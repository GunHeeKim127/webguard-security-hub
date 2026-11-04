import type {AssessmentReport} from './types';
import {compareAssessments} from './compare';
export const remediationStates=['open','in_progress','needs_retest','closed'] as const;
export type RemediationState=typeof remediationStates[number];
export type RemediationRecord={id:string;asset_id:string;run_id:string;finding_id:string;state:RemediationState;owner_label:string;note:string;version:number;baseline:AssessmentReport;created_at:string;updated_at:string};
/** remediationInput: 허용한 상태·짧은 메모·낙관적 버전만 받고 임의 완료 판정과 추가 필드를 거절합니다. */
export function remediationInput(value:Record<string,unknown>){
 const allowed=['assetId','runId','findingId','state','ownerLabel','note','version'];
 if(Object.keys(value).some(/** some: 허용하지 않은 변경 필드를 거절합니다. */ key=>!allowed.includes(key)))throw new Error('Invalid assessment input');
 const uuid=/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i;
 if(typeof value.assetId!=='string'||!uuid.test(value.assetId)||typeof value.runId!=='string'||!uuid.test(value.runId)||typeof value.findingId!=='string'||value.findingId.length<1||value.findingId.length>180||/[\x00-\x1f\x7f]/.test(value.findingId)||!remediationStates.includes(value.state as RemediationState)||!Number.isSafeInteger(value.version)||(Number(value.version)<0||Number(value.version)>2147483646))throw new Error('Invalid assessment input');
 for(const [key,max] of [['ownerLabel',80],['note',1000]] as const)if(typeof value[key]!=='string'||value[key].length>max||/[\x00-\x08\x0b-\x1f\x7f\u202a-\u202e\u2066-\u2069]/.test(value[key] as string))throw new Error('Invalid assessment input');
 if(value.state==='closed'&&!(value.note as string).trim())throw new Error('Invalid assessment input');
 return {assetId:value.assetId,runId:value.runId,findingId:value.findingId,state:value.state as RemediationState,ownerLabel:(value.ownerLabel as string).trim(),note:(value.note as string).trim(),version:Number(value.version)};
}
/** remediationBaseline: 비교에 필요한 최소 근거를 고정하며 원본 파일이나 사용자 메모를 복제하지 않습니다. */
export function remediationBaseline(report:AssessmentReport,findingId:string):AssessmentReport{
 const matches=report.findings.filter(/** filter: 하나의 실제 항목만 조치 대상으로 인정합니다. */ f=>f.id===findingId);if(matches.length!==1)throw new Error('Invalid assessment input');
 return {...report,findings:[matches[0]],scope:[],limitations:[]};
}
/** remediationVerification: 후속의 호환되는 검사에서 같은 항목이 통과했을 때만 재검증 통과로 표시합니다. */
export function remediationVerification(row:RemediationRecord,latest:{id:string;report:AssessmentReport;created_at:string}){
 if(row.run_id===latest.id||new Date(latest.created_at).getTime()<=new Date(row.created_at).getTime())return 'pending' as const;
 const result=compareAssessments(row.baseline,latest.report);if(!result.compatible)return 'incompatible' as const;
 const findings=latest.report.findings.filter(/** filter: 중복·누락된 결과를 통과로 판정하지 않습니다. */ f=>f.id===row.finding_id);
 if(findings.length!==1||findings[0].status==='not_assessed'||findings[0].status==='info')return 'unknown' as const;
 return findings[0].status==='pass'?'passed' as const:'review' as const;
}
