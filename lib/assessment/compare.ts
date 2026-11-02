import type {AssessmentReport,AssessmentStatus} from './types';
/** compareAssessments: 호환되는 두 검사 결과의 항목별 상태 변화를 비교합니다 주요 호출: map·keys. */ export function compareAssessments(previous:AssessmentReport,current:AssessmentReport){
 if(previous.integrity?.status!==current.integrity?.status||previous.integrity?.basis!==current.integrity?.basis)return {compatible:false,changes:[]};
 if(previous.moduleId!==current.moduleId||previous.targetKind!==current.targetKind||previous.moduleVersion!==current.moduleVersion||previous.ruleVersion!==current.ruleVersion)return {compatible:false,changes:[]};
 const before=new Map(previous.findings.map(/** map 콜백: 각 항목을 필요한 값으로 변환합니다 */ f=>[f.id,f])),after=new Map(current.findings.map(/** map 콜백: 각 항목을 필요한 값으로 변환합니다 */ f=>[f.id,f]));
 // SSH line numbers locate evidence, but moving a directive does not itself
 // change its observed policy. Keep values/status/conditional evidence intact.
 const fingerprint=/** fingerprint: 변경 비교에 사용할 항목의 고정 표현을 계산합니다 주요 호출: stringify·filter. */ (finding:AssessmentReport['findings'][number])=>JSON.stringify(previous.moduleId==='linux.ssh'?{...finding,evidence:finding.evidence.filter(/** filter 콜백: 조건에 맞는 항목만 고릅니다 */ value=>!/^line=\d+$/.test(value))}:finding);
 const rank=/** rank: 개선 비교가 가능한 상태의 기준 순위를 반환합니다 */ (status:AssessmentStatus)=>status==='warning'?1:status==='pass'?0:null;
 const changes=[...new Set([...before.keys(),...after.keys()])].map(/** map 콜백: 각 항목을 필요한 값으로 변환합니다 주요 호출: get·rank·fingerprint. */ id=>{
  const a=before.get(id),b=after.get(id),ar=a?rank(a.status):null,br=b?rank(b.status):null;
  let transition:'improved'|'regressed'|'unknown'|'changed'|'unchanged';
  if(ar!==null&&br!==null&&ar!==br)transition=br<ar?'improved':'regressed';
  else if(!a||!b||a.status==='not_assessed'||b.status==='not_assessed')transition='unknown';
  else transition=fingerprint(a)===fingerprint(b)?'unchanged':'changed';
  return {id,before:a?.status??null,after:b?.status??null,transition};
 });return {compatible:true,changes};
}
