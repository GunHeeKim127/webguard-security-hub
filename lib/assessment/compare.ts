import type {AssessmentReport,AssessmentStatus} from './types';
export function compareAssessments(previous:AssessmentReport,current:AssessmentReport){
 if(previous.integrity?.status!==current.integrity?.status||previous.integrity?.basis!==current.integrity?.basis)return {compatible:false,changes:[]};
 if(previous.moduleId!==current.moduleId||previous.moduleVersion!==current.moduleVersion||previous.ruleVersion!==current.ruleVersion)return {compatible:false,changes:[]};
 const before=new Map(previous.findings.map(f=>[f.id,f])),after=new Map(current.findings.map(f=>[f.id,f]));
 const rank=(status:AssessmentStatus)=>status==='warning'?1:status==='pass'?0:null;
 const changes=[...new Set([...before.keys(),...after.keys()])].map(id=>{
  const a=before.get(id),b=after.get(id),ar=a?rank(a.status):null,br=b?rank(b.status):null;
  let transition:'improved'|'regressed'|'unknown'|'changed'|'unchanged';
  if(ar!==null&&br!==null&&ar!==br)transition=br<ar?'improved':'regressed';
  else if(!a||!b||a.status==='not_assessed'||b.status==='not_assessed')transition='unknown';
  else transition=JSON.stringify(a)===JSON.stringify(b)?'unchanged':'changed';
  return {id,before:a?.status??null,after:b?.status??null,transition};
 });return {compatible:true,changes};
}
