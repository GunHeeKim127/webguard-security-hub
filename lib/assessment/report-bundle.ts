import {assessmentReportText} from './report-text';
import {compareAssessments} from './compare';
import {remediationVerification,type RemediationRecord} from './remediation';
import type {AssessmentReport} from './types';
export type ReportRun={id:string;report:AssessmentReport;created_at:string};
/** assessmentTrend: 인접 실행의 호환성을 확인하고 실제 관찰된 변화만 계산합니다. */
export function assessmentTrend(runs:ReportRun[]){const visible=runs.slice(0,10);return visible.map(/** map: 각 실행을 바로 이전 실행과만 비교합니다. */ (run,index)=>{
 const previous=visible[index+1],comparison=previous?compareAssessments(previous.report,run.report):null;
 return {at:run.created_at,comparable:comparison?.compatible??false,improved:comparison?.compatible?comparison.changes.filter(/** filter: 확인 가능한 개선만 집계합니다. */ change=>change.transition==='improved').length:null,regressed:comparison?.compatible?comparison.changes.filter(/** filter: 확인 가능한 악화만 집계합니다. */ change=>change.transition==='regressed').length:null,unknown:comparison?.compatible?comparison.changes.filter(/** filter: 비교할 수 없는 항목을 별도로 셉니다. */ change=>change.transition==='unknown').length:null};
 });}
/** line: 보고서에 쓰는 메모가 제어 문자나 구획을 삽입하지 않게 제한합니다. */
function line(value:string){return value.replace(/[\x00-\x1f\x7f-\x9f\u2028\u2029\u202a-\u202e\u2066-\u2069]/g,' ');}
/** reportBundleText: 최신 결과·호환 추세·수동 조치와 재검증을 같은 자료에 묶습니다. */
export function reportBundleText(runs:ReportRun[],items:RemediationRecord[],locale:'ko'|'en'){
 if(!runs.length)throw new Error('Scan not found');const ko=locale==='ko',latest=runs[0],lines=[assessmentReportText(latest.report,locale),'',ko?'실행 추세 · 조회한 최근 10개 이내':'Run trend · up to 10 retrieved runs'];
 for(const row of assessmentTrend(runs))lines.push(`${line(row.at)} · ${row.comparable?(ko?`개선 ${row.improved} / 악화 ${row.regressed} / 비교 불가 ${row.unknown}`:`improved ${row.improved} / regressed ${row.regressed} / unknown ${row.unknown}`):(ko?'기준이 다르거나 이전 실행이 없어 비교 보류':'No compatible previous run; comparison deferred')}`);
 lines.push('',ko?'조치 상태 · 사용자 입력':'Remediation · user-entered state');
 const states={open:ko?'미착수':'Open',in_progress:ko?'진행 중':'In progress',needs_retest:ko?'재검증 필요':'Needs retest',closed:ko?'종료 · 사용자 판단':'Closed · user decision'};
 const verification={pending:ko?'후속 검사 대기':'Awaiting retest',incompatible:ko?'다른 검사 기준':'Incompatible inspection',unknown:ko?'판단 근거 부족':'Insufficient evidence',passed:ko?'후속 검사 기준 충족':'Later inspection baseline met',review:ko?'후속 검사도 검토 필요':'Later inspection still requires review'};
 if(!items.length)lines.push(ko?'저장된 조치 기록 없음. 문제가 없다는 의미는 아닙니다.':'No saved remediation. This does not mean there are no issues.');
 for(const row of items)lines.push(`${line(row.finding_id)} · ${states[row.state]} · ${verification[remediationVerification(row,latest)]}`,`${ko?'담당':'Owner'}: ${line(row.owner_label)||'—'}`,`${ko?'근거 메모':'Evidence note'}: ${line(row.note)||'—'}`);
 lines.push('',ko?'수동 상태와 자동 재검증 관찰은 별개입니다. 이 보고서는 안전 인증서가 아닙니다.':'Manual state and retest observations are separate. This report is not a security certificate.');return lines.join('\n');
}
/** reportBundleHtml: 외부 리소스·스크립트 없이 이스케이프한 보고서를 인쇄 가능한 HTML로 만듭니다. */
export function reportBundleHtml(runs:ReportRun[],items:RemediationRecord[],locale:'ko'|'en'){
 const escaped=reportBundleText(runs,items,locale).replace(/[&<>"']/g,/** replace: 결과·메모가 HTML로 실행되지 않도록 문자만 표시합니다. */ value=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[value]!));
 return `<!doctype html><html lang="${locale}"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"><title>VELTHARA assessment report</title><style>body{max-width:900px;margin:40px auto;padding:24px;color:#172b3a;font:16px/1.7 system-ui,sans-serif}pre{font:inherit;white-space:pre-wrap;overflow-wrap:anywhere}h1{color:#08665d}@media print{body{margin:0;padding:0;font-size:11pt}@page{margin:18mm}}</style><h1>${locale==='ko'?'VELTHARA 진단 보고서':'VELTHARA assessment report'}</h1><pre>${escaped}</pre></html>`;
}
