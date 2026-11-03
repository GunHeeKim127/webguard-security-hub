import type {AssessmentReport} from './types';
import {orderedFindings,explainFinding,statusCopy} from './explanation';
import {findingContext} from './finding-context';

/** reportLine: 제어 문자·줄바꿈으로 보고서 구획을 위조하지 않도록 한 줄로 표시합니다. */
function reportLine(value:string){return value.replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069]/g,' ').trim();}

/** assessmentReportText: 이미 조회한 결과만으로 읽기용 초안을 생성하며 원본 파일·계정·접속키는 추가하지 않습니다. */
export function assessmentReportText(report:AssessmentReport,locale:'ko'|'en'){
 const ko=locale==='ko',rows=orderedFindings(report.findings),lines=[ko?'VELTHARA 보안 진단 보고서 · 초안':'VELTHARA security assessment report · draft',
 ko?'범위가 제한된 관찰 결과입니다. 안전 인증·침해 확정·조치 완료 증명이 아닙니다.':'Limited observations, not a safety certificate, confirmed compromise or proof of remediation.',
 `${ko?'검사 종류':'Module'}: ${reportLine(report.moduleId)}`,`${ko?'검사 시각':'Observed at'}: ${reportLine(report.observedAt)}`,`${ko?'검사 기준':'Rules'}: ${reportLine(report.moduleVersion)} / ${reportLine(report.ruleVersion)}`,
 `${ko?'근거 유형':'Evidence basis'}: ${reportLine(report.integrity?.status??'unverified-summary')}`, '',ko?'상태 요약':'Status summary'];
 for(const status of ['warning','not_assessed','info','pass'] as const)lines.push(`${statusCopy[status][locale]}: ${rows.filter(/** filter: 표시된 상태별 개수만 집계합니다. */ f=>f.status===status).length}`);
 lines.push('',ko?'검사 범위':'Scope');for(const value of report.scope)lines.push('- '+reportLine(value));
 lines.push('',ko?'한계·추가 확인':'Limitations / further verification');for(const value of report.limitations)lines.push('- '+reportLine(value));
 lines.push('',ko?'항목별 결과':'Findings');
 for(const [index,f] of rows.entries()){
  const copy=explainFinding(f,report.moduleId,locale),context=findingContext(f,report,locale);
  lines.push('',`${index+1}. ${reportLine(copy.title)} · ${statusCopy[f.status][locale]}`,
   `${ko?'관찰':'Observed'}: ${reportLine(context.observed)}`,`${ko?'비교 기준':'Baseline'}: ${reportLine(context.expected)}`,
   `${ko?'의미':'Meaning'}: ${reportLine(context.reason??copy.meaning)}`,
   `${ko?'다음 조치':'Next step'}: ${reportLine(context.nextStep??(f.status==='pass'?(ko?'현재 기준을 유지하고 실제 적용 상태를 재확인하세요.':'Maintain the baseline and verify effective configuration.'):copy.action))}`,
   `${ko?'기술 근거':'Technical evidence'}: ${f.evidence.map(reportLine).join(' · ')||'—'}`);
 }
 lines.push('',ko?'미확인은 안전이나 취약점 확정이 아닙니다. 조치 완료는 수정 후 재검증과 별도 근거가 필요합니다.':'Unknown is neither safe nor confirmed vulnerable. Completion requires retesting and supporting evidence.',ko?'공유 전 결과에 민감한 정보가 없는지 검토하세요.':'Review the result for sensitive information before sharing.');
 return lines.join('\n')+'\n';
}
