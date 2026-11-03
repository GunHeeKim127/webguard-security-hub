'use client';
import {Alert,Box,Paper,Typography} from '@mui/material';
import {commonHttpStatuses,httpStatusExplanation,webResponseStatuses} from '../lib/http-status-explanation';
import type {AssessmentReport} from '../lib/assessment/types';
/** HttpStatusGuide: 대상 HTTP 상태의 의미·조치와 현재 진단 범위를 초보자용으로 설명합니다. */
export default function HttpStatusGuide({status,locale,label}:{status:number,locale:string,label?:string}){
 const ko=locale==='ko',value=httpStatusExplanation(status,locale);
 return <Paper component="section" aria-label={ko?'HTTP 응답 설명':'HTTP response explanation'} variant="outlined" sx={{p:2,my:2}}>
  <Typography fontWeight={700}>{label?label+' · ':''}HTTP {status} · {value.title}</Typography>
  <Typography variant="body2" sx={{mt:1}}>{value.meaning}</Typography><Typography variant="body2" sx={{mt:1}}>{ko?'다음에 할 일: ':'Next step: '}{value.action}</Typography>
  {!value.eligible&&<Alert severity="info" sx={{mt:1.5}}>{ko?'오류·이동 응답의 헤더를 실제 서비스의 정상 페이지 설정으로 단정할 수 없어 헤더 평가는 확인 불가로 보류합니다. 보안 설정이 부족하다고 확정한 것은 아닙니다. 연결 TLS 항목은 별도로 확인할 수 있습니다.':'Header findings are left unverified because an error or redirect response may not represent the normal application. This is not a confirmed missing security control. Connection TLS checks are evaluated separately.'}</Alert>}
  <Typography variant="body2" color="text.secondary" sx={{mt:1.5}}>{ko?'검사 범위: 이 도메인의 / 주소에 대한 공개 HEAD 응답입니다. /프로젝트/ 같은 하위 페이지·로그인 후 화면·리디렉션 목적지는 검사하지 않았습니다. GitHub Pages의 하위 프로젝트는 기본 도메인의 결과와 다를 수 있습니다.':'Scope: the public HEAD response at this domain’s /. Subpath projects, signed-in pages and redirect destinations were not inspected. A GitHub Pages subpath project may differ from the root result.'}</Typography>
  <Box component="details" sx={{mt:1.5,'& summary':{cursor:'pointer',color:'primary.main'}}}><Typography component="summary" variant="body2">{ko?'다른 HTTP 상태 코드 뜻 보기':'What other HTTP status codes mean'}</Typography>{commonHttpStatuses.map(/** map: 자주 접하는 상태 코드의 뜻만 표시하고 보안 등급과 구분합니다. */ code=>{const row=httpStatusExplanation(code,locale);return <Box key={code} sx={{mt:1.5}}><Typography variant="body2" fontWeight={700}>{code} · {row.title}</Typography><Typography variant="body2">{row.meaning}</Typography></Box>;})}</Box>
 </Paper>;
}
/** WebReportResponseGuide: 저장된 PC·모바일 응답이 같으면 공통 설명으로 묶습니다. */
export function WebReportResponseGuide({report,locale}:{report:AssessmentReport,locale:string}){
 const values=webResponseStatuses(report),ko=locale==='ko';
 if(!values.length)return null;
 return <>{values.length===2&&values[0].status===values[1].status?<HttpStatusGuide status={values[0].status} locale={locale} label={ko?'PC·모바일 공통':'Desktop / mobile'}/>:values.map(/** map: 프로필별로 관찰한 실제 상태만 설명합니다. */ row=><HttpStatusGuide key={row.profile} status={row.status} locale={locale} label={row.profile==='desktop'?'PC':ko?'모바일':'Mobile'}/>)}</>;
}
