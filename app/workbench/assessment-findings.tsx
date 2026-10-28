'use client';
import {Alert,Box,Button,Chip,Paper,Stack,Typography} from '@mui/material';
import type {AssessmentReport,Finding} from '../../lib/assessment/types';
import {explainFinding,orderedFindings,statusCopy} from '../../lib/assessment/explanation';
type Props={report:AssessmentReport;locale:'ko'|'en'};
export function AssessmentInputSummary({report,locale}:Props){
 const ko=locale==='ko',integrity=report.integrity,web=report.moduleId==='web.compare';
 const text=web?(ko?'공개된 웹 응답의 일부만 확인했습니다. 로그인 후 화면이나 사이트 전체 취약점을 검사한 결과는 아닙니다.':'Only part of the public web response was checked, not signed-in pages or the whole site.'):!integrity?(ko?'과거 결과에는 입력과 결과를 연결하는 검증 근거가 없습니다. 현재 검사 방식으로 다시 확인하세요.':'This older result has no input-integrity evidence. Reassess using a current method.'):integrity.status==='unverified-summary'?(ko?'기기에서 만든 요약으로 검사했습니다. 서버가 원본 파일과 같은지 직접 대조하지는 않았습니다.':'This assessment uses an on-device summary. The server has not independently matched it to the original file.'):integrity.basis==='received-utf8-text'?(ko?'전달받은 설정 내용으로 검사했습니다. 현재 기기에 실제로 적용된 상태인지는 별도로 확인해야 합니다.':'The received configuration text was checked. Its effective state on the device requires a separate check.'):(ko?'서버가 전송받은 파일을 다시 읽어 검사했습니다. 제작자의 진위나 악성코드가 없다는 사실까지 보증하지는 않습니다.':'The server re-read the received file. This does not guarantee publisher authenticity or absence of malware.');
 return <Alert severity={!web&&integrity?.status!=='server-recomputed'?'warning':'info'} sx={{my:2}}>{text}</Alert>;
}
export function AssessmentOverview({report,locale}:Props){
 const ko=locale==='ko',warnings=orderedFindings(report.findings).filter(f=>f.status==='warning'),unknown=report.findings.filter(f=>f.status==='not_assessed');
 return <Paper variant="outlined" sx={{my:2,p:2,borderColor:warnings.length?'warning.main':'divider'}}>
  <Typography variant="h6">{ko?'결과를 쉽게 보면':'Your result at a glance'}</Typography>
  <Typography sx={{mt:1}}>{warnings.length?(ko?`보완하거나 검토할 항목이 ${warnings.length}개 있습니다.`:`${warnings.length} items need review or improvement.`):unknown.length===report.findings.length&&unknown.length>0?(ko?'이 자료만으로는 검사 항목을 판단할 수 없습니다.':'The supplied input is insufficient to decide these checks.'):(ko?'이번에 확인한 범위에서는 보완이 필요한 신호가 발견되지 않았습니다.':'No warning signals were found within the assessed scope.')}</Typography>
  {!!warnings.length&&<Box component="ul" sx={{pl:2.5,my:1}}>{warnings.slice(0,3).map(f=><Typography component="li" key={f.id}>{explainFinding(f,report.moduleId,locale).title}</Typography>)}{warnings.length>3&&<Typography component="li">{ko?`그 밖에 ${warnings.length-3}개 — 아래 항목을 확인하세요.`:`${warnings.length-3} more — see the items below.`}</Typography>}</Box>}
  <Typography variant="body2" sx={{mt:1}}>{unknown.length?(ko?`아직 확인하지 못한 항목도 ${unknown.length}개 있습니다. 정보가 부족하거나 현재 검사 방식이 지원하지 않는 내용이며, 문제가 없다는 뜻은 아닙니다.`:`${unknown.length} items remain unverified because information or inspection support is missing. They are not passes.`):(ko?'추가 미검사 항목은 없지만, 이 검사가 파일·기기·사이트 전체의 안전을 보장하지는 않습니다.':'No listed items remain unassessed, but this check does not guarantee overall safety.')}</Typography>
  <Typography variant="body2" color="text.secondary" sx={{mt:1}}>{ko?'아래에서 보완·검토할 내용 → 아직 확인하지 못한 내용 → 참고·기준 충족 항목 순서로 볼 수 있습니다. 설정은 자동으로 바뀌지 않습니다.':'Items needing review appear first, followed by unverified items and other observations. Settings are never changed automatically.'}</Typography>
  <Button href="#assessment-finding-list" size="small" sx={{mt:1}}>{ko?'설명과 다음에 할 일 보기 ↓':'See explanations and next steps ↓'}</Button>
 </Paper>;
}
function FindingCard({finding:f,report,locale}:Props&{finding:Finding}){
 const ko=locale==='ko',copy=explainFinding(f,report.moduleId,locale),warning=f.status==='warning',unknown=f.status==='not_assessed';
 return <Paper variant="outlined" component="article" sx={{p:2,minWidth:0,borderColor:warning?'warning.main':'divider'}}>
  <Stack direction="row" gap={1} alignItems="center" flexWrap="wrap"><Chip size="small" color={warning?'warning':f.status==='pass'?'success':'default'} label={statusCopy[f.status][locale]}/>{warning&&<Typography variant="caption">{ko?'확인 우선순위: ':'Review priority: '}{f.severity==='high'?(ko?'높음':'High'):f.severity==='low'?(ko?'낮음':'Low'):(ko?'보통':'Normal')}</Typography>}</Stack>
  <Typography component="h3" variant="subtitle1" fontWeight={700} sx={{mt:1}}>{copy.title}</Typography>
  <Typography variant="body2" sx={{mt:1}}>{copy.meaning}</Typography>
  <Alert severity={warning?'warning':'info'} sx={{my:1.5,'& .MuiAlert-message':{minWidth:0}}}>{unknown?(ko?'이번 검사로는 판단할 수 없습니다. 필요한 자료나 별도 환경에서 추가 확인이 필요합니다.':'This inspection cannot decide this item. More information or a separate environment is needed.'):warning?(ko?'검토 기준에 맞지 않는 신호가 관찰됐습니다. 실제 설정과 업무상 필요성을 확인하세요.':'A signal did not meet the review baseline. Check the effective setting and whether it is needed.'):f.status==='pass'?(ko?'제공된 자료에서 이 항목의 검사 기준을 충족했습니다.':'The supplied input meets this item’s baseline.'):(ko?'관찰된 정보입니다. 실제 보호 기능이 작동한다는 판정은 아닙니다.':'This is an observation, not a verdict that protection is effective.')}</Alert>
  <Typography variant="body2" fontWeight={700}>{ko?'왜 확인해야 하나요?':'Why does it matter?'}</Typography><Typography variant="body2" sx={{mt:.5}}>{copy.why}</Typography>
  <Typography variant="body2" fontWeight={700} sx={{mt:1.5}}>{ko?(unknown?'추가로 확인할 방법':'다음에 할 일'):'What to do next'}</Typography><Typography variant="body2" sx={{mt:.5,whiteSpace:'pre-line'}}>{copy.action}</Typography>
  <Box component="details" sx={{mt:2,'& > summary':{cursor:'pointer',color:'primary.main'},'& > summary:focus-visible':{outline:'2px solid',outlineColor:'primary.main',outlineOffset:4}}}>
   <Typography component="summary" variant="body2">{ko?'기술 근거·담당자용 상세 보기':'Technical evidence and details'}</Typography>
   <Typography variant="body2" fontWeight={700} sx={{mt:1}}>{f.title}</Typography>
   <Typography component="code" variant="body2" sx={{display:'block',my:1,overflowWrap:'anywhere'}}>{f.evidence.join(' · ')||'—'}</Typography>
   <Typography variant="body2">{f.remediation}</Typography>
   {f.reference&&<Button href={f.reference} target="_blank" rel="noreferrer" size="small">{ko?'검사 기준 문서':'Reference'}</Button>}
  </Box>
 </Paper>;
}
export default function AssessmentFindings(props:Props){
 const ko=props.locale==='ko',all=orderedFindings(props.report.findings),warnings=all.filter(f=>f.status==='warning'),unknown=all.filter(f=>f.status==='not_assessed'),other=all.filter(f=>f.status==='pass'||f.status==='info');
 const cards=(items:Finding[])=><Box sx={{display:'grid',gridTemplateColumns:{xs:'1fr',lg:'1fr 1fr'},gap:2,mt:1.5}}>{items.map(f=><FindingCard key={f.id} {...props} finding={f}/>)}</Box>;
 return <Stack id="assessment-finding-list" gap={3} sx={{scrollMarginTop:24}}>
  {!!warnings.length&&<Box><Typography variant="h6">{ko?`보완·검토할 내용 ${warnings.length}개`:`Review or improve (${warnings.length})`}</Typography>{cards(warnings)}</Box>}
  {!!unknown.length&&<Box component="details" open={!warnings.length} sx={{'& > summary':{cursor:'pointer',fontWeight:700,color:'primary.main'}}}><Typography component="summary">{ko?`추가 확인이 필요한 내용 ${unknown.length}개 — 문제가 없다는 뜻은 아닙니다`:`Not yet verified (${unknown.length}) — these are not passes`}</Typography>{cards(unknown)}</Box>}
  {!!other.length&&<Box component="details" sx={{'& > summary':{cursor:'pointer',fontWeight:700,color:'primary.main'}}}><Typography component="summary">{ko?`참고·기준 충족 항목 ${other.length}개 보기`:`Observations and baseline results (${other.length})`}</Typography>{cards(other)}</Box>}
 </Stack>;
}
