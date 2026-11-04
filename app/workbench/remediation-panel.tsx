'use client';
import {useEffect,useState} from 'react';
import {Alert,Box,Button,Chip,MenuItem,Paper,Stack,TextField,Typography} from '@mui/material';
import {protectedRequest} from '../../lib/protected-request';
import {errorText} from '../../lib/errors-i18n';
import {orderedFindings,explainFinding} from '../../lib/assessment/explanation';
import {remediationStates,remediationVerification,type RemediationRecord,type RemediationState} from '../../lib/assessment/remediation';
import type {AssessmentReport} from '../../lib/assessment/types';
type Latest={id:string;report:AssessmentReport;created_at:string};
const stateLabels={open:['미착수','Open'],in_progress:['진행 중','In progress'],needs_retest:['재검증 필요','Needs retest'],closed:['종료 · 사용자 판단','Closed · user decision']} as const;
const verifyLabels={pending:['후속 검사 대기','Awaiting retest'],incompatible:['검사 기준이 달라 비교 불가','Incompatible inspection'],unknown:['후속 근거 부족','Insufficient retest evidence'],passed:['후속 검사에서 기준 충족','Baseline met in later inspection'],review:['후속 검사도 검토 필요','Later inspection still requires review']} as const;
/** RemediationPanel: 펼칠 때만 계정별 조치를 조회하고 수동 상태·재검증 관찰을 구분합니다. */
export default function RemediationPanel({assetId,latest,locale}:{assetId:string;latest:Latest;locale:'ko'|'en'}){
 const ko=locale==='ko',index=ko?0:1,[open,setOpen]=useState(false),[items,setItems]=useState<RemediationRecord[]>([]),[history,setHistory]=useState<Array<{id:string;snapshot:{findingId:string;state:RemediationState;version:number};created_at:string}>>([]),[loading,setLoading]=useState(false),[revision,setRevision]=useState(0),[busy,setBusy]=useState(false),[problem,setProblem]=useState(''),[saved,setSaved]=useState(false);
 const findings=orderedFindings(latest.report.findings),[findingId,setFindingId]=useState(findings[0]?.id??''),[state,setState]=useState<RemediationState>('open'),[owner,setOwner]=useState(''),[note,setNote]=useState('');
 const selected=items.find(/** find: 현재 선택한 항목의 저장 조치를 연결합니다. */ row=>row.finding_id===findingId);
 useEffect(/** useEffect: 필요한 시점에만 조회하고 종료·변경된 요청은 취소합니다. */ ()=>{
  if(!open)return;const controller=new AbortController();setLoading(true);setProblem('');
  void protectedRequest('/api/remediations?assetId='+encodeURIComponent(assetId),{cache:'no-store',signal:controller.signal}).then(/** then: 자기 자산 조치와 변경 이력만 갱신합니다. */ async response=>{const body=await response.json();if(!response.ok)throw new Error(body.errorCode??'SERVICE_UNAVAILABLE');if(!controller.signal.aborted){setItems(body.items);setHistory(body.history);}}).catch(/** catch: 취소 외 실패는 기존 입력을 유지하며 안내합니다. */ error=>{if(!controller.signal.aborted)setProblem(errorText(locale,error instanceof Error?error.message:''));}).finally(/** finally: 활성 요청의 로딩만 종료합니다. */ ()=>{if(!controller.signal.aborted)setLoading(false);});
  return /** cleanup: 조회 요청의 수명 종료를 반영합니다. */ ()=>controller.abort();
 },[assetId,open,revision,locale]);
 useEffect(/** useEffect: 선택 항목의 저장 상태를 폼에 표시합니다. */ ()=>{setState(selected?.state??'open');setOwner(selected?.owner_label??'');setNote(selected?.note??'');},[selected,findingId]);
 /** save: 현재 버전과 자기 검사 항목을 전송하고 충돌 시 입력을 보존합니다. */
 async function save(){setBusy(true);setProblem('');setSaved(false);try{
  const response=await protectedRequest('/api/remediations',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({assetId,runId:latest.id,findingId,state,ownerLabel:owner,note,version:selected?.version??0})});const body=await response.json();
  if(response.status===409){setProblem(ko?'다른 화면에서 변경됐습니다. 메모를 보관한 뒤 새로고침하여 최신 상태와 합쳐 주세요.':'Changed in another view. Keep your note and refresh to merge the latest state.');return;}
  if(!response.ok)throw new Error(body.errorCode??'SERVICE_UNAVAILABLE');setSaved(true);setRevision(/** setRevision: 저장 후 서버의 확정 상태를 다시 읽습니다. */ value=>value+1);
 }catch(error){setProblem(errorText(locale,error instanceof Error?error.message:''));}finally{setBusy(false);}}
 return <Paper variant="outlined" sx={{my:3,p:2}}><Button aria-expanded={open} onClick={/** onClick: 조치 관리의 지연 조회를 시작하거나 접습니다. */ ()=>setOpen(!open)}>{ko?'항목별 조치 관리':'Finding remediation'}</Button>{open&&<Stack gap={2}>
  <Alert severity="info">{ko?'수동 종료는 보안 문제 해결의 증명이 아닙니다. 같은 기준의 후속 검사 결과를 따로 표시합니다. 메모에는 비밀번호·키·개인정보·원본 파일을 넣지 마세요.':'Manual closure does not prove remediation. Compatible later inspections are shown separately. Do not enter passwords, keys, personal data or original files.'}</Alert>
  {problem&&<Alert severity="warning">{problem}</Alert>}{saved&&<Alert severity="success">{ko?'조치 기록을 저장했습니다.':'Remediation saved.'}</Alert>}
  <Button disabled={loading||busy} onClick={/** onClick: 최신 버전 조회를 명시적으로 요청합니다. */ ()=>setRevision(/** setRevision: 조회 번호를 증가시킵니다. */ value=>value+1)}>{loading?(ko?'불러오는 중':'Loading'):(ko?'조치 새로고침':'Refresh remediation')}</Button>
  <TextField select fullWidth label={ko?'조치할 검사 항목':'Finding'} value={findingId} disabled={busy||loading} onChange={/** onChange: 선택한 항목의 조치 폼으로 전환합니다. */ event=>{setFindingId(event.target.value);setSaved(false);}}>{findings.map(/** map: 현재 보고서의 실제 검사 항목만 제공합니다. */ f=><MenuItem key={f.id} value={f.id}>{explainFinding(f,latest.report.moduleId,locale).title}</MenuItem>)}</TextField>
  {selected&&<Chip sx={{alignSelf:'start',maxWidth:'100%',height:'auto','& .MuiChip-label':{whiteSpace:'normal'}}} label={verifyLabels[remediationVerification(selected,latest)][index]}/>}
  <TextField select label={ko?'조치 상태':'Remediation state'} value={state} disabled={busy} onChange={/** onChange: 사용자 선언 상태만 변경합니다. */ event=>{setState(event.target.value as RemediationState);setSaved(false);}}>{remediationStates.map(/** map: 수동 상태와 재검증 통과를 혼동하지 않는 이름을 표시합니다. */ value=><MenuItem key={value} value={value}>{stateLabels[value][index]}</MenuItem>)}</TextField>
  <TextField label={ko?'담당 표시 이름 · 선택':'Owner display name · optional'} value={owner} disabled={busy} slotProps={{htmlInput:{maxLength:80}}} onChange={/** onChange: 짧은 담당 표시만 받습니다. */ event=>{setOwner(event.target.value);setSaved(false);}}/>
  <TextField label={ko?'조치 내용·근거 메모':'Action / evidence note'} multiline minRows={3} value={note} disabled={busy} slotProps={{htmlInput:{maxLength:1000}}} helperText={ko?'최대 1,000자 · 종료 시 근거 메모 필수 · 최근 30일 표시':'Up to 1,000 characters; note required for closure; visible for 30 days'} onChange={/** onChange: 원문 파일 대신 짧은 처리 근거를 받습니다. */ event=>{setNote(event.target.value);setSaved(false);}}/>
  <Button variant="outlined" disabled={busy||loading||!findingId||state==='closed'&&!note.trim()} onClick={save}>{busy?(ko?'저장 중':'Saving'):(ko?'조치 기록 저장':'Save remediation')}</Button>
  <Box component="details"><Typography component="summary">{ko?'최근 변경 이력 · 최대 20개':'Recent changes · up to 20'}</Typography>{history.map(/** map: 현재 회원의 최근 상태 변경을 표시합니다. */ entry=><Typography key={entry.id} variant="body2" sx={{mt:1,overflowWrap:'anywhere'}}>{new Date(entry.created_at).toLocaleString(locale)} · {stateLabels[entry.snapshot.state]?.[index]??'—'} · v{entry.snapshot.version}</Typography>)}</Box>
 </Stack>}</Paper>;
}
