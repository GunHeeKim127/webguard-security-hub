'use client';
import {useEffect,useRef,useState} from 'react';
import {Alert,Button,Checkbox,FormControlLabel,Paper,Stack,Typography} from '@mui/material';
import {protectedRequest} from '../../lib/protected-request';
import {errorText} from '../../lib/errors-i18n';
import type {AssessmentReport} from '../../lib/assessment/types';
import AssessmentFindings,{AssessmentInputSummary} from './assessment-findings';
export default function SourceInspection({locale,disabled}:{locale:'ko'|'en',disabled:boolean}){
 const t=(ko:string,en:string)=>locale==='ko'?ko:en;
 const [file,setFile]=useState<File|null>(null),[consent,setConsent]=useState(false),[busy,setBusy]=useState(false),[error,setError]=useState(''),[report,setReport]=useState<AssessmentReport|null>(null);
 const epoch=useRef(0),request=useRef<AbortController|null>(null);
 useEffect(()=>()=>{epoch.current++;request.current?.abort();},[]);
 async function inspect(){
  if(disabled||busy)return;
  if(!file){setError(t('검사할 파일을 먼저 선택해 주세요.','Select a file to inspect first.'));return;}
  if(!consent)return;
  const chosen=file,stamp=++epoch.current,controller=new AbortController();request.current=controller;setBusy(true);setError('');setReport(null);
  try{const text=await chosen.text();if(stamp!==epoch.current)return;if(new TextEncoder().encode(text).length>65536)throw new Error('BODY_TOO_LARGE');
   const response=await protectedRequest('/api/source-inspection',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({text,authorized:true}),signal:controller.signal});const data=await response.json();if(stamp!==epoch.current)return;
   if(!response.ok)throw new Error(data.errorCode??'SERVICE_UNAVAILABLE');setReport(data.report);setConsent(false);
  }catch(e){if(stamp===epoch.current&&!controller.signal.aborted)setError(errorText(locale,e instanceof Error?e.message:''));}finally{if(stamp===epoch.current)setBusy(false);}
 }
 return <Paper id="source-inspector" variant="outlined" sx={{p:{xs:2.5,sm:3.5},mt:3}}><Stack gap={1.5}>
  <Typography variant="h6">{t('소스·의존성 파일의 기술·취약점 검토','Source / dependency technology and advisory review')}</Typography>
  <Alert severity="info">{t('PHP·JS·TS·JSX·TSX 또는 package.json·package-lock.json·composer.json 파일 한 개를 확인합니다. 파일은 동의 후 서버 메모리에서 정적으로 분석하며 실행·저장·외부 AI 전송하지 않습니다. 결과는 이 화면에만 표시되며 새로고침하면 사라집니다. 전체 코드 보안 감사는 아닙니다.','Inspect one PHP / JS / TS / JSX / TSX or package.json / package-lock.json / composer.json file. With consent, it is statically analyzed in server memory without execution, storage or external AI. Results exist only on this screen and disappear on reload. This is not a full code security audit.')}</Alert>
  <Typography variant="body2">{t('비밀 키·비밀번호·.env 파일은 선택하지 마세요. 정확한 배포 버전은 잠금 파일과 실제 실행 버전 자료로 추가 확인해야 합니다.','Do not select secrets, passwords or .env files. Confirm exact deployed versions using lockfiles and runtime evidence.')}</Typography>
  <Button component="label" variant="outlined" disabled={disabled||busy}>{t('기기에서 파일 선택 · 최대 64 KiB','Choose a file · up to 64 KiB')}<input hidden type="file" accept=".php,.js,.jsx,.ts,.tsx,.json" disabled={disabled||busy} onChange={e=>{epoch.current++;request.current?.abort();setConsent(false);setReport(null);setError('');const chosen=e.target.files?.[0]??null;if(chosen&&(!/\.(?:php|[jt]sx?|json)$/i.test(chosen.name)||chosen.size===0||chosen.size>65536)){setFile(null);setError(t('지원하는 비어 있지 않은 64 KiB 이하 파일을 선택하세요.','Choose a supported nonempty file up to 64 KiB.'));}else setFile(chosen);}}/></Button>
  <Typography variant="body2" sx={{overflowWrap:'anywhere'}}>{file?.name??t('선택된 파일 없음','No file selected')}</Typography>
  <FormControlLabel control={<Checkbox checked={consent} disabled={!file||disabled||busy} onChange={e=>setConsent(e.target.checked)}/>} label={t('현재 파일의 읽기와 이번 검사에 한한 서버 전송에 동의합니다.','Allow reading and sending this file to the server for this inspection.')}/>
  <Button variant="contained" disabled={disabled||busy||!!file&&!consent} onClick={()=>void inspect()}>{busy?t('검사 중','Inspecting'):t('허용한 파일 검사','Inspect permitted file')}</Button>
  {error&&<Alert severity="warning" role="alert">{error}</Alert>}
  {report&&<><AssessmentInputSummary report={report} locale={locale}/><AssessmentFindings report={report} locale={locale} listId="source-finding-list"/></>}
 </Stack></Paper>;
}
