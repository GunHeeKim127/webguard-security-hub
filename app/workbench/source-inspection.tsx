'use client';
import InspectionProblem from './inspection-problem';
import {singleFileSelection,singleFileMessage} from '../../lib/single-file';

import {useEffect,useRef,useState} from 'react';
import {Alert,Button,Checkbox,FormControlLabel,Paper,Stack,Typography} from '@mui/material';
import {protectedRequest} from '../../lib/protected-request';
import {errorText} from '../../lib/errors-i18n';
import type {AssessmentReport} from '../../lib/assessment/types';
import AssessmentFindings,{AssessmentInputSummary} from './assessment-findings';
import InspectionHelp from './inspection-help';
/** SourceInspection: 소스 파일 선택·동의·검토 결과 표시를 관리합니다 주요 호출: useState·useRef·useEffect. */ export default function SourceInspection({locale,disabled}:{locale:'ko'|'en',disabled:boolean}){
 const t=/** t: 현재 화면 언어에 맞는 문구를 고릅니다 */ (ko:string,en:string)=>locale==='ko'?ko:en;
 const [file,setFile]=useState<File|null>(null),[consent,setConsent]=useState(false),[busy,setBusy]=useState(false),[error,setError]=useState(''),[report,setReport]=useState<AssessmentReport|null>(null);
 const epoch=useRef(0),request=useRef<AbortController|null>(null);
 useEffect(/** useEffect 콜백: 의존값에 따른 부수 작업과 정리를 실행합니다 */ ()=>/** useEffect 콜백: 의존값에 따른 부수 작업과 정리를 실행합니다 주요 호출: abort. */ ()=>{epoch.current++;request.current?.abort();},[]);
 /** inspect: 해당 자료의 관찰·검토 결과를 계산합니다 주요 호출: setError·t·setBusy. */ async function inspect(){
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
  <Typography variant="body2">{t('SQL을 사용하는 코드와 .sql 파일도 검토합니다. SQL 문자열 조합·Unsafe 실행 API·공개 권한·함수 검색 경로의 단서를 확인하고 필요한 추가 자료를 안내합니다. 실제 DB 접속·공격 시험·전체 코드 추적은 하지 않습니다.','SQL code and .sql files are also reviewed for construction, Unsafe APIs, public grants and function search-path hints. Results request missing evidence; no database connection, exploitation or full program tracing occurs.')}</Typography>
  <Alert severity="info">{t('PHP·JS·TS·JSX·TSX 또는 package.json·package-lock.json·composer.json 파일 한 개를 확인합니다. 파일은 동의 후 서버 메모리에서 정적으로 분석하며 실행·저장·외부 AI 전송하지 않습니다. 결과는 이 화면에만 표시되며 새로고침하면 사라집니다. 전체 코드 보안 감사는 아닙니다.','Inspect one PHP / JS / TS / JSX / TSX or package.json / package-lock.json / composer.json file. With consent, it is statically analyzed in server memory without execution, storage or external AI. Results exist only on this screen and disappear on reload. This is not a full code security audit.')}</Alert>
  <Typography variant="body2">{t('비밀 키·비밀번호·.env 파일은 선택하지 마세요. 정확한 배포 버전은 잠금 파일과 실제 실행 버전 자료로 추가 확인해야 합니다.','Do not select secrets, passwords or .env files. Confirm exact deployed versions using lockfiles and runtime evidence.')}</Typography>
  <Typography variant="body2">{singleFileMessage(locale)}</Typography>
  <InspectionHelp locale={locale} steps={[t('지원하는 소스·의존성·SQL 파일 하나를 선택합니다.','Choose one supported source, dependency or SQL file.'),t('현재 파일 읽기·서버 전송에 동의합니다.','Consent to reading and server transmission.'),t('허용한 파일 검사를 누릅니다. 결과는 이 화면에만 표시됩니다.','Select Inspect permitted file. Results appear only on this screen.')]} blockers={[...(disabled?[t('다른 작업이 끝날 때까지 기다리고 현재 계정의 검사 권한을 확인해 주세요.','Wait for other operations to finish and verify this account can inspect.')]:[]),...(!file?[t('검사할 파일을 먼저 선택하세요.','Choose a file first.')]:[]),...(!consent?[t('현재 파일의 읽기·서버 전송에 동의하세요. 재검사도 새 동의가 필요합니다.','Consent to reading and server transmission. Inspecting again requires renewed consent.')]:[]),...(busy?[t('파일 검사 중입니다. 잠시 기다려 주세요.','Inspection is running. Please wait.')]:[])]}/>
  <Button component="label" variant="outlined" disabled={disabled||busy}>{t('기기에서 파일 선택 · 최대 64 KiB','Choose a file · up to 64 KiB')}<input hidden type="file" multiple={false} accept=".php,.js,.jsx,.ts,.tsx,.json,.sql" disabled={disabled||busy} onChange={/** onChange 콜백: onChange 이벤트의 입력·상태 처리를 실행합니다 주요 호출: abort·setConsent·setReport. */ e=>{epoch.current++;request.current?.abort();setConsent(false);setReport(null);setError('');const selection=singleFileSelection(e.target.files),chosen=selection.file;if(selection.tooMany){e.target.value='';setFile(null);setError(singleFileMessage(locale));return;}if(chosen&&(!/\.(?:php|[jt]sx?|json|sql)$/i.test(chosen.name)||chosen.size===0||chosen.size>65536)){setFile(null);setError(t('지원하는 비어 있지 않은 64 KiB 이하 파일을 선택하세요.','Choose a supported nonempty file up to 64 KiB.'));}else setFile(chosen);}}/></Button>
  <Typography variant="body2" sx={{overflowWrap:'anywhere'}}>{file?.name??t('선택된 파일 없음','No file selected')}</Typography>
  <FormControlLabel control={<Checkbox checked={consent} disabled={!file||disabled||busy} onChange={/** onChange 콜백: onChange 이벤트의 입력·상태 처리를 실행합니다 주요 호출: setConsent. */ e=>setConsent(e.target.checked)}/>} label={t('현재 파일의 읽기와 이번 검사에 한한 서버 전송에 동의합니다.','Allow reading and sending this file to the server for this inspection.')}/>
  {file&&!consent&&!busy&&!disabled&&<Alert severity="info" role="status">{report?t('검사가 완료됐습니다. 같은 파일을 다시 검사하려면 읽기·서버 전송에 다시 동의해 주세요.','Inspection is complete. To inspect again, renew consent to reading and server transmission.'):t('검사를 시작하려면 위의 파일 읽기·서버 전송 동의에 체크해 주세요.','To start inspection, confirm file reading and server transmission above.')}</Alert>}
  <Button variant="contained" disabled={disabled||busy||!!file&&!consent} onClick={/** onClick 콜백: onClick 이벤트의 입력·상태 처리를 실행합니다 주요 호출: inspect. */ ()=>void inspect()}>{busy?t('검사 중','Inspecting'):t('허용한 파일 검사','Inspect permitted file')}</Button>
  <InspectionProblem locale={locale} message={error}/>
  {report&&<><AssessmentInputSummary report={report} locale={locale}/><AssessmentFindings report={report} locale={locale} listId="source-finding-list"/></>}
 </Stack></Paper>;
}
