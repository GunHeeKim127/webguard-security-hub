'use client';
import Link from './navigation-link';
import {useEffect,useRef,useState} from 'react';
import {ThemeProvider,createTheme,CssBaseline,Container,Box,Typography,Paper,TextField,Button,Alert,Chip,Stack,Checkbox,FormControlLabel,FormControl,InputLabel,Select,MenuItem,IconButton,InputAdornment} from '@mui/material';
import {isLocale,locales,localeNames,type Locale} from '../lib/locale';
import {messages,eventLabel,type MessageKey} from '../lib/messages';
import {errorText} from '../lib/errors-i18n';
import {canAssess} from '../lib/assessment-permission';
import {appendLog,readScanStream,type ScanLog} from '../lib/scan-run';
import {adviceCopy,localAdvice} from '../lib/local-advice';
import {registrationCopy} from '../lib/registration-copy';
import {scanUI} from '../lib/scan-ui';
import {assessmentText} from '../lib/assessment-copy';
import {scanTarget} from '../lib/scan-policy';
import OperationsPanel from './operations-panel';
import InspectionHelp from './workbench/inspection-help';
import PageLoading from './page-loading';
import WebTargetField from './web-target-field';
import InspectionProblem from './workbench/inspection-problem';
import {webTargetInput,webTargetReason} from '../lib/web-target-input';
import DefensePanel from './defense-panel';
import LoginIllustration from './login-illustration';
import {defenseText} from '../lib/defense-copy';
import {operationsMessages} from '../lib/operations-messages';
import type {Dashboard,Inspection,Operation,OperationState} from '../lib/inspection';

const theme=createTheme({palette:{mode:'dark',primary:{main:'#66e6c3'},background:{default:'#091321',paper:'#111f31'}},typography:{fontFamily:'Arial, sans-serif'},shape:{borderRadius:14}});
const headerKeys:Record<string,MessageKey>={'content-security-policy':'csp','strict-transport-security':'hsts','x-content-type-options':'nosniff','referrer-policy':'referrer'};

/** Home: 로그인과 웹 점검의 세션·작업 화면을 관리합니다 주요 호출: useState·useRef·useEffect. */ export default function Home({initialLocale}:{initialLocale:Locale}){
 const [adviceExpanded,setAdviceExpanded]=useState(true);
 const [passwordVisible,setPasswordVisible]=useState(false);
 const [locale,setLocale]=useState(initialLocale),[data,setData]=useState<Dashboard|null>(null),[code,setCode]=useState(''),[busy,setBusy]=useState(false),[switching,setSwitching]=useState(false),[advice,setAdvice]=useState(''),[authorized,setAuthorized]=useState(false);
 const [inspection,setInspection]=useState<Inspection>({state:'idle',target:''}),[operation,setOperation]=useState<OperationState>(null),[activity,setActivity]=useState<NonNullable<OperationState>[]>([]),[targetValue,setTargetValue]=useState('');
 const [logs,setLogs]=useState<ScanLog[]>([]);const scanRequest=useRef<AbortController|null>(null),generation=useRef(0);
 const accountGeneration=useRef(0),sessionChannel=useRef<BroadcastChannel|null>(null);
 useEffect(/** useEffect 콜백: 의존값에 따른 부수 작업과 정리를 실행합니다 */ ()=>/** useEffect 콜백: 의존값에 따른 부수 작업과 정리를 실행합니다 주요 호출: abort. */ ()=>scanRequest.current?.abort(),[]);
 const [adviceInfo,setAdviceInfo]=useState<{source:string,reasonCode?:string,provider?:string,model?:string,inputTokens?:number,outputTokens?:number}|null>(null);
 const [bootLoading,setBootLoading]=useState(true);
 const t=messages[locale],ops=operationsMessages[locale],scanCopy=scanUI[locale];
 /** resetAccountView: 계정에 종속된 화면 정보를 초기화합니다 주요 호출: abort·setData·setAdvice. */ function resetAccountView(loading=false){accountGeneration.current++;generation.current++;scanRequest.current?.abort();scanRequest.current=null;setData(null);setAdvice('');setAdviceInfo(null);setAuthorized(false);setTargetValue('');setInspection({state:'idle',target:''});setLogs([]);setCode('');setOperation(null);setActivity([]);setBusy(false);setBootLoading(loading);}
 /** changeTarget: 점검 대상을 바꾸고 관련 작업 상태를 갱신합니다 주요 호출: abort·setBusy·setTargetValue. */ function changeTarget(value:string){if(value===targetValue)return;generation.current++;if(scanRequest.current){scanRequest.current.abort();setBusy(false);}scanRequest.current=null;setTargetValue(value);setAuthorized(false);setInspection({state:'idle',target:''});setLogs([]);setCode('');setOperation(null);setActivity([]);setAdvice('');}
 const targetInput=webTargetInput(targetValue),normalizedTarget=targetInput.normalized;
 const publicTargets=data?.overview.targetPolicy==='public';
 let targetApproved=false;try{scanTarget(normalizedTarget,publicTargets?undefined:data?.overview.approvedHosts??[]);targetApproved=true;}catch{}
 const blockReason=targetInput.issue?webTargetReason(targetInput.issue,locale):!authorized?scanCopy.permission:!canAssess(data?.user.role??'')?t.viewerHelp:!publicTargets&&data?.overview.approvedCount===0?ops.notConfigured:!targetApproved?(publicTargets?assessmentText(locale,'targetInvalid'):scanCopy.unapproved):'';
 /** runScan: 선택한 대상의 검사 요청과 진행 상태를 관리합니다 주요 호출: abort·setTargetValue·setLogs. */ async function runScan(){
  const url=normalizedTarget;scanRequest.current?.abort();const request=new AbortController(),run=++generation.current;scanRequest.current=request;
  setTargetValue(url);setLogs([]);setCode('');setAdvice('');setInspection({state:'running',target:url});setBusy(true);markOperation('scan','running');
  const current=/** current: 요청한 자료나 현재 상태를 조회합니다 */ ()=>generation.current===run&&!request.signal.aborted;
  try{const response=await fetch('/api/scans',{method:'POST',headers:{'Content-Type':'application/json',Accept:'application/x-ndjson'},body:JSON.stringify({url,authorized}),signal:request.signal});
   if(!response.ok){const error=await response.json();throw {errorCode:error.errorCode??'SERVICE_UNAVAILABLE'};}
   if(!response.body)throw new Error('Missing stream');
   await readScanStream(response.body,/** readScanStream 콜백: readScanStream에서 전달한 값을 처리하는 콜백입니다 주요 호출: current·setLogs·setInspection. */ event=>{if(!current())return;setLogs(/** setLogs 콜백: setLogs의 이전 상태로부터 다음 상태를 계산합니다 주요 호출: appendLog. */ old=>appendLog(old,event));
    if(event.type==='result'){setInspection({state:'success',target:url,result:event.result,recordId:event.id});markOperation('scan','success');}
    if(event.type==='error'){setCode(event.errorCode);setInspection({state:'error',target:url});markOperation('scan','error');}
   });if(current())await load(false);
  }catch(error){if(!current())return;const code=typeof error==='object'&&error&&'errorCode' in error?String(error.errorCode):'NETWORK_ERROR';setCode(code);setLogs(/** setLogs 콜백: setLogs의 이전 상태로부터 다음 상태를 계산합니다 주요 호출: appendLog·toISOString. */ old=>appendLog(old,{type:'error',errorCode:code,at:new Date().toISOString()}));setInspection({state:'error',target:url});markOperation('scan','error');}
  finally{if(current()){setBusy(false);scanRequest.current=null;}}
 }
 /** markOperation: 사용자 작업의 진행 상태를 반영합니다 주요 호출: toISOString·setOperation·setActivity. */ function markOperation(kind:Operation,state:'running'|'success'|'error'){const item={kind,state,at:new Date().toISOString()};setOperation(item);if(state!=='running')setActivity(/** setActivity 콜백: setActivity의 이전 상태로부터 다음 상태를 계산합니다 주요 호출: slice. */ old=>[item,...old].slice(0,8));}
 const message=code==='THREAT_BLOCKED'?defenseText(locale,'temporary'):code==='IP_BLACKLISTED'?defenseText(locale,'permanent'):code==='PROTECTION_UNAVAILABLE'?defenseText(locale,'unavailable'):code==='NETWORK_ERROR'?t.networkError:code==='SWITCH_ERROR'?t.switchError:code==='INVALID_EMAIL'?t.invalidEmail:code==='REQUIRED'?t.required:code?errorText(locale,code):'';
 useEffect(/** useEffect 콜백: 의존값에 따른 부수 작업과 정리를 실행합니다 */ ()=>{document.documentElement.lang=locale;document.title=`WebGuard · ${messages[locale].title}`;},[locale]);
 /** load: 요청한 자료나 현재 상태를 조회합니다 주요 호출: markOperation·fetch·json. */ async function load(record=true){const epoch=accountGeneration.current;if(record)markOperation('refresh','running');try{
  const r=await fetch('/api/dashboard',{cache:'no-store'});const json=await r.json();
  if(epoch!==accountGeneration.current)return;
  if(r.ok){setData(json);if(record)markOperation('refresh','success');}
  else {if(record)markOperation('refresh','error');if(r.status===401)resetAccountView();else setCode(json.errorCode??'SERVICE_UNAVAILABLE');}
 }catch{if(epoch===accountGeneration.current){setCode('NETWORK_ERROR');if(record)markOperation('refresh','error');}}finally{if(epoch===accountGeneration.current)setBootLoading(false);}}
 useEffect(/** useEffect 콜백: 의존값에 따른 부수 작업과 정리를 실행합니다 주요 호출: load. */ ()=>{void load(false);},[]);
 useEffect(/** useEffect 콜백: 의존값에 따른 부수 작업과 정리를 실행합니다 주요 호출: addEventListener. */ ()=>{
  const refreshSession=/** refreshSession: 현재 세션을 다시 확인해 사용자 상태를 갱신합니다 주요 호출: resetAccountView·load. */ ()=>{resetAccountView(true);void load(false);};
  const restored=/** restored: 뒤로 가기 캐시 복원 시 세션과 화면 상태를 다시 확인합니다 주요 호출: refreshSession. */ (event:PageTransitionEvent)=>{if(event.persisted)refreshSession();};
  try{if(typeof BroadcastChannel!=='undefined'){sessionChannel.current=new BroadcastChannel('webguard-session');sessionChannel.current.onmessage=/** 처리 콜백: 처리에서 전달한 값을 처리하는 콜백입니다 주요 호출: refreshSession. */ event=>{if(event.data==='changed')refreshSession();};}}catch{sessionChannel.current=null;}
  window.addEventListener('pageshow',restored);
  return/** useEffect 콜백: 의존값에 따른 부수 작업과 정리를 실행합니다 주요 호출: close·removeEventListener. */ ()=>{sessionChannel.current?.close();sessionChannel.current=null;window.removeEventListener('pageshow',restored);};
 },[]);
 /** post: 전달된 자료를 결과·상태·출력에 반영합니다 주요 호출: setBusy·setCode·markOperation. */ async function post(path:string,payload:unknown,current=/** 처리 콜백: 처리에서 전달한 값을 처리하는 콜백입니다 */ ()=>true){if(path==='/api/login'||path==='/api/logout')accountGeneration.current++;const epoch=accountGeneration.current,isCurrent=/** isCurrent: 현재 응답이 최신 작업에 속하는지 확인합니다 주요 호출: current. */ ()=>epoch===accountGeneration.current&&current();setBusy(true);setCode('');const kind:Operation=path==='/api/login'?'login':path==='/api/logout'?'logout':path==='/api/ai'?'ai':'scan';markOperation(kind,'running');try{
  const r=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});const json=await r.json();
  if(!isCurrent())return null;
  if(!r.ok){setCode(json.errorCode??'SERVICE_UNAVAILABLE');markOperation(kind,'error');return null;}markOperation(kind,'success');if(kind==='login'||kind==='logout'){try{sessionChannel.current?.postMessage('changed');}catch{/* Tab notifications are optional; the authenticated response remains valid. */}}return json;
 }catch{if(isCurrent()){setCode('NETWORK_ERROR');markOperation(kind,'error');}return null;}finally{if(epoch===accountGeneration.current)setBusy(false);}}
 /** changeLanguage: 언어 변경 요청과 화면 언어 상태를 반영합니다 주요 호출: isLocale·setSwitching·fetch. */ async function changeLanguage(value:unknown){if(!isLocale(value))return;setSwitching(true);try{
  const r=await fetch('/api/locale',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({locale:value})});
  if(!r.ok){setCode('SWITCH_ERROR');return;}setLocale(value);setAdvice('');
 }catch{setCode('NETWORK_ERROR');}finally{setSwitching(false);}}
 const roleLabel=data?(['admin','analyst','viewer'].includes(data.user.role)?t[data.user.role as 'admin'|'analyst'|'viewer']:t.viewer):'';
 const languageControl=<FormControl size="small" sx={{minWidth:{xs:112,sm:150}}} disabled={busy||switching}>
  <InputLabel id="language-label">{t.language}</InputLabel>
  <Select labelId="language-label" id="language-select" label={t.language} value={locale} onChange={/** onChange 콜백: onChange 이벤트의 입력·상태 처리를 실행합니다 주요 호출: changeLanguage. */ e=>void changeLanguage(e.target.value)}>
   {locales.map(/** map 콜백: 각 항목을 필요한 값으로 변환합니다 */ l=><MenuItem key={l} value={l} lang={l}>{localeNames[l]}</MenuItem>)}
  </Select>
 </FormControl>;
 return <ThemeProvider theme={theme}><CssBaseline/><Container maxWidth="lg" sx={{py:{xs:data?3:1.5,md:5},...(!data?{minHeight:'100svh',display:'flex',flexDirection:'column',justifyContent:'center'}:{})}}>
  {data&&<><Stack component="header" direction="row" flexWrap="wrap" gap={2} justifyContent="space-between" alignItems="center">
   <Typography variant="h6" color="primary">◈ WEBGUARD</Typography>
   <Stack direction="row" gap={2} alignItems="center" flexWrap="wrap">
    <Button component={Link} href="/help">{locale==='ko'?'사용 가이드':'User guide'}</Button><Button component={Link} href="/workbench/web" variant="outlined">{locale==='ko'?'PC·모바일 응답 비교':'Desktop/mobile response comparison'}</Button><Button component={Link} href="/workbench" variant="outlined">{locale==='ko'?'검사 선택':'Choose a check'}</Button><Chip label={t.local} variant="outlined"/>{languageControl}
   </Stack>
  </Stack>
  <Box sx={{my:3}}><Typography variant="overline" color="primary">{t.operations}</Typography><Typography variant="h3" fontWeight={800}>{t.title}</Typography><Typography color="text.secondary" sx={{mt:2}}>{t.intro}</Typography>{inspection.state!=='idle'&&<Button href="#inspection-console" variant="outlined" size="small" sx={{mt:2}}>{ops.title} ↓</Button>}</Box></>}
  {data&&<InspectionProblem locale={locale==='ko'?'ko':'en'} message={message}/>}
  {bootLoading?<PageLoading message={ops.refresh}/>:!data?<Box component="main" sx={{display:'grid',gridTemplateColumns:{xs:'1fr',md:'minmax(0,1fr) minmax(0,1.1fr)'},gap:{xs:3,md:6},alignItems:'center'}}>
   <Paper component="section" elevation={0} sx={{p:{xs:3,sm:4,md:5},border:'1px solid #26394b',background:'linear-gradient(145deg,#142537,#101d2d)'}}>
   <Stack direction="row" justifyContent="space-between" alignItems="center" gap={2} flexWrap="wrap" sx={{mb:{xs:2,md:5}}}><Typography color="primary" fontWeight={700} sx={{letterSpacing:1}}>◈ WEBGUARD</Typography>{languageControl}</Stack>
   <Typography variant="overline" color="primary">{t.operations}</Typography>
   <Typography component="h1" variant="h4" fontWeight={800} sx={{mt:1,mb:2}}>{t.loginTitle}</Typography><Typography color="text.secondary" mb={{xs:2,md:4}} sx={{lineHeight:1.7}}>{registrationCopy[locale].help}</Typography>
   {message&&<Alert severity="warning" sx={{mb:3}} role="alert">{message}</Alert>}
   <Box component="form" noValidate onSubmit={/** onSubmit 콜백: onSubmit 이벤트의 입력·상태 처리를 실행합니다 주요 호출: preventDefault·namedItem·setCode. */ async e=>{
    e.preventDefault();setPasswordVisible(false);const form=e.currentTarget;const email=form.elements.namedItem('email') as HTMLInputElement;const password=form.elements.namedItem('password') as HTMLInputElement;
    if(!email.value||!password.value){setCode('REQUIRED');(!email.value?email:password).focus();return;}
    if(!email.validity.valid){setCode('INVALID_EMAIL');email.focus();return;}
    if(await post('/api/login',{email:email.value,password:password.value}))window.location.replace('/workbench');
   }}><Stack spacing={2}>
    <TextField name="email" label={t.email} type="email" autoComplete="username" required/>
    <TextField name="password" label={t.password} type={passwordVisible?'text':'password'} autoComplete="current-password" required slotProps={{input:{endAdornment:<InputAdornment position="end"><IconButton type="button" aria-label={locale==='ko'?(passwordVisible?'비밀번호 숨기기':'비밀번호 보기'):(passwordVisible?'Hide password':'Show password')} aria-pressed={passwordVisible} edge="end" onMouseDown={/** onMouseDown 콜백: 토글 사용 시 비밀번호 입력 포커스를 유지합니다. */ e=>e.preventDefault()} onClick={/** onClick 콜백: 비밀번호 값과 전송 방식은 유지하고 표시만 전환합니다. */ ()=>setPasswordVisible(!passwordVisible)}><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" aria-hidden="true"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12Z"/><circle cx="12" cy="12" r="3"/>{!passwordVisible&&<path d="m3 3 18 18"/>}</svg></IconButton></InputAdornment>}}}/>
    <Button type="submit" variant="contained" disabled={busy||switching}>{busy?t.loading:t.login}</Button><Button component={Link} href="/signup" disabled={busy}>{registrationCopy[locale].title}</Button><Button component={Link} href="/help">{locale==='ko'?'사용 가이드':'User guide'}</Button>
   </Stack></Box>
   </Paper>
   <Box data-login-illustration="true" sx={{display:{xs:'none',md:'block'},minWidth:0,textAlign:'center',px:{md:0}}}><Box sx={{maxWidth:580,mx:'auto'}}><LoginIllustration/></Box><Typography color="primary" variant="overline" sx={{letterSpacing:3}}>WEBGUARD</Typography><Typography color="text.secondary" sx={{mt:1,mx:'auto',maxWidth:400,lineHeight:1.8}}>{t.intro}</Typography></Box>
  </Box>:<>
   <Stack direction="row" gap={2} mb={3} alignItems="center" flexWrap="wrap">
    <Chip label={roleLabel}/><Typography sx={{overflowWrap:'anywhere'}}>{data.user.email}</Typography>
    <Button disabled={busy} onClick={/** onClick 콜백: onClick 이벤트의 입력·상태 처리를 실행합니다 주요 호출: post·resetAccountView. */ async()=>{if(await post('/api/logout',{}))resetAccountView();}}>{t.logout}</Button><Button disabled={busy||operation?.state==='running'} onClick={/** onClick 콜백: onClick 이벤트의 입력·상태 처리를 실행합니다 주요 호출: load. */ ()=>void load()}>{t.refresh}</Button>
   </Stack>
   {!canAssess(data.user.role)&&<Alert severity="info" sx={{mb:3}}>{t.viewerHelp}</Alert>}
   <Box>
    <Paper sx={{p:3}}><Typography variant="h6">{assessmentText(locale,'title')}</Typography><Typography color="text.secondary" my={2}>{assessmentText(locale,'scope')}</Typography>
     <Box component="form" noValidate onSubmit={/** onSubmit 콜백: onSubmit 이벤트의 입력·상태 처리를 실행합니다 주요 호출: preventDefault·runScan. */ e=>{e.preventDefault();if(blockReason||busy||switching)return;void runScan();}}><Stack spacing={2}>
      <WebTargetField locale={locale} value={targetValue} disabled={busy&&!scanRequest.current} onChange={changeTarget}/>
      <FormControlLabel control={<Checkbox checked={authorized} onChange={/** onChange 콜백: onChange 이벤트의 입력·상태 처리를 실행합니다 주요 호출: setAuthorized. */ e=>setAuthorized(e.target.checked)}/>} label={assessmentText(locale,'ownership')}/>
      {publicTargets&&<Alert severity="info">{assessmentText(locale,'publicNotice')}</Alert>}
      <Button type="submit" variant="contained" disabled={busy||switching||!!blockReason} aria-describedby={blockReason?'scan-block-reason':undefined}>{busy?t.loading:assessmentText(locale,'title')}</Button>
      {blockReason&&<Alert id="scan-block-reason" severity="info">{blockReason}</Alert>}
      <InspectionHelp locale={locale==='ko'?'ko':'en'} blockers={[...(blockReason?[blockReason]:[]),...(busy||switching?[locale==='ko'?'현재 작업이 끝날 때까지 기다려 주세요.':'Wait for the current operation to finish.']:[])]} steps={locale==='ko'?['본인 또는 점검 허가가 있는 공개 HTTPS 주소를 입력합니다.','소유·진단 허가 및 분석 동의를 확인합니다.','웹 기본 보안 진단을 누르고 진행 단계와 저장된 결과를 확인합니다.']:['Enter an authorized public HTTPS URL.','Confirm ownership/permission and assessment consent.','Start the web baseline check, then review progress and saved results.']}/>
      <Typography variant="caption" color="text.secondary">{scanCopy.reset}</Typography>
     </Stack></Box>
    </Paper>
    {inspection.state!=='idle'&&<Box sx={{mt:3}}><OperationsPanel locale={locale} data={data} inspection={inspection} operation={operation} activity={activity} logs={logs}/></Box>}
    <Paper sx={{p:3,mt:3}}><Typography variant="h6">{t.eventsTitle}</Typography><Typography color="text.secondary" my={2}>{t.eventsHelp}</Typography>
     {data.events.length?data.events.map(/** map 콜백: 각 항목을 필요한 값으로 변환합니다 주요 호출: eventLabel·format. */ e=><Stack key={e.category} direction="row" justifyContent="space-between" gap={1} py={1}><Typography>{eventLabel(locale,e.category)}</Typography><Chip label={new Intl.NumberFormat(locale).format(e.count)}/></Stack>):<Typography>{t.noEvents}</Typography>}
     <Alert severity="info" sx={{mt:2}}>{defenseText(locale,'scope')}</Alert>
    </Paper>
    {data.user.role==='admin'&&data.ipBlocks&&<DefensePanel locale={locale} blocks={data.ipBlocks} accounts={data.accountBlocks??[]} onReleased={/** onReleased 콜백: onReleased 이벤트의 입력·상태 처리를 실행합니다 주요 호출: load. */ ()=>void load(false)}/>}
   </Box>
   <Paper sx={{p:3,mt:3}}><Typography variant="h6" mb={2}>{t.history}</Typography>
    {data.scans.length===0&&<Typography color="text.secondary">{t.noScans}</Typography>}
    {data.scans.map(/** map 콜백: 각 항목을 필요한 값으로 변환합니다 주요 호출: toLocaleString·map·canAssess. */ s=><Box key={s.id} sx={{borderTop:'1px solid #29384b',py:3}}>
     <Typography fontWeight={700} sx={{overflowWrap:'anywhere'}}>{s.hostname} · HTTP {s.result.status}</Typography>
     <Button size="small" onClick={/** onClick 콜백: onClick 이벤트의 입력·상태 처리를 실행합니다 주요 호출: changeTarget·setTargetValue·setLogs. */ ()=>{changeTarget('https://'+s.hostname);setTargetValue('https://'+s.hostname);setLogs([]);setInspection({state:'success',target:'https://'+s.hostname,result:s.result,recordId:s.id});requestAnimationFrame(/** requestAnimationFrame 콜백: requestAnimationFrame에서 전달한 값을 처리하는 콜백입니다 주요 호출: scrollIntoView·getElementById·matchMedia. */ ()=>document.getElementById('inspection-console')?.scrollIntoView({behavior:window.matchMedia('(prefers-reduced-motion: reduce)').matches?'auto':'smooth'}));}}>{ops.choose}</Button>
     <Typography variant="caption" color="text.secondary">{new Date(s.created_at).toLocaleString(locale)}</Typography>
     <Stack direction="row" flexWrap="wrap" gap={1} my={2}>{s.result.checks.map(/** map 콜백: 각 항목을 필요한 값으로 변환합니다 주요 호출: find·assessmentText. */ c=>{const detail=s.result.assessment?.find(/** find 콜백: 조건에 맞는 첫 항목을 찾습니다 */ item=>item.id===headerKeys[c.header]);return <Chip key={c.header} title={c.header} color={detail?(detail.status==='pass'?'success':detail.status==='warning'?'warning':'default'):c.present?'default':'warning'} variant="outlined" label={`${t[headerKeys[c.header]??'scanTitle']}: ${detail?assessmentText(locale,detail.status):c.present?t.present:t.missing}`}/>;})}</Stack>
     <Stack direction="row" gap={1} flexWrap="wrap"><Button variant="outlined" onClick={/** onClick 콜백: onClick 이벤트의 입력·상태 처리를 실행합니다 주요 호출: localAdvice·setAdviceExpanded·setAdvice. */ ()=>{const next=localAdvice(locale,s.result.checks);setAdviceExpanded(advice===next&&adviceInfo?.source==='local'?!adviceExpanded:true);setAdvice(next);setAdviceInfo({source:'local'});}}>{adviceCopy[locale].button}</Button>
     <Button disabled={busy||switching||!data.aiEnabled||!canAssess(data.user.role)} onClick={/** onClick 콜백: onClick 이벤트의 입력·상태 처리를 실행합니다 주요 호출: setAdvice·setAdviceInfo·setAdviceExpanded. */ async()=>{setAdvice('');setAdviceInfo(null);setAdviceExpanded(true);const run=generation.current;const r=await post('/api/ai',{scanId:s.id},/** post 콜백: post에서 전달한 값을 처리하는 콜백입니다 */ ()=>generation.current===run);if(r&&typeof r.advice==='string'){setAdvice(r.advice);setAdviceInfo(r);}}}>{t.ai}</Button></Stack>
     <Typography variant="caption" color="text.secondary" display="block" mt={1}>{adviceCopy[locale].note}</Typography>
    </Box>)}
    {!data.aiEnabled&&<Typography color="text.secondary" variant="body2" sx={{mt:2}}>{t.aiDisabled}</Typography>}
    {advice&&<Alert severity={adviceInfo?.reasonCode?'warning':'info'} sx={{mt:2}}><Typography fontWeight={700}>{adviceInfo?.source==='local'?adviceCopy[locale].local:adviceInfo?.source==='cache'?adviceCopy[locale].cache:adviceCopy[locale].ai}</Typography>
     <Button size="small" aria-expanded={adviceExpanded} aria-controls="saved-advice-content" onClick={/** onClick 콜백: onClick 이벤트의 입력·상태 처리를 실행합니다 주요 호출: setAdviceExpanded. */ ()=>setAdviceExpanded(/** setAdviceExpanded 콜백: setAdviceExpanded의 이전 상태로부터 다음 상태를 계산합니다 */ value=>!value)}>{assessmentText(locale,adviceExpanded?'hide':'show')}</Button>
     <Box id="saved-advice-content" hidden={!adviceExpanded}>
     {adviceInfo?.reasonCode&&<Typography variant="body2" mb={2}>{adviceInfo.reasonCode==='AI_IN_PROGRESS'?adviceCopy[locale].pending:errorText(locale,adviceInfo.reasonCode)}</Typography>}
     {adviceInfo?.provider&&<Typography variant="caption" display="block">{adviceInfo.provider==='groq'?'Groq':adviceInfo.provider==='gemini'?'Gemini':'OpenAI'} · {adviceInfo.model}</Typography>}
     {adviceInfo?.source==='ai'&&<Typography variant="caption" display="block">{adviceCopy[locale].usage}: {(adviceInfo.inputTokens??0)+(adviceInfo.outputTokens??0)}</Typography>}
     <Typography sx={{whiteSpace:'pre-wrap'}}>{advice}</Typography></Box></Alert>}
   </Paper>
  </>}
  <Typography color="text.secondary" variant="body2" sx={{mt:4,display:data?'block':{xs:'none',md:'block'}}}>{t.disclaimer}</Typography>
 </Container></ThemeProvider>;
}
