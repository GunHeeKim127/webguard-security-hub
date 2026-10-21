'use client';
import {useEffect,useRef,useState} from 'react';
import {ThemeProvider,CssBaseline,Container,Box,Typography,Paper,TextField,Button,Alert,Chip,Stack,Checkbox,FormControlLabel,FormControl,InputLabel,Select,MenuItem,LinearProgress} from '@mui/material';
import {isLocale,locales,localeNames,type Locale} from '../lib/locale';
import {messages,eventLabel,type MessageKey} from '../lib/messages';
import {errorText} from '../lib/errors-i18n';
import {appendLog,readScanStream,type ScanLog} from '../lib/scan-run';
import {adviceCopy,localAdvice} from '../lib/local-advice';
import {registrationCopy} from '../lib/registration-copy';
import {scanUI} from '../lib/scan-ui';
import {assessmentText} from '../lib/assessment-copy';
import {scanTarget} from '../lib/scan-policy';
import OperationsPanel from './operations-panel';
import DefensePanel from './defense-panel';
import LoginIllustration from './login-illustration';
import {defenseText} from '../lib/defense-copy';
import {operationsMessages} from '../lib/operations-messages';
import type {Dashboard,Inspection,Operation,OperationState} from '../lib/inspection';
import {platformTheme} from './platform-theme';

const headerKeys:Record<string,MessageKey>={'content-security-policy':'csp','strict-transport-security':'hsts','x-content-type-options':'nosniff','referrer-policy':'referrer'};

export default function Home({initialLocale}:{initialLocale:Locale}){
 const [adviceExpanded,setAdviceExpanded]=useState(true);
 const [locale,setLocale]=useState(initialLocale),[data,setData]=useState<Dashboard|null>(null),[code,setCode]=useState(''),[busy,setBusy]=useState(false),[switching,setSwitching]=useState(false),[advice,setAdvice]=useState(''),[authorized,setAuthorized]=useState(false);
 const [inspection,setInspection]=useState<Inspection>({state:'idle',target:''}),[operation,setOperation]=useState<OperationState>(null),[activity,setActivity]=useState<NonNullable<OperationState>[]>([]),[targetValue,setTargetValue]=useState('');
 const [logs,setLogs]=useState<ScanLog[]>([]);const scanRequest=useRef<AbortController|null>(null),generation=useRef(0);
 const accountGeneration=useRef(0),sessionChannel=useRef<BroadcastChannel|null>(null);
 useEffect(()=>()=>scanRequest.current?.abort(),[]);
 const [adviceInfo,setAdviceInfo]=useState<{source:string,reasonCode?:string,provider?:string,model?:string,inputTokens?:number,outputTokens?:number}|null>(null);
 const [bootLoading,setBootLoading]=useState(true);
 const t=messages[locale],ops=operationsMessages[locale],scanCopy=scanUI[locale];
 function resetAccountView(loading=false){accountGeneration.current++;generation.current++;scanRequest.current?.abort();scanRequest.current=null;setData(null);setAdvice('');setAdviceInfo(null);setAuthorized(false);setTargetValue('');setInspection({state:'idle',target:''});setLogs([]);setCode('');setOperation(null);setActivity([]);setBusy(false);setBootLoading(loading);}
 function changeTarget(value:string){if(value===targetValue)return;generation.current++;if(scanRequest.current){scanRequest.current.abort();setBusy(false);}scanRequest.current=null;setTargetValue(value);setAuthorized(false);setInspection({state:'idle',target:''});setLogs([]);setCode('');setOperation(null);setActivity([]);setAdvice('');}
 const normalizedTarget=targetValue.trim().includes('://')?targetValue.trim():'https://'+targetValue.trim();
 const publicTargets=data?.overview.targetPolicy==='public';
 let targetApproved=false;try{scanTarget(normalizedTarget,publicTargets?undefined:data?.overview.approvedHosts??[]);targetApproved=true;}catch{}
 const blockReason=!targetValue.trim()?scanCopy.address:!authorized?scanCopy.permission:data?.user.role==='viewer'?t.viewerHelp:!publicTargets&&data?.overview.approvedCount===0?ops.notConfigured:!targetApproved?(publicTargets?assessmentText(locale,'targetInvalid'):scanCopy.unapproved):'';
 async function runScan(){
  const url=normalizedTarget;scanRequest.current?.abort();const request=new AbortController(),run=++generation.current;scanRequest.current=request;
  setTargetValue(url);setLogs([]);setCode('');setAdvice('');setInspection({state:'running',target:url});setBusy(true);markOperation('scan','running');
  const current=()=>generation.current===run&&!request.signal.aborted;
  try{const response=await fetch('/api/scans',{method:'POST',headers:{'Content-Type':'application/json',Accept:'application/x-ndjson'},body:JSON.stringify({url,authorized}),signal:request.signal});
   if(!response.ok){const error=await response.json();throw {errorCode:error.errorCode??'SERVICE_UNAVAILABLE'};}
   if(!response.body)throw new Error('Missing stream');
   await readScanStream(response.body,event=>{if(!current())return;setLogs(old=>appendLog(old,event));
    if(event.type==='result'){setInspection({state:'success',target:url,result:event.result,recordId:event.id});markOperation('scan','success');}
    if(event.type==='error'){setCode(event.errorCode);setInspection({state:'error',target:url});markOperation('scan','error');}
   });if(current())await load(false);
  }catch(error){if(!current())return;const code=typeof error==='object'&&error&&'errorCode' in error?String(error.errorCode):'NETWORK_ERROR';setCode(code);setLogs(old=>appendLog(old,{type:'error',errorCode:code,at:new Date().toISOString()}));setInspection({state:'error',target:url});markOperation('scan','error');}
  finally{if(current()){setBusy(false);scanRequest.current=null;}}
 }
 function markOperation(kind:Operation,state:'running'|'success'|'error'){const item={kind,state,at:new Date().toISOString()};setOperation(item);if(state!=='running')setActivity(old=>[item,...old].slice(0,8));}
 const message=code==='THREAT_BLOCKED'?defenseText(locale,'temporary'):code==='IP_BLACKLISTED'?defenseText(locale,'permanent'):code==='PROTECTION_UNAVAILABLE'?defenseText(locale,'unavailable'):code==='NETWORK_ERROR'?t.networkError:code==='SWITCH_ERROR'?t.switchError:code==='INVALID_EMAIL'?t.invalidEmail:code==='REQUIRED'?t.required:code?errorText(locale,code):'';
 useEffect(()=>{document.documentElement.lang=locale;document.title=`VELTHARA · ${messages[locale].title}`;},[locale]);
 async function load(record=true){const epoch=accountGeneration.current;if(record)markOperation('refresh','running');try{
  const r=await fetch('/api/dashboard',{cache:'no-store'});const json=await r.json();
  if(epoch!==accountGeneration.current)return;
  if(r.ok){setData(json);if(record)markOperation('refresh','success');}
  else {if(record)markOperation('refresh','error');if(r.status===401)resetAccountView();else setCode(json.errorCode??'SERVICE_UNAVAILABLE');}
 }catch{if(epoch===accountGeneration.current){setCode('NETWORK_ERROR');if(record)markOperation('refresh','error');}}finally{if(epoch===accountGeneration.current)setBootLoading(false);}}
 useEffect(()=>{void load(false);},[]);
 useEffect(()=>{
  const refreshSession=()=>{resetAccountView(true);void load(false);};
  const restored=(event:PageTransitionEvent)=>{if(event.persisted)refreshSession();};
  try{if(typeof BroadcastChannel!=='undefined'){sessionChannel.current=new BroadcastChannel('webguard-session');sessionChannel.current.onmessage=event=>{if(event.data==='changed')refreshSession();};}}catch{sessionChannel.current=null;}
  window.addEventListener('pageshow',restored);
  return()=>{sessionChannel.current?.close();sessionChannel.current=null;window.removeEventListener('pageshow',restored);};
 },[]);
 async function post(path:string,payload:unknown,current=()=>true){if(path==='/api/login'||path==='/api/logout')accountGeneration.current++;const epoch=accountGeneration.current,isCurrent=()=>epoch===accountGeneration.current&&current();setBusy(true);setCode('');const kind:Operation=path==='/api/login'?'login':path==='/api/logout'?'logout':path==='/api/ai'?'ai':'scan';markOperation(kind,'running');try{
  const r=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});const json=await r.json();
  if(!isCurrent())return null;
  if(!r.ok){setCode(json.errorCode??'SERVICE_UNAVAILABLE');markOperation(kind,'error');return null;}markOperation(kind,'success');if(kind==='login'||kind==='logout'){try{sessionChannel.current?.postMessage('changed');}catch{/* Tab notifications are optional; the authenticated response remains valid. */}}return json;
 }catch{if(isCurrent()){setCode('NETWORK_ERROR');markOperation(kind,'error');}return null;}finally{if(epoch===accountGeneration.current)setBusy(false);}}
 async function changeLanguage(value:unknown){if(!isLocale(value))return;setSwitching(true);try{
  const r=await fetch('/api/locale',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({locale:value})});
  if(!r.ok){setCode('SWITCH_ERROR');return;}setLocale(value);setAdvice('');
 }catch{setCode('NETWORK_ERROR');}finally{setSwitching(false);}}
 const roleLabel=data?(['admin','analyst','viewer'].includes(data.user.role)?t[data.user.role as 'admin'|'analyst'|'viewer']:t.viewer):'';
 const languageControl=<FormControl size="small" sx={{minWidth:150}} disabled={busy||switching}>
  <InputLabel id="language-label">{t.language}</InputLabel>
  <Select labelId="language-label" id="language-select" label={t.language} value={locale} onChange={e=>void changeLanguage(e.target.value)}>
   {locales.map(l=><MenuItem key={l} value={l} lang={l}>{localeNames[l]}</MenuItem>)}
  </Select>
 </FormControl>;
 return <ThemeProvider theme={platformTheme}><CssBaseline/><Container maxWidth="lg" sx={{py:{xs:3,md:5},...(!data?{minHeight:'100svh',display:'flex',flexDirection:'column',justifyContent:'center'}:{})}}>
  {data&&<><Stack component="header" direction="row" flexWrap="wrap" gap={2} justifyContent="space-between" alignItems="center">
   <Typography variant="h6" color="primary">◈ VELTHARA</Typography>
   <Stack direction="row" gap={2} alignItems="center" flexWrap="wrap">
    <Button href="/workbench" variant="outlined">{locale==='ko'?'VELTHARA 모듈 진단':'VELTHARA modules'}</Button><Chip label={t.local} variant="outlined"/>{languageControl}
   </Stack>
  </Stack>
  <Box sx={{my:3}}><Typography variant="overline" color="primary">{t.operations}</Typography><Typography variant="h3" fontWeight={800}>{t.title}</Typography><Typography color="text.secondary" sx={{mt:2}}>{t.intro}</Typography>{inspection.state!=='idle'&&<Button href="#inspection-console" variant="outlined" size="small" sx={{mt:2}}>{ops.title} ↓</Button>}</Box></>}
  {data&&message&&<Alert severity="warning" sx={{mb:3}} role="alert">{message}</Alert>}
  {bootLoading?<Paper sx={{p:4,maxWidth:520}}><Typography role="status" mb={2}>{ops.refresh}</Typography><LinearProgress aria-label={ops.refresh}/></Paper>:!data?<Box component="main" sx={{display:'grid',gridTemplateColumns:{xs:'1fr',md:'minmax(0,1fr) minmax(0,1.1fr)'},gap:{xs:3,md:6},alignItems:'center'}}>
   <Paper component="section" variant="outlined" sx={{p:{xs:3,sm:4,md:5},background:'#fafbfb'}}>
   <Stack direction="row" justifyContent="space-between" alignItems="center" gap={2} flexWrap="wrap" mb={5}><Typography color="primary" fontWeight={700} sx={{letterSpacing:1}}>◈ VELTHARA</Typography>{languageControl}</Stack>
   <Typography variant="overline" color="primary">{t.operations}</Typography>
   <Typography component="h1" variant="h4" fontWeight={800} sx={{mt:1,mb:2}}>{t.loginTitle}</Typography><Typography color="text.secondary" mb={4} sx={{lineHeight:1.7}}>{registrationCopy[locale].help}</Typography>
   {message&&<Alert severity="warning" sx={{mb:3}} role="alert">{message}</Alert>}
   <Box component="form" noValidate onSubmit={async e=>{
    e.preventDefault();const form=e.currentTarget;const email=form.elements.namedItem('email') as HTMLInputElement;const password=form.elements.namedItem('password') as HTMLInputElement;
    if(!email.value||!password.value){setCode('REQUIRED');(!email.value?email:password).focus();return;}
    if(!email.validity.valid){setCode('INVALID_EMAIL');email.focus();return;}
    if(await post('/api/login',{email:email.value,password:password.value}))window.location.replace('/workbench');
   }}><Stack spacing={2}>
    <TextField name="email" label={t.email} type="email" autoComplete="username" required/>
    <TextField name="password" label={t.password} type="password" autoComplete="current-password" required/>
    <Button type="submit" variant="contained" disabled={busy||switching}>{busy?t.loading:t.login}</Button><Button href="/signup" disabled={busy}>{registrationCopy[locale].title}</Button>
   </Stack></Box>
   </Paper>
   <Box sx={{minWidth:0,textAlign:'center',px:{xs:2,md:0}}}><Box sx={{maxWidth:{xs:280,md:450},mx:'auto'}}><LoginIllustration/></Box><Typography color="primary" variant="overline" sx={{letterSpacing:3}}>VELTHARA</Typography><Typography color="text.secondary" sx={{mt:1,mx:'auto',maxWidth:400,lineHeight:1.8}}>Unified Asset Security Assessment Platform</Typography></Box>
  </Box>:<>
   <Stack direction="row" gap={2} mb={3} alignItems="center" flexWrap="wrap">
    <Chip label={roleLabel}/><Typography sx={{overflowWrap:'anywhere'}}>{data.user.email}</Typography>
    <Button disabled={busy} onClick={async()=>{if(await post('/api/logout',{}))resetAccountView();}}>{t.logout}</Button><Button disabled={busy||operation?.state==='running'} onClick={()=>void load()}>{t.refresh}</Button>
   </Stack>
   {data.user.role==='viewer'&&<Alert severity="info" sx={{mb:3}}>{t.viewerHelp}</Alert>}
   <Box>
    <Paper sx={{p:3}}><Typography variant="h6">{assessmentText(locale,'title')}</Typography><Typography color="text.secondary" my={2}>{assessmentText(locale,'scope')}</Typography>
     <Box component="form" noValidate onSubmit={e=>{e.preventDefault();if(blockReason||busy||switching)return;void runScan();}}><Stack spacing={2}>
      <TextField name="url" type="url" disabled={busy&&!scanRequest.current} value={targetValue} onChange={e=>changeTarget(e.target.value)} label={t.url} placeholder="https://example.com" required/>
      <FormControlLabel control={<Checkbox checked={authorized} onChange={e=>setAuthorized(e.target.checked)}/>} label={assessmentText(locale,'ownership')}/>
      {publicTargets&&<Alert severity="info">{assessmentText(locale,'publicNotice')}</Alert>}
      <Button type="submit" variant="contained" disabled={busy||switching||!!blockReason} aria-describedby={blockReason?'scan-block-reason':undefined}>{busy?t.loading:assessmentText(locale,'title')}</Button>
      {blockReason&&<Alert id="scan-block-reason" severity="info">{blockReason}</Alert>}
      <Typography variant="caption" color="text.secondary">{scanCopy.reset}</Typography>
     </Stack></Box>
    </Paper>
    {inspection.state!=='idle'&&<Box sx={{mt:3}}><OperationsPanel locale={locale} data={data} inspection={inspection} operation={operation} activity={activity} logs={logs}/></Box>}
    <Paper sx={{p:3,mt:3}}><Typography variant="h6">{t.eventsTitle}</Typography><Typography color="text.secondary" my={2}>{t.eventsHelp}</Typography>
     {data.events.length?data.events.map(e=><Stack key={e.category} direction="row" justifyContent="space-between" gap={1} py={1}><Typography>{eventLabel(locale,e.category)}</Typography><Chip label={new Intl.NumberFormat(locale).format(e.count)}/></Stack>):<Typography>{t.noEvents}</Typography>}
     <Alert severity="info" sx={{mt:2}}>{defenseText(locale,'scope')}</Alert>
    </Paper>
    {data.user.role==='admin'&&data.ipBlocks&&<DefensePanel locale={locale} blocks={data.ipBlocks}/>}
   </Box>
   <Paper sx={{p:3,mt:3}}><Typography variant="h6" mb={2}>{t.history}</Typography>
    {data.scans.length===0&&<Typography color="text.secondary">{t.noScans}</Typography>}
    {data.scans.map(s=><Box key={s.id} sx={{borderTop:'1px solid #29384b',py:3}}>
     <Typography fontWeight={700} sx={{overflowWrap:'anywhere'}}>{s.hostname} · HTTP {s.result.status}</Typography>
     <Button size="small" onClick={()=>{changeTarget('https://'+s.hostname);setTargetValue('https://'+s.hostname);setLogs([]);setInspection({state:'success',target:'https://'+s.hostname,result:s.result,recordId:s.id});requestAnimationFrame(()=>document.getElementById('inspection-console')?.scrollIntoView({behavior:window.matchMedia('(prefers-reduced-motion: reduce)').matches?'auto':'smooth'}));}}>{ops.choose}</Button>
     <Typography variant="caption" color="text.secondary">{new Date(s.created_at).toLocaleString(locale)}</Typography>
     <Stack direction="row" flexWrap="wrap" gap={1} my={2}>{s.result.checks.map(c=>{const detail=s.result.assessment?.find(item=>item.id===headerKeys[c.header]);return <Chip key={c.header} title={c.header} color={detail?(detail.status==='pass'?'success':detail.status==='warning'?'warning':'default'):c.present?'default':'warning'} variant="outlined" label={`${t[headerKeys[c.header]??'scanTitle']}: ${detail?assessmentText(locale,detail.status):c.present?t.present:t.missing}`}/>;})}</Stack>
     <Stack direction="row" gap={1} flexWrap="wrap"><Button variant="outlined" onClick={()=>{const next=localAdvice(locale,s.result.checks);setAdviceExpanded(advice===next&&adviceInfo?.source==='local'?!adviceExpanded:true);setAdvice(next);setAdviceInfo({source:'local'});}}>{adviceCopy[locale].button}</Button>
     <Button disabled={busy||switching||!data.aiEnabled||data.user.role==='viewer'} onClick={async()=>{setAdvice('');setAdviceInfo(null);setAdviceExpanded(true);const run=generation.current;const r=await post('/api/ai',{scanId:s.id},()=>generation.current===run);if(r&&typeof r.advice==='string'){setAdvice(r.advice);setAdviceInfo(r);}}}>{t.ai}</Button></Stack>
     <Typography variant="caption" color="text.secondary" display="block" mt={1}>{adviceCopy[locale].note}</Typography>
    </Box>)}
    {!data.aiEnabled&&<Typography color="text.secondary" variant="body2" sx={{mt:2}}>{t.aiDisabled}</Typography>}
    {advice&&<Alert severity={adviceInfo?.reasonCode?'warning':'info'} sx={{mt:2}}><Typography fontWeight={700}>{adviceInfo?.source==='local'?adviceCopy[locale].local:adviceInfo?.source==='cache'?adviceCopy[locale].cache:adviceCopy[locale].ai}</Typography>
     <Button size="small" aria-expanded={adviceExpanded} aria-controls="saved-advice-content" onClick={()=>setAdviceExpanded(value=>!value)}>{assessmentText(locale,adviceExpanded?'hide':'show')}</Button>
     <Box id="saved-advice-content" hidden={!adviceExpanded}>
     {adviceInfo?.reasonCode&&<Typography variant="body2" mb={2}>{adviceInfo.reasonCode==='AI_IN_PROGRESS'?adviceCopy[locale].pending:errorText(locale,adviceInfo.reasonCode)}</Typography>}
     {adviceInfo?.provider&&<Typography variant="caption" display="block">{adviceInfo.provider==='groq'?'Groq':adviceInfo.provider==='gemini'?'Gemini':'OpenAI'} · {adviceInfo.model}</Typography>}
     {adviceInfo?.source==='ai'&&<Typography variant="caption" display="block">{adviceCopy[locale].usage}: {(adviceInfo.inputTokens??0)+(adviceInfo.outputTokens??0)}</Typography>}
     <Typography sx={{whiteSpace:'pre-wrap'}}>{advice}</Typography></Box></Alert>}
   </Paper>
  </>}
  <Typography color="text.secondary" variant="body2" sx={{mt:4}}>{t.disclaimer}</Typography>
 </Container></ThemeProvider>;
}
