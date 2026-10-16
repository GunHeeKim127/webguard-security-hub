'use client';
import {useEffect,useRef,useState} from 'react';
import {ThemeProvider,createTheme,CssBaseline,Container,Box,Typography,Paper,TextField,Button,Alert,Chip,Stack,Checkbox,FormControlLabel,FormControl,InputLabel,Select,MenuItem,LinearProgress} from '@mui/material';
import {isLocale,locales,localeNames,type Locale} from '../lib/locale';
import {messages,eventLabel,type MessageKey} from '../lib/messages';
import {errorText} from '../lib/errors-i18n';
import {appendLog,readScanStream,type ScanLog} from '../lib/scan-run';
import {adviceCopy,localAdvice} from '../lib/local-advice';
import {registrationCopy} from '../lib/registration-copy';
import {scanUI} from '../lib/scan-ui';
import OperationsPanel from './operations-panel';
import {operationsMessages} from '../lib/operations-messages';
import type {Dashboard,Inspection,Operation,OperationState} from '../lib/inspection';

const theme=createTheme({palette:{mode:'dark',primary:{main:'#66e6c3'},background:{default:'#091321',paper:'#111f31'}},typography:{fontFamily:'Arial, sans-serif'},shape:{borderRadius:14}});
const headerKeys:Record<string,MessageKey>={'content-security-policy':'csp','strict-transport-security':'hsts','x-content-type-options':'nosniff','referrer-policy':'referrer'};

export default function Home({initialLocale}:{initialLocale:Locale}){
 const [locale,setLocale]=useState(initialLocale),[data,setData]=useState<Dashboard|null>(null),[code,setCode]=useState(''),[busy,setBusy]=useState(false),[switching,setSwitching]=useState(false),[advice,setAdvice]=useState(''),[authorized,setAuthorized]=useState(false);
 const [inspection,setInspection]=useState<Inspection>({state:'idle',target:''}),[operation,setOperation]=useState<OperationState>(null),[activity,setActivity]=useState<NonNullable<OperationState>[]>([]),[targetValue,setTargetValue]=useState('');
 const [logs,setLogs]=useState<ScanLog[]>([]);const scanRequest=useRef<AbortController|null>(null),generation=useRef(0);
 useEffect(()=>()=>scanRequest.current?.abort(),[]);
 const [adviceInfo,setAdviceInfo]=useState<{source:string,reasonCode?:string,provider?:string,model?:string,inputTokens?:number,outputTokens?:number}|null>(null);
 const [bootLoading,setBootLoading]=useState(true);
 const t=messages[locale],ops=operationsMessages[locale],scanCopy=scanUI[locale];
 function changeTarget(value:string){if(value===targetValue)return;generation.current++;if(scanRequest.current){scanRequest.current.abort();setBusy(false);}scanRequest.current=null;setTargetValue(value);setInspection({state:'idle',target:''});setLogs([]);setCode('');setOperation(null);setActivity([]);setAdvice('');}
 const normalizedTarget=targetValue.trim().includes('://')?targetValue.trim():'https://'+targetValue.trim();
 let targetApproved=false;try{const url=new URL(normalizedTarget);targetApproved=url.protocol==='https:'&&!url.username&&!url.password&&(!url.port||url.port==='443')&&url.pathname==='/'&&!url.search&&!url.hash&&!!data?.overview.approvedHosts.includes(url.hostname);}catch{}
 const blockReason=!targetValue.trim()?scanCopy.address:!authorized?scanCopy.permission:data?.user.role==='viewer'?t.viewerHelp:data?.overview.approvedCount===0?ops.notConfigured:!targetApproved?scanCopy.unapproved:'';
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
 const message=code==='NETWORK_ERROR'?t.networkError:code==='SWITCH_ERROR'?t.switchError:code==='INVALID_EMAIL'?t.invalidEmail:code==='REQUIRED'?t.required:code?errorText(locale,code):'';
 useEffect(()=>{document.documentElement.lang=locale;document.title=`WebGuard · ${messages[locale].title}`;},[locale]);
 async function load(record=true){if(record)markOperation('refresh','running');try{
  const r=await fetch('/api/dashboard',{cache:'no-store'});const json=await r.json();
  if(r.ok){setData(json);if(record)markOperation('refresh','success');}
  else {if(record)markOperation('refresh','error');if(r.status===401)setData(null);else setCode(json.errorCode??'SERVICE_UNAVAILABLE');}
 }catch{setCode('NETWORK_ERROR');if(record)markOperation('refresh','error');}finally{setBootLoading(false);}}
 useEffect(()=>{void load(false);},[]);
 async function post(path:string,payload:unknown){setBusy(true);setCode('');const kind:Operation=path==='/api/login'?'login':path==='/api/logout'?'logout':path==='/api/ai'?'ai':'scan';markOperation(kind,'running');try{
  const r=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});const json=await r.json();
  if(!r.ok){setCode(json.errorCode??'SERVICE_UNAVAILABLE');markOperation(kind,'error');return null;}markOperation(kind,'success');return json;
 }catch{setCode('NETWORK_ERROR');markOperation(kind,'error');return null;}finally{setBusy(false);}}
 async function changeLanguage(value:unknown){if(!isLocale(value))return;setSwitching(true);try{
  const r=await fetch('/api/locale',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({locale:value})});
  if(!r.ok){setCode('SWITCH_ERROR');return;}setLocale(value);setAdvice('');
 }catch{setCode('NETWORK_ERROR');}finally{setSwitching(false);}}
 const roleLabel=data?(['admin','analyst','viewer'].includes(data.user.role)?t[data.user.role as 'admin'|'analyst'|'viewer']:t.viewer):'';
 return <ThemeProvider theme={theme}><CssBaseline/><Container maxWidth="lg" sx={{py:5}}>
  <Stack direction="row" flexWrap="wrap" gap={2} justifyContent="space-between" alignItems="center">
   <Typography variant="h6" color="primary">◈ WEBGUARD</Typography>
   <Stack direction="row" gap={2} alignItems="center" flexWrap="wrap">
    <Chip label={t.local} variant="outlined"/><Button href="/signup" size="small">{registrationCopy[locale].title}</Button>
    <FormControl size="small" sx={{minWidth:150}} disabled={busy||switching}>
     <InputLabel id="language-label">{t.language}</InputLabel>
     <Select labelId="language-label" id="language-select" label={t.language} value={locale} onChange={e=>void changeLanguage(e.target.value)}>
      {locales.map(l=><MenuItem key={l} value={l} lang={l}>{localeNames[l]}</MenuItem>)}
     </Select>
    </FormControl>
   </Stack>
  </Stack>
  <Box sx={{my:3}}><Typography variant="overline" color="primary">{t.operations}</Typography><Typography variant="h3" fontWeight={800}>{t.title}</Typography><Typography color="text.secondary" sx={{mt:2}}>{t.intro}</Typography>{data&&inspection.state!=='idle'&&<Button href="#inspection-console" variant="outlined" size="small" sx={{mt:2}}>{ops.title} ↓</Button>}</Box>
  {message&&<Alert severity="warning" sx={{mb:3}} role="alert">{message}</Alert>}
  {bootLoading?<Paper sx={{p:4,maxWidth:520}}><Typography role="status" mb={2}>{ops.refresh}</Typography><LinearProgress aria-label={ops.refresh}/></Paper>:!data?<Paper sx={{p:4,maxWidth:520}}>
   <Typography variant="h5" mb={2}>{t.loginTitle}</Typography><Typography color="text.secondary" mb={3}>{registrationCopy[locale].help}</Typography>
   <Box component="form" noValidate onSubmit={async e=>{
    e.preventDefault();const form=e.currentTarget;const email=form.elements.namedItem('email') as HTMLInputElement;const password=form.elements.namedItem('password') as HTMLInputElement;
    if(!email.value||!password.value){setCode('REQUIRED');(!email.value?email:password).focus();return;}
    if(!email.validity.valid){setCode('INVALID_EMAIL');email.focus();return;}
    if(await post('/api/login',{email:email.value,password:password.value}))await load();
   }}><Stack spacing={2}>
    <TextField name="email" label={t.email} type="email" autoComplete="username" required/>
    <TextField name="password" label={t.password} type="password" autoComplete="current-password" required/>
    <Button type="submit" variant="contained" disabled={busy||switching}>{busy?t.loading:t.login}</Button><Button href="/signup" disabled={busy}>{registrationCopy[locale].title}</Button>
   </Stack></Box>
  </Paper>:<>
   <Stack direction="row" gap={2} mb={3} alignItems="center" flexWrap="wrap">
    <Chip label={roleLabel}/><Typography sx={{overflowWrap:'anywhere'}}>{data.user.email}</Typography>
    <Button disabled={busy} onClick={async()=>{if(await post('/api/logout',{})){setData(null);setAdvice('');setInspection({state:'idle',target:''});setActivity([]);setTargetValue('');setLogs([]);generation.current++;scanRequest.current?.abort();}}}>{t.logout}</Button><Button disabled={busy||operation?.state==='running'} onClick={()=>void load()}>{t.refresh}</Button>
   </Stack>
   {data.user.role==='viewer'&&<Alert severity="info" sx={{mb:3}}>{t.viewerHelp}</Alert>}
   <Box>
    <Paper sx={{p:3}}><Typography variant="h6">{t.scanTitle}</Typography><Typography color="text.secondary" my={2}>{t.scanHelp}</Typography>
     <Box component="form" noValidate onSubmit={e=>{e.preventDefault();if(blockReason||busy||switching)return;void runScan();}}><Stack spacing={2}>
      <TextField name="url" type="url" disabled={busy&&!scanRequest.current} value={targetValue} onChange={e=>changeTarget(e.target.value)} label={t.url} placeholder="https://example.com" required/>
      <FormControlLabel control={<Checkbox checked={authorized} onChange={e=>setAuthorized(e.target.checked)}/>} label={t.authorized}/>
      <Button type="submit" variant="contained" disabled={busy||switching||!!blockReason} aria-describedby={blockReason?'scan-block-reason':undefined}>{busy?t.loading:t.scan}</Button>
      {blockReason&&<Alert id="scan-block-reason" severity="info">{blockReason}</Alert>}
      <Typography variant="caption" color="text.secondary">{scanCopy.reset}</Typography>
     </Stack></Box>
    </Paper>
    {inspection.state!=='idle'&&<Box sx={{mt:3}}><OperationsPanel locale={locale} data={data} inspection={inspection} operation={operation} activity={activity} logs={logs}/></Box>}
    <Paper sx={{p:3,mt:3}}><Typography variant="h6">{t.eventsTitle}</Typography><Typography color="text.secondary" my={2}>{t.eventsHelp}</Typography>
     {data.events.length?data.events.map(e=><Stack key={e.category} direction="row" justifyContent="space-between" gap={1} py={1}><Typography>{eventLabel(locale,e.category)}</Typography><Chip label={new Intl.NumberFormat(locale).format(e.count)}/></Stack>):<Typography>{t.noEvents}</Typography>}
     <Alert severity="info" sx={{mt:2}}>{t.trafficLimit}</Alert>
    </Paper>
   </Box>
   <Paper sx={{p:3,mt:3}}><Typography variant="h6" mb={2}>{t.history}</Typography>
    {data.scans.length===0&&<Typography color="text.secondary">{t.noScans}</Typography>}
    {data.scans.map(s=><Box key={s.id} sx={{borderTop:'1px solid #29384b',py:3}}>
     <Typography fontWeight={700} sx={{overflowWrap:'anywhere'}}>{s.hostname} · HTTP {s.result.status}</Typography>
     <Button size="small" onClick={()=>{changeTarget('https://'+s.hostname);setTargetValue('https://'+s.hostname);setLogs([]);setInspection({state:'success',target:'https://'+s.hostname,result:s.result,recordId:s.id});requestAnimationFrame(()=>document.getElementById('inspection-console')?.scrollIntoView({behavior:window.matchMedia('(prefers-reduced-motion: reduce)').matches?'auto':'smooth'}));}}>{ops.choose}</Button>
     <Typography variant="caption" color="text.secondary">{new Date(s.created_at).toLocaleString(locale)}</Typography>
     <Stack direction="row" flexWrap="wrap" gap={1} my={2}>{s.result.checks.map(c=><Chip key={c.header} title={c.header} color={c.present?'success':'warning'} variant="outlined" label={`${t[headerKeys[c.header]??'scanTitle']}: ${c.present?t.present:t.missing}`}/>)}</Stack>
     <Stack direction="row" gap={1} flexWrap="wrap"><Button variant="outlined" onClick={()=>{setAdvice(localAdvice(locale,s.result.checks));setAdviceInfo({source:'local'});}}>{adviceCopy[locale].button}</Button>
     <Button disabled={busy||switching||!data.aiEnabled||data.user.role==='viewer'} onClick={async()=>{setAdvice('');setAdviceInfo(null);const r=await post('/api/ai',{scanId:s.id});if(r&&typeof r.advice==='string'){setAdvice(r.advice);setAdviceInfo(r);}}}>{t.ai}</Button></Stack>
     <Typography variant="caption" color="text.secondary" display="block" mt={1}>{adviceCopy[locale].note}</Typography>
    </Box>)}
    {!data.aiEnabled&&<Typography color="text.secondary" variant="body2" sx={{mt:2}}>{t.aiDisabled}</Typography>}
    {advice&&<Alert severity={adviceInfo?.reasonCode?'warning':'info'} sx={{mt:2}}><Typography fontWeight={700}>{adviceInfo?.source==='local'?adviceCopy[locale].local:adviceInfo?.source==='cache'?adviceCopy[locale].cache:adviceCopy[locale].ai}</Typography>
     {adviceInfo?.reasonCode&&<Typography variant="body2" mb={2}>{adviceInfo.reasonCode==='AI_IN_PROGRESS'?adviceCopy[locale].pending:errorText(locale,adviceInfo.reasonCode)}</Typography>}
     {adviceInfo?.provider&&<Typography variant="caption" display="block">{adviceInfo.provider==='groq'?'Groq':adviceInfo.provider==='gemini'?'Gemini':'OpenAI'} · {adviceInfo.model}</Typography>}
     {adviceInfo?.source==='ai'&&<Typography variant="caption" display="block">{adviceCopy[locale].usage}: {(adviceInfo.inputTokens??0)+(adviceInfo.outputTokens??0)}</Typography>}
     <Typography sx={{whiteSpace:'pre-wrap'}}>{advice}</Typography></Alert>}
   </Paper>
  </>}
  <Typography color="text.secondary" variant="body2" sx={{mt:4}}>{t.disclaimer}</Typography>
 </Container></ThemeProvider>;
}
