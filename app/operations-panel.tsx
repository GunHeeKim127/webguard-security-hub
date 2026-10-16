'use client';
import {Box,Typography,Paper,Stack,Chip,Alert,LinearProgress,Button} from '@mui/material';
import type {Locale} from '../lib/locale';
import {messages,eventLabel} from '../lib/messages';
import {operationsMessages} from '../lib/operations-messages';
import {stages,scanReport,type ScanLog} from '../lib/scan-run';
import {scanUI} from '../lib/scan-ui';
import {errorText} from '../lib/errors-i18n';
import {inspectionSummary,type Dashboard,type Inspection,type OperationState} from '../lib/inspection';
export default function OperationsPanel({locale,data,inspection,operation,activity,logs}:{locale:Locale,data:Dashboard,inspection:Inspection,operation:OperationState,activity:NonNullable<OperationState>[],logs:ScanLog[]}){
 const copy=scanUI[locale];
 const pulse={animation:"scanPulse 1.2s ease-in-out infinite",'@keyframes scanPulse':{'0%,100%':{boxShadow:'0 0 0 0 #66e6c322'},'50%':{boxShadow:'0 0 0 4px #66e6c366'}},'@media (prefers-reduced-motion: reduce)':{animation:'none'}};
 const stepLabels=[operationsMessages[locale].targetStep,operationsMessages[locale].networkStep,operationsMessages[locale].headersStep,operationsMessages[locale].storeStep];
 const t=operationsMessages[locale],ui=messages[locale],summary=inspectionSummary(inspection);
 const stateLabel=(state:string)=>state==='running'?t.running:state==='success'?t.success:state==='error'?t.failed:t.idle;
 const current=operation?.state==='running'?t[operation.kind]:inspection.state==='success'?t.record:operation?t[operation.kind]:t.idle;
 const totalEvents=data.events.reduce((sum,event)=>sum+event.count,0);
 const stats=[{label:t.registered,value:data.overview.approvedCount},{label:t.saved,value:data.overview.savedCount},{label:t.events,value:totalEvents},{label:t.http,value:summary.httpStatus??'—'}];
 const checkItems=[['csp','cspHelp','content-security-policy'],['hsts','hstsHelp','strict-transport-security'],['nosniff','nosniffHelp','x-content-type-options'],['referrer','referrerHelp','referrer-policy']] as const;
 return <Box id="inspection-console" sx={{mb:4,scrollMarginTop:24}}>
  <Stack direction="row" gap={2} justifyContent="space-between" flexWrap="wrap" alignItems="center" mb={2}>
   <Box><Typography variant="h5" fontWeight={800}>{t.title}</Typography><Typography color="text.secondary" variant="body2" mt={1}>{t.help}</Typography></Box>
   <Chip color={operation?.state==='running'?'primary':operation?.state==='error'?'warning':'default'} label={stateLabel(inspection.state)} variant="outlined"/>
  </Stack>
  <Paper variant="outlined" sx={{overflow:'hidden',borderColor:'#294451',background:'linear-gradient(120deg,#102b33,#101c2b)'}}>
   <Box sx={{display:'grid',gridTemplateColumns:{xs:'1fr 1fr',md:'repeat(4,1fr)'}}}>{stats.map((item,index)=><Box key={item.label} sx={{p:2.5,borderBottom:'1px solid #294451',borderInlineEnd:index<3?'1px solid #294451':undefined}}><Typography variant="caption" color="text.secondary">{item.label}</Typography><Typography variant="h4" fontWeight={800} color={index===3?'text.primary':'primary'} mt={1}>{typeof item.value==='number'?new Intl.NumberFormat(locale).format(item.value):item.value}</Typography></Box>)}</Box>
   <Box sx={{display:'grid',gridTemplateColumns:{xs:'1fr',lg:'minmax(0,1.6fr) minmax(260px,1fr)'}}}>
    <Box sx={{p:3,borderInlineEnd:{lg:'1px solid #294451'}}}>
     <Typography variant="overline" color="primary">{t.active}</Typography><Typography fontWeight={700} role="status" aria-live="polite">{current}</Typography>
     <Typography variant="caption" color="text.secondary">{t.updated}: {new Date(data.overview.updatedAt).toLocaleString(locale)}</Typography>
     <Box sx={{my:2,p:2,bgcolor:'#08151f',border:'1px solid #31535a',borderRadius:2}}>
      <Typography variant="caption" color="text.secondary">{t.target}</Typography><Typography fontWeight={700} sx={{overflowWrap:'anywhere',mt:.5}}>{inspection.target||t.noTarget}</Typography>
      <Typography variant="body2" color="text.secondary" mt={1}>{t.scope}: {t.scopeValue}</Typography>
     </Box>
     <Box role="list" sx={{display:'grid',gridTemplateColumns:{xs:'1fr 1fr',sm:'repeat(4,1fr)'},gap:1}}>{stages.map((stage,index)=>{
      const latest=logs.filter(log=>log.stage===stage).at(-1),state=latest?.state??(summary.complete?'success':'idle'),active=state==='running'&&inspection.state==='running';
      return <Box key={stage} role="listitem" aria-current={active?'step':undefined} sx={{p:1.5,border:'1px solid',borderColor:active||state==='success'?'#66e6c3':state==='error'?'#ed9c46':'#304350',borderRadius:2,bgcolor:active?'#173e3b':'#10202c',...(active?pulse:{}),...(state==='success'?{animation:'scanComplete .9s ease-out','@keyframes scanComplete':{from:{backgroundColor:'#286957'},to:{backgroundColor:'#10202c'}},'@media (prefers-reduced-motion: reduce)':{animation:'none'}}:{})}}>
       <Typography color={active||state==='success'?'primary':'text.secondary'} fontWeight={800}>{state==='success'?'✓':String(index+1).padStart(2,'0')}</Typography><Typography variant="body2" fontWeight={700} mt={1}>{stepLabels[index]}</Typography><Typography variant="caption" color="text.secondary">{state==='idle'?t.waiting:stateLabel(state)}</Typography>
      </Box>;
     })}</Box>
     {inspection.state==='running'&&<Box sx={{mt:2}}><LinearProgress aria-label={t.running}/><Typography variant="caption" color="text.secondary" display="block" mt={1}>{copy.live}</Typography></Box>}
     {inspection.state==='error'&&<Alert severity="warning" sx={{mt:2}}>{t.failed} · {t.noResult}</Alert>}
     <Stack direction="row" gap={1} flexWrap="wrap" mt={2}>
      <Chip size="small" label={`${t.database}: ${t.connected}`} color="success" variant="outlined"/>
      <Chip size="small" label={`${t.aiStatus}: ${data.aiEnabled?t.configured:t.notAvailable}`} variant="outlined"/>
      {data.aiEnabled&&<Typography variant="caption" color="text.secondary" alignSelf="center">{t.notVerified}</Typography>}
      {summary.missing!==null&&<Chip size="small" color={summary.missing?'warning':'success'} label={`${t.missing}: ${summary.missing}`}/>}
     </Stack>
    </Box>
    <Box sx={{p:3,minWidth:0}}>
     <Stack gap={1} mb={2}><Typography fontWeight={700}>◉ {copy.log}</Typography>
      <Button size="small" variant="outlined" disabled={!logs.length&&inspection.state!=='success'} onClick={()=>{
       const blob=new Blob([scanReport(inspection.target,logs,inspection)],{type:'application/json;charset=utf-8'}),url=URL.createObjectURL(blob),a=document.createElement('a');
       let host='scan';try{host=new URL(inspection.target).hostname.replace(/[^a-z0-9.-]/gi,'_');}catch{}
       a.href=url;a.download=`webguard-${host}-${new Date().toISOString().replace(/[:.]/g,'-')}.json`;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
      }}>{copy.download}</Button>
     </Stack>
     <Box role="log" aria-label={copy.log} aria-live="polite" sx={{maxHeight:300,overflowY:'auto',fontFamily:'monospace',bgcolor:'#07131c',p:1.5,borderRadius:2}}>
      {logs.length?logs.map((log,index)=><Box key={index} sx={{py:.8,borderBottom:'1px solid #20303a'}}><Typography variant="caption" color="text.secondary">{new Date(log.at).toLocaleTimeString(locale)} · {stepLabels[stages.indexOf(log.stage)]}</Typography><Typography variant="body2" color={log.state==='error'?'warning.main':'text.primary'}>{stateLabel(log.state)}{log.errorCode?' · '+(log.errorCode==='NETWORK_ERROR'?ui.networkError:errorText(locale,log.errorCode)):''}</Typography></Box>):<Typography variant="body2" color="text.secondary">{t.noLog}</Typography>}
     </Box>
     <Typography variant="caption" color="text.secondary" display="block" sx={{mt:2}}>{t.inactive}</Typography>
     <Typography fontWeight={700} variant="body2" mt={2}>{t.requestLog}</Typography>
     {activity.length?activity.slice(0,4).map((item,index)=><Typography key={index} variant="caption" color="text.secondary" display="block" mt={1}>{new Date(item.at).toLocaleTimeString(locale)} · {t[item.kind]} · {stateLabel(item.state)}</Typography>):<Typography variant="caption" color="text.secondary">{t.noActivity}</Typography>}
    </Box>
   </Box>
  </Paper>
  {data.overview.approvedCount===0&&<Alert severity="info" sx={{mt:2}}>{t.notConfigured}</Alert>}
  <Typography variant="h6" sx={{mt:3,mb:2}}>{t.checks}</Typography>
  <Box sx={{display:'grid',gridTemplateColumns:{xs:'1fr',sm:'1fr 1fr',lg:'repeat(4,1fr)'},gap:1.5}}>{checkItems.map(([label,help,header])=>{
   const check=summary.complete?inspection.result?.checks.find(c=>c.header===header):undefined;
   return <Paper key={header} variant="outlined" sx={{p:2,borderColor:'#294451',...(inspection.state==='running'&&logs.at(-1)?.stage==='headers'?pulse:{})}}><Stack direction="row" gap={1} justifyContent="space-between"><Typography fontWeight={700} variant="body2">{ui[label]}</Typography><Chip size="small" variant="outlined" color={check?(check.present?'success':'warning'):'default'} label={check?(check.present?ui.present:ui.missing):t.noResult}/></Stack><Typography variant="body2" color="text.secondary" mt={1.5}>{t[help]}</Typography><Typography variant="caption" color="text.secondary" display="block" mt={1} sx={{overflowWrap:'anywhere'}}>{header}</Typography></Paper>;
  })}</Box>
  <Typography variant="caption" color="text.secondary" display="block" mt={2}>{t.limited}</Typography>
 </Box>;
}
