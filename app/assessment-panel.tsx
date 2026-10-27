'use client';
import {Alert,Box,Chip,Paper,Stack,Typography} from '@mui/material';
import type {CheckResult} from '../lib/inspection';
import type {Locale} from '../lib/locale';
import {assessmentText} from '../lib/assessment-copy';
import TechnologyPanel from './technology-panel';
export default function AssessmentPanel({locale,result}:{locale:Locale,result:CheckResult}){
 const t=(key:string)=>assessmentText(locale,key);
 return <Box sx={{mt:3}}><Typography variant="h6" mb={2}>{t('title')}</Typography><Alert severity="info" sx={{mb:2}}>{t('scope')}</Alert>
 {result.technology&&<TechnologyPanel observation={result.technology} locale={locale}/>}
 {!result.assessment?<Alert severity="info">{t('legacy')}</Alert>:<Box sx={{display:'grid',gridTemplateColumns:{xs:'1fr',md:'1fr 1fr'},gap:2}}>{result.assessment.map(item=><Paper variant="outlined" key={item.id} sx={{p:2,minWidth:0}}>
 <Stack direction="row" gap={1} flexWrap="wrap" alignItems="center"><Typography fontWeight={700}>{t(item.group==='headers'?item.id:item.group)}{/^cookie-\d+$/.test(item.id)?` #${item.id.slice(7)}`:''}</Typography><Chip size="small" label={t(item.status)} color={item.status==='warning'?'warning':item.status==='pass'?'success':'default'}/><Typography variant="caption">{t('severity')}: {t(item.severity)}</Typography></Stack>
 {item.issues.map(issue=><Typography key={issue} variant="body2" sx={{mt:1}}>{t(issue==='exposure'?'exposure_note':issue)}</Typography>)}
 <Typography variant="caption" color="text.secondary" display="block" mt={1}>{t('evidence')}</Typography><Typography component="code" variant="body2" sx={{display:'block',overflowWrap:'anywhere'}}>{item.evidence.join(' · ')||'—'}</Typography>
 <Box component="details" sx={{mt:1.5,'& > summary':{cursor:'pointer',color:'primary.main',fontSize:14},'& > summary:focus-visible':{outline:'2px solid',outlineColor:'primary.main',outlineOffset:4}}}><Typography component="summary">{t('guidance')}</Typography><Typography variant="body2" mt={1}>{t(`${item.group==='headers'?item.id:item.group}_fix`)}</Typography></Box>
 </Paper>)}</Box>}</Box>;
}
