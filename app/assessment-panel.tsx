'use client';
import {Alert,Box,Chip,Paper,Stack,Typography} from '@mui/material';
import type {CheckResult} from '../lib/inspection';
import type {Locale} from '../lib/locale';
import {assessmentText} from '../lib/assessment-copy';
import TechnologyPanel from './technology-panel';
import HttpStatusGuide from './http-status-guide';
/** AssessmentPanel: 해당 자료의 관찰·검토 결과를 계산합니다 주요 호출: t·map. */ export default function AssessmentPanel({locale,result}:{locale:Locale,result:CheckResult}){
 const t=/** t: 현재 화면 언어에 맞는 문구를 고릅니다 주요 호출: assessmentText. */ (key:string)=>assessmentText(locale,key);
 return <Box sx={{mt:3}}><Typography variant="h6" mb={2}>{t('title')}</Typography><Alert severity="info" sx={{mb:2}}>{t('scope')}</Alert><HttpStatusGuide status={result.status} locale={locale}/><Alert severity="info" sx={{mb:2}}>{locale==='ko'?'검토 필요: 관찰된 설정이 이 검사의 기준과 다릅니다. 확인 불가: 자료나 검사 범위가 부족해 판정을 보류한 것이며, 설정 미흡이나 안전이 확정된 것은 아닙니다.':'Review needed: an observed setting differs from this check’s baseline. Unverified: evidence or scope was insufficient; neither an absent control nor safety is established.'}</Alert>
 {result.technology&&<TechnologyPanel observation={result.technology} locale={locale}/>}
 {!result.assessment?<Alert severity="info">{t('legacy')}</Alert>:<Box sx={{display:'grid',gridTemplateColumns:{xs:'1fr',md:'1fr 1fr'},gap:2}}>{result.assessment.map(/** map 콜백: 각 항목을 필요한 값으로 변환합니다 주요 호출: t·slice·map. */ item=><Paper variant="outlined" key={item.id} sx={{p:2,minWidth:0}}>
 <Stack direction="row" gap={1} flexWrap="wrap" alignItems="center"><Typography fontWeight={700}>{t(item.group==='headers'?item.id:item.group)}{/^cookie-\d+$/.test(item.id)?` #${item.id.slice(7)}`:''}</Typography><Chip size="small" label={t(item.status)} color={item.status==='warning'?'warning':item.status==='pass'?'success':'default'}/><Typography variant="caption">{t('severity')}: {t(item.severity)}</Typography></Stack>
 {item.issues.map(/** map 콜백: 각 항목을 필요한 값으로 변환합니다 주요 호출: t. */ issue=><Typography key={issue} variant="body2" sx={{mt:1}}>{t(issue==='exposure'?'exposure_note':issue)}</Typography>)}
 <Typography variant="caption" color="text.secondary" display="block" mt={1}>{t('evidence')}</Typography><Typography component="code" variant="body2" sx={{display:'block',overflowWrap:'anywhere'}}>{item.evidence.join(' · ')||'—'}</Typography>
 <Box component="details" sx={{mt:1.5,'& > summary':{cursor:'pointer',color:'primary.main',fontSize:14},'& > summary:focus-visible':{outline:'2px solid',outlineColor:'primary.main',outlineOffset:4}}}><Typography component="summary">{t('guidance')}</Typography><Typography variant="body2" mt={1}>{t(`${item.group==='headers'?item.id:item.group}_fix`)}</Typography></Box>
 </Paper>)}</Box>}</Box>;
}
