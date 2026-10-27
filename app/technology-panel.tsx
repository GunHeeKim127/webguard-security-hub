'use client';
import {Alert,Box,Button,Chip,Paper,Stack,Typography} from '@mui/material';
import {technologyFindings,type TechnologyObservation} from '../lib/web-technology';
export default function TechnologyPanel({observation,locale}:{observation:TechnologyObservation,locale:string}){
 const ko=locale==='ko',findings=technologyFindings(observation,ko?'ko':'en');
 return <Box sx={{my:2}}><Typography variant="h6">{ko?'웹 기술·알려진 취약점 검토':'Web technology / known vulnerability review'}</Typography>
 <Alert severity="info" sx={{my:1}}>{ko?'헤더 기반 관찰이며 숨겨진 기술과 실제 공격 가능성을 검증하지 않습니다. 규칙 기준: ':'Header-based hints; hidden technology and actual exploitability are not verified. Catalog: '}{observation.catalogVersion}</Alert>
 <Stack gap={1}>{findings.map(f=><Paper variant="outlined" key={f.id} sx={{p:2}}><Stack direction="row" gap={1} flexWrap="wrap"><Typography fontWeight={700}>{f.title}</Typography><Chip size="small" color={f.status==='warning'?'warning':'default'} label={f.status==='warning'?(ko?'검토 필요':'Review needed'):f.status==='not_assessed'?(ko?'미검사':'Not assessed'):(ko?'참고':'Information')}/></Stack><Typography variant="body2" sx={{overflowWrap:'anywhere',my:1}}>{f.evidence.join(' · ')}</Typography><Typography variant="body2">{f.remediation}</Typography>{f.reference&&<Button href={f.reference} target="_blank" rel="noreferrer">{ko?'공식 보안 권고':'Official advisory'}</Button>}</Paper>)}</Stack></Box>;
}
