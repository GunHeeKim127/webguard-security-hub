'use client';
import {Box,Typography,Button} from '@mui/material';
import Link from '../navigation-link';
import {moduleGuides} from '../../lib/assessment/module-guides';
import type {ModuleId} from '../../lib/assessment/types';
import InspectionHelp from './inspection-help';
/** ModuleGuide: 모듈별 지원 자료와 현재 진행 도움말을 표시합니다. */ export default function ModuleGuide({moduleId,locale,full=false,blockers}:{moduleId:ModuleId,locale:'ko'|'en',full?:boolean,blockers?:readonly string[]}){
 const index=locale==='ko'?0:1,guide=moduleGuides[moduleId],t=/** t: 현재 화면 언어에 맞는 문구를 고릅니다 */ (ko:string,en:string)=>locale==='ko'?ko:en;
 return <Box component="section" aria-label={t('지원 파일과 사용 방법','Supported input and steps')} sx={{p:2,border:1,borderColor:'divider',borderRadius:2}}>
  <Typography fontWeight={700}>{t('사용할 수 있는 자료','What you can use')}</Typography><Typography variant="body2" sx={{mt:.5}}>{guide.input[index]}</Typography>
  <Typography variant="body2" color="text.secondary" sx={{mt:1}}>{guide.limit[index]}</Typography>
  <InspectionHelp locale={locale} blockers={blockers} steps={[t('저장할 결과의 자산 이름을 입력합니다.','Enter a name for the saved result.'),...guide.steps.map(/** map 콜백: 현재 언어의 검사 순서를 선택합니다. */ step=>step[index])]}/>
  <Box component="details" open={full} sx={{mt:1.5}}><Box component="summary" sx={{cursor:'pointer',fontWeight:700,color:'primary.main'}}>{t('준비·검사 순서 보기','Show preparation and steps')}</Box>
   <Box component="ol" sx={{pl:3,'& li':{mb:1}}}>{guide.steps.map(/** map 콜백: 각 항목을 필요한 값으로 변환합니다 */ (step,n)=><li key={n}><Typography variant="body2">{step[index]}</Typography></li>)}</Box>
   {moduleId==='windows.policy'&&<Button component={Link} href="/help#windows-export" size="small">{t('지원 JSON 만드는 방법','How to create the supported JSON')}</Button>}
   {moduleId==='linux.ssh'&&<Button component={Link} href="/help#ssh-preparation" size="small">{t('SSH 자료 준비 방법','Prepare SSH input')}</Button>}
   {!full&&<Button component={Link} href={'/help#'+moduleId} size="small">{t('전체 사용 가이드·오류 해결','Full guide and troubleshooting')}</Button>}
  </Box>
 </Box>;
}
