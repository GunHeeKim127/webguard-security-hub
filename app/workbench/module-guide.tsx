'use client';
import {Box,Typography,Button} from '@mui/material';
import Link from '../navigation-link';
import {moduleGuides} from '../../lib/assessment/module-guides';
import type {ModuleId} from '../../lib/assessment/types';
export default function ModuleGuide({moduleId,locale,full=false}:{moduleId:ModuleId,locale:'ko'|'en',full?:boolean}){
 const index=locale==='ko'?0:1,guide=moduleGuides[moduleId],t=(ko:string,en:string)=>locale==='ko'?ko:en;
 return <Box component="section" aria-label={t('지원 파일과 사용 방법','Supported input and steps')} sx={{p:2,border:1,borderColor:'divider',borderRadius:2}}>
  <Typography fontWeight={700}>{t('사용할 수 있는 자료','What you can use')}</Typography><Typography variant="body2" sx={{mt:.5}}>{guide.input[index]}</Typography>
  <Typography variant="body2" color="text.secondary" sx={{mt:1}}>{guide.limit[index]}</Typography>
  <Box component="details" open={full} sx={{mt:1.5}}><Box component="summary" sx={{cursor:'pointer',fontWeight:700,color:'primary.main'}}>{t('준비·검사 순서 보기','Show preparation and steps')}</Box>
   <Box component="ol" sx={{pl:3,'& li':{mb:1}}}>{guide.steps.map((step,n)=><li key={n}><Typography variant="body2">{step[index]}</Typography></li>)}</Box>
   {moduleId==='windows.policy'&&<Button component={Link} href="/help#windows-export" size="small">{t('지원 JSON 만드는 방법','How to create the supported JSON')}</Button>}
   {moduleId==='linux.ssh'&&<Button component={Link} href="/help#ssh-preparation" size="small">{t('SSH 자료 준비 방법','Prepare SSH input')}</Button>}
   {!full&&<Button component={Link} href={'/help#'+moduleId} size="small">{t('전체 사용 가이드·오류 해결','Full guide and troubleshooting')}</Button>}
  </Box>
 </Box>;
}
