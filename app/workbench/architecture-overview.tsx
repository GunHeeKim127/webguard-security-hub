'use client';
import {Box,Button,ButtonBase,Chip,Paper,Stack,Typography} from '@mui/material';
import Link from '../navigation-link';
import type {ModuleId} from '../../lib/assessment/types';
type Category='web'|'mobile'|'endpoint'|'cloud'|'virtualization'|'network'|'iot'|'container';
const categories:{id:Category,title:string,subtitle:string,module?:ModuleId,scope:[string,string]}[]=[
 {id:'web',title:'Web',subtitle:'HTTP / TLS / 인증',module:'web.compare',scope:['공개 헤더·TLS·응답 비교','Public headers, TLS and response comparison']},
 {id:'mobile',title:'Mobile',subtitle:'APK / IPA / PWA',module:'application.package',scope:['패키지 정적 점검 · PWA 준비 중','Package baseline · PWA planned']},
 {id:'endpoint',title:'Endpoint',subtitle:'Windows / Linux / macOS',module:'application.pe',scope:['실행 파일·설정 스냅샷 점검','Executable and configuration snapshots']},
 {id:'cloud',title:'Cloud',subtitle:'AWS / Azure / GCP',scope:['클라우드 설정·권한 점검 예정','Cloud configuration and access · planned']},
 {id:'virtualization',title:'Virtualization',subtitle:'VMware VMX',module:'virtualization.vmx',scope:['VMX 명시적 격리 설정','Explicit VMX isolation declarations']},
 {id:'network',title:'Network',subtitle:'GNS3 2.x topology',module:'network.gns3',scope:['GNS3 프로젝트 구성 점검','GNS3 project configuration baseline']},
 {id:'iot',title:'IoT',subtitle:'Firmware / Device Config',scope:['펌웨어·장비 설정 분석 예정','Firmware and device configuration · planned']},
 {id:'container',title:'Container',subtitle:'Docker / Kubernetes',scope:['컨테이너·클러스터 점검 예정','Container and cluster assessment · planned']},
];
export {categoryFor} from '../../lib/assessment/categories';
export function ModuleIcon({kind,size=24}:{kind:Category|'shield'|'arrow'|'report',size?:number}){
 const lines={
  web:<><circle cx="12" cy="12" r="8"/><ellipse cx="12" cy="12" rx="3.5" ry="8"/><path d="M4 12h16"/></>,
  mobile:<><rect x="7" y="2.5" width="10" height="19" rx="2.5"/><path d="M11 18h2"/></>,
  endpoint:<><rect x="3" y="4" width="18" height="13" rx="2"/><path d="M9 21h6M12 17v4"/></>,
  cloud:<path d="M7 18h10a4 4 0 0 0 .3-8 5.7 5.7 0 0 0-10.6-1A4.5 4.5 0 0 0 7 18Z"/>,
  virtualization:<><rect x="3" y="3" width="18" height="7" rx="1.5"/><rect x="3" y="14" width="18" height="7" rx="1.5"/><path d="M6 6.5h1M6 17.5h1"/></>,
  network:<><circle cx="12" cy="4" r="2"/><circle cx="5" cy="19" r="2"/><circle cx="12" cy="19" r="2"/><circle cx="19" cy="19" r="2"/><path d="M12 6v11M5 17v-5h14v5"/></>,
  iot:<><rect x="5" y="5" width="14" height="14" rx="2"/><rect x="9" y="9" width="6" height="6" rx=".5"/><path d="M8 2v3m8-3v3M8 19v3m8-3v3M2 8h3m-3 8h3M19 8h3m-3 8h3"/></>,
  container:<><path d="m12 2 5 3v6l-5 3-5-3V5l5-3Zm-5 9-5 3v6l5 3 5-3m5-9 5 3v6l-5 3-5-3v-6m-5 9v-6l-5-3m10 0 5 3 5-3M7 5l5 3 5-3m-5 3v6"/></>,
  shield:<path d="m12 2 8 3v6c0 5-4 8-8 11-4-3-8-6-8-11V5l8-3Zm-4 10 3 3 5-6"/>,
  arrow:<path d="M12 4v16m-4-4 4 4 4-4"/>,
  report:<><path d="M6 2h9l4 4v16H6V2Zm9 0v5h4M9 11h7m-7 4h7m-7 4h4"/></>,
 };
 return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.65" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" focusable="false">{lines[kind]}</svg>;
}
export default function ArchitectureOverview({locale}:{locale:'ko'|'en'}){
 const t=(ko:string,en:string)=>locale==='ko'?ko:en;
 return <Box component="section" aria-label={t('통합 진단 모듈','Unified assessment modules')}>
  <Box textAlign="center" sx={{pt:{xs:3,sm:5},pb:3}}><Typography component="h1" sx={{fontSize:{xs:30,sm:38},fontWeight:750,letterSpacing:'-.035em'}}>VELTHARA</Typography><Typography sx={{mt:1,fontSize:{xs:12,sm:14},letterSpacing:'.035em',color:'text.secondary'}}>Unified Asset Security Assessment Platform</Typography><Typography color="text.secondary" sx={{mt:1.5,fontSize:14}}>{t('다양한 디지털 자산의 보안 상태를 한곳에서.','One place to understand security across your digital assets.')}</Typography></Box>
  <Paper variant="outlined" sx={{p:{xs:2.5,sm:3},textAlign:'center',bgcolor:'background.paper',borderRadius:'16px'}}><Stack direction="row" gap={1} justifyContent="center" alignItems="center"><ModuleIcon kind="shield" size={22}/><Typography fontWeight={700}>{t('공통 진단 관리 엔진','Common assessment management engine')}</Typography></Stack><Typography variant="body2" color="text.secondary" sx={{mt:1.25,lineHeight:1.9}}>{t('자산 등록 · 작업 예약 · 결과 표준화 · 위험도 · 재검증','Asset registration · Scheduling · Standardized results · Risk · Retesting')}</Typography><Typography variant="caption" color="text.secondary">{t('현재: 계정별 자산·수동 진단·결과 비교 / 작업 예약 준비 중','Available: private assets, manual assessment and comparison / Scheduling planned')}</Typography></Paper>
  <Box aria-hidden="true" sx={{display:'flex',justifyContent:'center',py:1,color:'#9a9fa2'}}><ModuleIcon kind="arrow" size={20}/></Box>
  <Box sx={{display:'grid',gridTemplateColumns:'repeat(2,minmax(0,1fr))',gap:{xs:1,sm:1.4}}}>
   {categories.map(c=>{const available=!!c.module;return <ButtonBase key={c.id} {...(available?{component:Link,href:c.id==='web'?'/?view=web':'/workbench/'+c.id,prefetch:false}:{disabled:true})} aria-label={`${c.title} · ${available?t('검사 화면으로 이동','Go to assessment'):t('준비 중','Planned')}`} sx={{display:'flex',flexDirection:'column',justifyContent:'center',gap:.65,p:1.75,minHeight:{xs:132,sm:126},borderRadius:'16px',bgcolor:'background.paper',border:'1px solid transparent',color:'text.primary',transition:'background-color .16s, border-color .16s','&:hover':{bgcolor:'#183339',borderColor:'primary.main'},'&.Mui-focusVisible':{outline:'3px solid #66e6c3',outlineOffset:3},'&.Mui-disabled':{color:'text.disabled'}}}>
    <ModuleIcon kind={c.id} size={22}/><Typography component="h2" sx={{fontSize:{xs:16,sm:18},fontWeight:600}}>{c.title}</Typography><Typography sx={{fontSize:{xs:10.5,sm:12},color:'text.secondary',textAlign:'center'}}>{locale==='en'&&c.id==='web'?'HTTP / TLS / Authentication':c.subtitle}</Typography><Typography variant="caption" sx={{fontSize:10.5,color:available?'primary.main':'text.secondary',mt:.25}}>{available?t(c.id==='web'?'웹 진단 작전실 →':c.id==='mobile'?'모바일 진단 작전실 →':c.id==='virtualization'?'VMware 설정 진단 →':c.id==='network'?'GNS3 구성 진단 →':'실행 파일·시스템 진단 작전실 →','Go to assessment operations →'):t('준비 중','Planned')}</Typography>
   </ButtonBase>;})}
  </Box>
  <Box aria-hidden="true" sx={{display:'flex',justifyContent:'center',py:1,color:'#9a9fa2'}}><ModuleIcon kind="arrow" size={20}/></Box>
  <Paper variant="outlined" sx={{textAlign:'center',p:3,borderRadius:'16px',bgcolor:'background.paper'}}><Stack direction="row" gap={1} alignItems="center" justifyContent="center"><ModuleIcon kind="report" size={21}/><Typography fontWeight={700}>{t('공통 보안 분석 및 보고서','Shared security analysis and reporting')}</Typography></Stack><Typography variant="body2" color="text.secondary" mt={1}>{t('진단 근거 · 위험도 · 개선 방법 · 이력 · AI 분석','Evidence · Risk · Remediation · History · AI analysis')}</Typography><Stack direction="row" gap={1} flexWrap="wrap" justifyContent="center" mt={1.5}><Chip size="small" variant="outlined" label={t('결과·재검증·JSON 제공','Results, retests and JSON')}/><Chip size="small" variant="outlined" label={t('정식 보고서·새 모듈 AI 준비 중','Full reports / module AI planned')}/></Stack><Button component={Link} href="/workbench/results" size="small" sx={{mt:1}}>{t('내 결과 확인하기 ↓','View my results ↓')}</Button></Paper>
  <Typography textAlign="center" variant="caption" color="text.secondary" component="p" sx={{mt:2,mb:0,lineHeight:1.8}}>{t('지원하는 항목만 점검합니다. 인증 심화·PWA·미지원 장비와 작업 예약은 아직 검사하지 않습니다.','Only supported checks run. Advanced authentication, PWA, unsupported devices and scheduling are not assessed yet.')}</Typography>
 </Box>;
}
