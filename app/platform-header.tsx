'use client';

import {useState} from 'react';
import {Alert,Box,Button,Chip,MenuItem,Stack,TextField,Typography} from '@mui/material';
import Link from './navigation-link';
import {localeNames,type Locale} from '../lib/locale';
import type {PublicUser} from '../lib/public-identity';
import {protectedRequest} from '../lib/protected-request';

export type PlatformLocation='modules'|'web'|'comparison'|'results'|'help'|'endpoint'|'java'|'repository'|'mobile'|'network'|'virtualization';
const labels:Record<Locale,readonly string[]>={
 ko:['통합 보안 진단','검사 선택','웹 진단','내 결과','사용 가이드','주 메뉴','관련 검사','언어','로그아웃','관리자','분석가','일반 회원','설정을 변경하지 못했습니다. 잠시 후 다시 시도하세요.'],
 en:['Unified security assessment','Choose a check','Web assessment','My results','User guide','Main navigation','Related checks','Language','Sign out','Admin','Analyst','Member','Unable to update. Please try again.'],
 ja:['統合セキュリティ診断','検査を選択','Web診断','自分の結果','利用ガイド','メインメニュー','関連する検査','言語','ログアウト','管理者','分析担当','一般会員','変更できませんでした。もう一度お試しください。'],
 zh:['统一安全检查','选择检查','Web 检查','我的结果','使用指南','主菜单','相关检查','语言','退出登录','管理员','分析员','普通会员','无法更新，请稍后重试。'],
 es:['Evaluación de seguridad','Elegir revisión','Revisión web','Mis resultados','Guía de uso','Navegación principal','Revisiones relacionadas','Idioma','Cerrar sesión','Administrador','Analista','Miembro','No se pudo actualizar. Inténtelo de nuevo.'],
 fr:['Évaluation de sécurité','Choisir un contrôle','Contrôle web','Mes résultats','Guide','Navigation principale','Contrôles associés','Langue','Déconnexion','Administrateur','Analyste','Membre','Échec de la modification. Réessayez.'],
};

const webLabels:Record<Locale,readonly [string,string]>={ko:['웹사이트 기본 보안 점검','PC·모바일 접속 환경 비교'],en:['Website security check','Desktop / mobile connection comparison'],ja:['Webサイトの基本セキュリティ確認','PC・モバイル接続環境の比較'],zh:['网站基础安全检查','桌面与移动连接环境比较'],es:['Seguridad básica del sitio web','Comparación de conexión PC / móvil'],fr:['Sécurité de base du site web','Comparaison des connexions PC / mobile']};

/** Shared navigation keeps global destinations separate from checks within one module. */
export default function PlatformHeader({locale,current,user,busy=false,onLogout,onLocaleChange,onSwitchingChange,localeOptions=['ko','en']}:{locale:Locale;current:PlatformLocation;user?:PublicUser;busy?:boolean;onLogout?:()=>void|Promise<void>;onLocaleChange:(locale:Locale)=>void;onSwitchingChange?:(switching:boolean)=>void;localeOptions?:readonly Locale[]}){
 const [switching,setSwitching]=useState(false),[error,setError]=useState(false);
 const l=labels[locale],ko=locale==='ko',web=current==='web'||current==='comparison',endpoint=current==='endpoint'||current==='java';
 const active=current==='results'||current==='help'?current:'modules';
 const items=[{id:'modules',href:'/workbench',label:l[1]},{id:'results',href:'/workbench/results',label:l[3]},{id:'help',href:'/help',label:l[4]}];
 const related=web?[{id:'web',href:'/?view=web',label:webLabels[locale][0]},{id:'comparison',href:'/workbench/web',label:webLabels[locale][1]}]:endpoint?[{id:'endpoint',href:'/workbench/endpoint',label:ko?'프로그램·컴퓨터 보안 점검':'Program / computer security check'},{id:'java',href:'/workbench/java',label:ko?'Java 실행 환경 보안 점검':'Java runtime security check'}]:current==='results'?[{id:'results',href:'/workbench/results',label:ko?'모듈 진단 기록':'Module assessment history'},{id:'web-history',href:'/?view=web#web-results',label:ko?'웹사이트 점검 기록':'Website assessment history'}]:[];
 async function changeLanguage(value:Locale){setSwitching(true);onSwitchingChange?.(true);setError(false);try{const r=await fetch('/api/locale',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({locale:value})});if(!r.ok)throw new Error();onLocaleChange(value);}catch{setError(true);}finally{setSwitching(false);onSwitchingChange?.(false);}}
 async function logout(){if(onLogout){await onLogout();return;}setSwitching(true);setError(false);try{const r=await protectedRequest('/api/logout',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'});if(!r.ok)throw new Error();try{const channel=new BroadcastChannel('webguard-session');channel.postMessage('changed');channel.close();}catch{/* Session invalidation remains enforced by the server. */}window.location.replace('/');}catch{setError(true);setSwitching(false);}}
 return <Box component="header" sx={{borderBottom:1,borderColor:'divider',pb:2,mb:3}}>
  <Stack direction={{xs:'column',sm:'row'}} justifyContent="space-between" alignItems={{xs:'stretch',sm:'center'}} gap={2}>
   <Box component={Link} href="/workbench" aria-label={`VELTHARA · ${l[1]}`} sx={{textDecoration:'none',color:'primary.main',width:'fit-content'}}><Typography component="span" fontWeight={800} sx={{letterSpacing:1.4,fontSize:20}}>◈ VELTHARA</Typography><Typography variant="caption" display="block" color="text.secondary">{l[0]}</Typography></Box>
   <Stack direction="row" alignItems="center" justifyContent={{xs:'space-between',sm:'flex-end'}} gap={2}>
    {user&&<Stack alignItems="flex-end" sx={{minWidth:0}}><Typography variant="caption" color="text.secondary" sx={{overflowWrap:'anywhere'}}>{user.email}</Typography><Stack direction="row" alignItems="center" gap={.5}><Chip size="small" variant="outlined" label={l[user.role==='admin'?9:user.role==='analyst'?10:11]}/><Button size="small" onClick={()=>void logout()} disabled={busy||switching}>{l[8]}</Button></Stack></Stack>}
    <TextField select size="small" label={l[7]} value={locale} disabled={busy||switching} onChange={e=>void changeLanguage(e.target.value as Locale)} sx={{minWidth:110}}>{localeOptions.map(value=><MenuItem value={value} key={value} lang={value}>{localeNames[value]}</MenuItem>)}</TextField>
   </Stack>
  </Stack>
  <Stack component="nav" aria-label={l[5]} direction="row" flexWrap="wrap" gap={.5} sx={{mt:2}}>{items.map(item=><Button component={Link} href={item.href} key={item.id} aria-current={active===item.id?(current===item.id?'page':'location'):undefined} variant={active===item.id?'contained':'text'} size="small" sx={{px:1.75,minHeight:36}}>{item.label}</Button>)}</Stack>
  {related.length>0&&<Stack component="nav" aria-label={l[6]} direction="row" flexWrap="wrap" gap={.5} sx={{mt:1.5,pt:1.5,borderTop:1,borderColor:'divider'}}>{related.map(item=><Button component={Link} key={item.id} href={item.href} size="small" aria-current={current===item.id?'page':undefined} sx={{color:current===item.id?'primary.main':'text.secondary',bgcolor:current===item.id?'action.selected':undefined,px:1.5}}>{item.label}</Button>)}</Stack>}
  {error&&<Alert severity="warning" sx={{mt:2}}>{l[12]}</Alert>}
 </Box>;
}
