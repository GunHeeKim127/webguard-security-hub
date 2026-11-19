'use client';

import {Button,Stack,Typography} from '@mui/material';
import Link from './navigation-link';
import type {Locale} from '../lib/locale';
import type {PlatformLocation} from './platform-header';

const webLabels:Record<Locale,readonly [string,string]>={ko:['웹사이트 기본 보안 점검','PC·모바일 접속 환경 비교'],en:['Website security check','Desktop / mobile connection comparison'],ja:['Webサイトの基本セキュリティ確認','PC・モバイル接続環境の比較'],zh:['网站基础安全检查','桌面与移动连接环境比较'],es:['Seguridad básica del sitio web','Comparación de conexión PC / móvil'],fr:['Sécurité de base du site web','Comparaison des connexions PC / mobile']};

/** Show only a useful next destination inside the current page, without repeating module navigation. */
export default function ContextLinks({locale,current}:{locale:Locale;current:PlatformLocation}){
 const ko=locale==='ko';
 const destination=current==='web'?{href:'/workbench/web',label:webLabels[locale][1]}:current==='comparison'?{href:'/?view=web',label:webLabels[locale][0]}:current==='java'?{href:'/workbench/endpoint',label:ko?'프로그램·컴퓨터 보안 점검으로':'Back to program / computer security checks'}:current==='results'?{href:'/?view=web#web-results',label:ko?'웹사이트 점검 기록':'Website assessment history'}:null;
 if(!destination)return null;
 return <Stack component="nav" aria-label={ko?'관련 화면':'Related pages'} direction="row" gap={1} alignItems="center" flexWrap="wrap" sx={{mt:1.5}}>
  {current==='results'&&<Typography variant="body2" color="text.secondary">{ko?'모듈 진단 기록':'Module assessment history'}</Typography>}
  <Button component={Link} href={destination.href} size="small" sx={{px:0,textTransform:'none',textAlign:'left',justifyContent:'flex-start'}}>{current==='java'?'← ':''}{destination.label}{current==='java'?'':' →'}</Button>
 </Stack>;
}
