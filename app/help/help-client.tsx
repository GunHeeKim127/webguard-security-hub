'use client';
import {useState} from 'react';
import {ThemeProvider,CssBaseline,Container,Stack,Typography,Button,Box,Alert} from '@mui/material';
import {platformTheme} from '../platform-theme';
import Link from '../navigation-link';
import ModuleGuide from '../workbench/module-guide';
import {moduleGuides} from '../../lib/assessment/module-guides';
import type {ModuleId} from '../../lib/assessment/types';
export default function Help({initialLocale}:{initialLocale:'ko'|'en'}){
 const [locale,setLocale]=useState(initialLocale),index=locale==='ko'?0:1,t=(ko:string,en:string)=>locale==='ko'?ko:en;
 return <ThemeProvider theme={platformTheme}><CssBaseline/><Container component="main" maxWidth="md" sx={{py:3,pb:6}}>
  <Stack component="header" direction="row" justifyContent="space-between" gap={1} flexWrap="wrap"><Button component={Link} href="/workbench">{t('검사 화면으로','Go to assessments')}</Button><Button onClick={()=>setLocale(locale==='ko'?'en':'ko')}>{locale==='ko'?'English':'한국어'}</Button></Stack>
  <Typography variant="h4" component="h1" sx={{my:2}}>{t('사용 가이드','User guide')}</Typography>
  <Typography sx={{mb:2}}>{t('지원 자료를 확인하고 하나를 선택하세요. 선택 → 읽기 허용 → 검사 → 결과 확인 → 저장 순서로 진행합니다.','Check supported input and choose one item: select → allow reading → inspect → review → save.')}</Typography>
  <Alert severity="info">{t('기준 충족은 전체 안전 보증이 아닙니다. 미검사는 안전·취약 어느 쪽도 확정하지 못한 상태입니다. 비밀번호·개인키는 올리지 마세요.','Meeting a criterion is not overall safety. Unassessed means no conclusion, not safe or vulnerable. Do not submit passwords or private keys.')}</Alert>
  <Stack component="nav" aria-label={t('가이드 목차','Guide contents')} direction="row" flexWrap="wrap" gap={.5} sx={{my:2}}>{(Object.keys(moduleGuides) as ModuleId[]).map(id=><Button key={id} component="a" href={'#'+id} size="small">{moduleGuides[id].title[index]}</Button>)}</Stack>
  <Stack gap={3}>{(Object.keys(moduleGuides) as ModuleId[]).map(id=><Box component="section" id={id} key={id} sx={{scrollMarginTop:24}}><Typography component="h2" variant="h6" sx={{mb:1}}>{moduleGuides[id].title[index]}</Typography><ModuleGuide moduleId={id} locale={locale} full/></Box>)}</Stack>
  <Box component="section" id="windows-export" sx={{mt:3}}><Typography component="h2" variant="h6">{t('Windows 정책 JSON 준비','Prepare a Windows policy JSON')}</Typography>
   <Button component="a" href="/tools/export-windows-policy.ps1" download="export-windows-policy.ps1">{t('읽기 전용 내보내기 도구 받기','Download read-only exporter')}</Button>
   <Typography variant="body2">{t('내용을 확인한 뒤 PowerShell에 & 와 공백을 입력하고 받은 .ps1을 끌어놓아 실행합니다. 저장할 새 JSON 경로를 묻습니다. 방화벽·Defender·RDP의 선택된 상태만 읽으며 설정은 바꾸지 않습니다.','Review the script. In PowerShell, type & and a space, drag in the downloaded .ps1 and run it. Enter a new JSON output path when prompted. It reads selected firewall/Defender/RDP states without changing settings.')}</Typography>
   <Typography variant="body2" color="text.secondary" sx={{mt:1}}>{t('조직 정책이 실행을 막으면 우회하지 말고 담당자에게 지원 형식의 내보내기를 요청하세요. 읽지 못한 값은 미검사로 남습니다.','If organizational policy blocks execution, ask the administrator for a supported export rather than bypassing policy. Unavailable states remain unassessed.')}</Typography>
  </Box>
  <Box component="section" id="ssh-preparation" sx={{mt:3}}><Typography component="h2" variant="h6">{t('SSH 자료는 어디서 준비하나요?','Where do I prepare SSH input?')}</Typography>
   <Typography variant="body2" sx={{my:1}}>{t('허가받은 Linux의 터미널·기존 SSH 세션에서 담당자가 확인합니다. 아래 명령은 기본 설정 기준의 읽기 전용 확인입니다. 서비스가 다른 설정 파일·옵션을 쓰면 그 조건을 먼저 확인하세요.','An administrator uses an authorized Linux terminal or existing SSH session. These are read-only checks of the default configuration; verify any custom service configuration/options first.')}</Typography>
   <Typography component="pre" variant="body2" sx={{p:2,bgcolor:'background.paper',whiteSpace:'pre-wrap',overflowWrap:'anywhere'}}>{'/usr/sbin/sshd -t\n/usr/sbin/sshd -T | grep -E \'^(permitrootlogin|passwordauthentication|permitemptypasswords|pubkeyauthentication|maxauthtries) \''}</Typography>
   <Typography variant="body2">{t('출력을 검토해 필요한 5개 값만 붙여넣으세요. 문법 검사 성공은 로그인 성공이 아닙니다. 사용자·주소별 Match는 sshd -T -C로 별도 확인하며, 서비스 재시작·인증 약화는 필요하지 않습니다.','Review the output and paste only the five required values. Syntax success is not login success. Inspect user/address Match conditions separately with sshd -T -C; no restart or weaker authentication is needed.')}</Typography>
  </Box>
  <Box component="section" id="troubleshooting" sx={{mt:3}}><Typography component="h2" variant="h6">{t('멈췄을 때 확인할 것','If inspection stops')}</Typography><Box component="ul" sx={{pl:3}}>
   <li><Typography variant="body2">{t('Mac .app은 폴더 묶음입니다. 브라우저에서 선택되지 않으면 로컬 도구를 쓰세요. .pkg·.dmg는 Mac 로컬 도구의 메타데이터 검사 대상입니다. 내부 코드까지 검사했다는 뜻은 아닙니다.','A Mac .app is a bundle directory. Use the local tool if browser selection is unavailable. PKG/DMG support local Mac metadata checks; their internal code is not inspected.')}</Typography></li>
   <li><Typography variant="body2">{t('파일 미선택: 실제 파일 하나를 선택하세요. 읽기 허용은 선택만으로 켜지지 않습니다.','No file: select an actual file. Selecting does not grant read consent.')}</Typography></li>
   <li><Typography variant="body2">{t('MODULE_NOT_FOUND: 대상 앱이 아니라 검사 도구 위치를 먼저 확인하세요. Mac 실행 안내로 실제 도구를 선택합니다.','MODULE_NOT_FOUND: check the inspector location, not the target app. Use the Mac launcher to select the tool.')}</Typography></li>
   <li><Typography variant="body2">{t('지원 형식·경로·권한·저장 이름을 확인하세요. 오류를 곧바로 취약점으로 해석하지 마세요.','Check supported format, location, permissions and a new output name. An operational error is not automatically a vulnerability.')}</Typography></li>
   <li><Typography variant="body2">{t('Mac 오류는 Diagnostic 한 줄을 전달하면 됩니다. 결과 JSON과 명령에 개인정보가 없는지 먼저 확인하세요.','For Mac issues, share the Diagnostic line. Check reports and commands for personal information first.')}</Typography></li>
  </Box></Box>
 </Container></ThemeProvider>;
}
