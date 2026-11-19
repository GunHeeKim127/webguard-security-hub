'use client';
import {useEffect,useRef,useState} from 'react';
import {ThemeProvider,CssBaseline,Container,Stack,Typography,Paper,Alert,TextField,MenuItem,Button,Checkbox,FormControlLabel,Box,LinearProgress,Chip} from '@mui/material';
import PlatformHeader from '../../platform-header';
import type {PublicUser} from '../../../lib/public-identity';
import {platformTheme} from '../../platform-theme';
import {protectedRequest} from '../../../lib/protected-request';
import type {JavaRuntimeInput,JavaRuntimeReport} from '../../../lib/java-runtime-review';
const initial:JavaRuntimeInput={version:'',vendor:'unknown',architecture:'unknown',cpuFeatures:'unknown',intrinsic:'unknown',untrustedBase64:'unknown',performancePack:'unknown'};
/** Endpoint JVM observations, with explicit consent and no target execution. */
export default function JavaReview({locale:initialLocale,user}:{locale:'ko'|'en';user?:PublicUser}){
 const [locale,setLocale]=useState(initialLocale);
 const t=(ko:string,en:string)=>locale==='ko'?ko:en;
 const [input,setInput]=useState(initial),[consent,setConsent]=useState(false),[busy,setBusy]=useState(false),[report,setReport]=useState<JavaRuntimeReport|null>(null),[error,setError]=useState('');
 const epoch=useRef(0),request=useRef<AbortController|null>(null);
 useEffect(()=>()=>{epoch.current++;request.current?.abort();},[]);
 function change(key:keyof JavaRuntimeInput,value:string){epoch.current++;request.current?.abort();setInput(old=>({...old,[key]:value}));setConsent(false);setReport(null);setError('');setBusy(false);}
 function cancel(){epoch.current++;request.current?.abort();setBusy(false);setConsent(false);setReport(null);setError('');}
 async function inspect(){if(!consent||busy)return;const stamp=++epoch.current,controller=new AbortController();request.current=controller;setBusy(true);setReport(null);setError('');
  try{const response=await protectedRequest('/api/java-review',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({authorized:true,runtime:input}),signal:controller.signal});const data=await response.json();if(stamp!==epoch.current)return;if(!response.ok)throw new Error();setReport(data.report);}
  catch{if(stamp===epoch.current&&!controller.signal.aborted)setError(t('점검 요청에 실패했습니다. 로그인·입력값·요청 한도를 확인하고 다시 시도하세요.','Review failed. Check sign-in, input and request limits, then retry.'));}
  finally{if(stamp===epoch.current){setBusy(false);setConsent(false);}}
 }
 function download(){if(!report)return;const url=URL.createObjectURL(new Blob([JSON.stringify(report,null,2)],{type:'application/json'})),link=document.createElement('a');link.href=url;link.download='java4shell-review.json';link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}
 const select=(key:Exclude<keyof JavaRuntimeInput,'version'>,label:string,options:[string,string][],help?:string)=><TextField select label={label} value={input[key]} disabled={busy} onChange={e=>change(key,e.target.value)} helperText={help}>{options.map(([value,title])=><MenuItem key={value} value={value}>{title}</MenuItem>)}</TextField>;
 const unknown=t('확인하지 못함','Unknown');
 return <ThemeProvider theme={platformTheme}><CssBaseline/><Container maxWidth="md" sx={{py:4}}><Stack gap={3}>
  <PlatformHeader locale={locale} current="java" user={user} busy={busy} onLocaleChange={value=>setLocale(value==='ko'?'ko':'en')}/>
  <Box><Typography variant="overline">ENDPOINT · JAVA / JVM</Typography><Typography component="h1" variant="h4">{t('Java4Shell 적용 여부 점검','Java4Shell applicability review')}</Typography><Typography mt={1}>CVE-2026-114938 · {t('공식 권고 확인일: 2026-11-19','Advisories reviewed: 2026-11-19')}</Typography></Box>
  <Alert severity="info">{t('Java/JVM 실행 환경 점검입니다. 웹 서버·서버 앱·PC 프로그램·번들 런타임 모두 대상이 될 수 있습니다. URL·HTTP 헤더·JAR 이름만으로는 판정할 수 없습니다. Log4Shell과는 다른 JVM Base64 처리 취약점입니다.','Review the Java/JVM runtime used by web servers, server apps, desktop apps or bundled software. URLs, HTTP headers and JAR names cannot establish applicability. This JVM Base64 issue is distinct from Log4Shell.')}</Alert>
  <Paper variant="outlined" sx={{p:3}}><Stack gap={2}>
   <Typography variant="h6">{t('대상 JVM의 확인 자료','Evidence from the target JVM')}</Typography>
   <Typography variant="body2">{t('모르는 값은 확인하지 못함으로 두세요. 대상 프로세스의 값만 입력하고 비밀 키·전체 실행 명령·개인 경로는 넣지 마세요.','Leave unknown fields as Unknown. Enter target-process evidence only, without secrets, complete command lines or personal paths.')}</Typography>
   <TextField label={t('Java 버전','Java version')} placeholder="17.0.21.0.3 / 17.0.21.1+4" value={input.version} disabled={busy} onChange={e=>change('version',e.target.value)} slotProps={{htmlInput:{maxLength:80}}} helperText={t('java -version의 숫자 버전만 입력하세요. 17.0.21.0.3과 17.0.21.1은 다른 버전입니다.','Enter the numeric version from java -version. 17.0.21.0.3 and 17.0.21.1 are different releases.')}/>
   {select('vendor',t('배포 공급자','Distribution'),[['unknown',unknown],['oracle','Oracle Java SE'],['openjdk',t('OpenJDK 계열 · 공급자 공지 별도 확인','OpenJDK distribution · verify vendor advisory')],['graalvm','GraalVM'],['other',t('기타·번들 JBR','Other / bundled JBR')]])}
   {select('architecture',t('대상 JVM의 CPU 아키텍처','Target JVM CPU architecture'),[['unknown',unknown],['x64','x86-64 / amd64'],['arm64','ARM64 / aarch64'],['other',t('그 밖의 아키텍처','Other architecture')]])}
   {select('cpuFeatures',t('CPU 기능 4개 지원 여부','CPU feature support'),[['unknown',unknown],['supported',t('4개 모두 지원 확인','All four confirmed supported')],['not_supported',t('전체 목록에서 필요한 기능 미지원 확인','Required feature absent in complete inventory')]],'avx512f · avx512bw · avx512vbmi · bmi2')}
   {select('intrinsic',t('실제 프로세스의 Base64 intrinsic','Effective Base64 intrinsic'),[['unknown',unknown],['enabled',t('활성 확인','Confirmed enabled')],['disabled',t('비활성 확인','Confirmed disabled')]],t('새로 실행한 java의 기본값은 기존 서비스의 실효 설정을 증명하지 않습니다.','Defaults in a newly started java process do not attest to the existing service.') )}
   {select('untrustedBase64',t('외부·비신뢰 Base64 데이터 도달','Untrusted Base64 reaches decoder'),[['unknown',unknown],['yes',t('해당 경로 확인','Path confirmed')],['no',t('검토한 범위에서 도달하지 않음','No path in reviewed scope')]])}
   {select('performancePack',t('Java 8 Performance Pack 여부','Java 8 Performance Pack'),[['unknown',unknown],['yes',t('사용 확인','Confirmed used')],['no',t('미사용 확인 · 또는 Java 8 대상 아님','Not used / not a Java 8 target')]])}
   <FormControlLabel control={<Checkbox checked={consent} disabled={busy} onChange={e=>setConsent(e.target.checked)}/>} label={t('점검 권한이 있으며 위 자료의 이번 서버 분석에 동의합니다. 실제 기기에 접속하거나 변경하지 않는 점을 확인했습니다.','I have assessment permission and consent to this server analysis. The target is not accessed or modified.')}/>
   <Stack direction="row" gap={1}><Button variant="contained" disabled={busy||!consent} onClick={()=>void inspect()}>{t('Java4Shell 적용 여부 점검','Review Java4Shell applicability')}</Button>{busy&&<Button onClick={cancel}>{t('취소','Cancel')}</Button>}</Stack>{busy&&<LinearProgress/>}{error&&<Alert severity="error">{error}</Alert>}
  </Stack></Paper>
  <Box component="details"><Typography component="summary" sx={{cursor:'pointer',color:'primary.main'}}>{t('자료 확인·업데이트 방법 펼치기','How to collect evidence and update')}</Typography><Stack gap={1.5} mt={2}>
   <Typography>{t('신뢰하는 설치본의 java -version으로 버전·배포판을 확인하세요. PATH의 Java와 서비스·컨테이너·IDE가 쓰는 Java는 다를 수 있습니다. 각 대상의 실제 런타임을 확인해야 합니다.','Use java -version from a trusted installation. Java on PATH may differ from Java bundled in services, containers or IDEs. Check each actual runtime.')}</Typography>
   <Typography>{t('Linux는 uname -m과 완전한 lscpu 출력 등으로 아키텍처·CPU 기능을 확인합니다. Windows는 제품 운영 도구·하드웨어 자료로 해당 기능을 확인하고, 단순히 64비트라는 표시나 CPU 이름만으로 기능을 추정하지 마세요.','On Linux use uname -m and complete lscpu output to confirm architecture and CPU features. On Windows use operating/vendor hardware tools; do not infer instruction support from 64-bit labels or a CPU name.')}</Typography>
   <Typography>{t('UseBASE64Intrinsics와 UseAVX 등은 실행 중인 대상 JVM의 실효 설정을 운영 담당자와 확인하세요. 전체 프로세스 명령행에는 비밀번호가 있을 수 있으므로 그대로 제출하지 마세요. 외부 입력 경로도 코드·설정 검토로 확인하며 공격 데이터를 보내지 않습니다.','Confirm effective UseBASE64Intrinsics/UseAVX settings with operators. Full process command lines can contain passwords; do not submit them. Review untrusted input paths through code/configuration without attack traffic.')}</Typography>
   <Typography>{t('공급자의 해당 CVE 수정 릴리스 또는 번들 제품 업데이트를 적용하고 프로세스를 재시작한 뒤 다시 점검하세요. CPU·JVM 임시 완화 옵션은 성능과 호환성을 확인해야 하며 자동 적용하지 않습니다.','Apply the vendor CVE fix or bundled-product update, restart the process and reassess. Temporary CPU/JVM mitigations require performance and compatibility review and are not applied automatically.')}</Typography>
   <Typography>{t('자료·결과는 DB에 저장하거나 외부 AI에 전송하지 않습니다. 결과를 보관하려면 JSON을 내려받으세요.','Input/results are not stored in the database or sent to external AI. Download JSON to retain the result.')}</Typography>
  </Stack></Box>
  {report&&<Paper variant="outlined" sx={{p:3}}><Stack gap={2}><Typography component="h2" variant="h5">{t('점검 결과','Review result')}</Typography><Alert severity={report.summary.code==='update_recommended'?'warning':'info'}><Typography fontWeight={700}>{report.summary.title}</Typography>{report.summary.detail}</Alert><Chip label={t('사용자 제공 자료 · 실행 상태 독립 검증 아님','Supplied evidence · not independent runtime verification')}/>{report.checks.map(c=><Box key={c.id} sx={{borderTop:1,borderColor:'divider',pt:2}}><Typography fontWeight={700}>{c.title} · {c.status==='warning'?t('보완 검토','Remediation review'):c.status==='not_assessed'?t('확인 필요','More evidence needed'):t('참고','Information')}</Typography><Typography>{c.detail}</Typography></Box>)}<Typography variant="h6">{t('해결·재확인 순서','Remediation and recheck steps')}</Typography>{report.remediation.map((r,i)=><Typography key={i}>{i+1}. {r}</Typography>)}<Button onClick={download}>{t('결과 JSON 다운로드','Download result JSON')}</Button>{report.references.map(url=><Typography key={url} component="a" href={url} target="_blank" rel="noopener noreferrer" sx={{overflowWrap:'anywhere'}}>{url.includes('oracle')?'Oracle':url.includes('cert.europa')?'CERT-EU':'CISA'} · {t('공식 권고','Official advisory')}</Typography>)}</Stack></Paper>}
 </Stack></Container></ThemeProvider>;
}
