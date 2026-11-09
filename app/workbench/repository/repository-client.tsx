'use client';
import {useEffect,useRef,useState} from 'react';
import {ThemeProvider,CssBaseline,Container,Stack,Typography,Button,Paper,TextField,Checkbox,FormControlLabel,Alert,LinearProgress,Box} from '@mui/material';
import Link from '../../navigation-link';
import {platformTheme} from '../../platform-theme';
import {protectedRequest} from '../../../lib/protected-request';
import {repositoryLimits,repositoryFileLimit,reviewablePath} from '../../../lib/repository-review';
import RepositoryResults,{type RepositoryResult} from './repository-results';
export default function RepositoryReview({locale}:{locale:'ko'|'en'}){
 const t=(ko:string,en:string)=>locale==='ko'?ko:en;
 const [url,setUrl]=useState(''),[files,setFiles]=useState<File[]>([]),[consent,setConsent]=useState(false),[advisoryConsent,setAdvisoryConsent]=useState(false),[busy,setBusy]=useState(false),[result,setResult]=useState<RepositoryResult|null>(null),[error,setError]=useState('');
 const epoch=useRef(0),controller=useRef<AbortController|null>(null);
 useEffect(()=>()=>{epoch.current++;controller.current?.abort();},[]);
 function reset(){epoch.current++;controller.current?.abort();setBusy(false);setConsent(false);setAdvisoryConsent(false);setResult(null);setError('');}
 async function inspect(){if(!consent||busy)return;const stamp=++epoch.current,c=new AbortController();controller.current=c;setBusy(true);setResult(null);setError('');
  try{
   let payload:object;
   if(files.length){const selected=[];let total=0;for(const file of files){if(file.size>repositoryFileLimit(file.name)||!reviewablePath(file.name))throw new Error('INPUT_INVALID');total+=file.size;if(total>repositoryLimits.totalBytes)throw new Error('INPUT_INVALID');selected.push({path:file.name,text:new TextDecoder('utf-8',{fatal:true}).decode(await file.arrayBuffer())});if(stamp!==epoch.current)return;}payload={files:selected};}
   else payload={url};
   const response=await protectedRequest('/api/repository-review',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({...payload,authorized:true,advisories:advisoryConsent}),signal:c.signal});const data=await response.json();if(stamp!==epoch.current)return;
   if(!response.ok)throw new Error(data.errorCode??'FAILED');setResult(data);setConsent(false);setAdvisoryConsent(false);
  }catch(e){if(stamp!==epoch.current)return;const code=e instanceof Error?e.message:'';setError(({INPUT_INVALID:t('파일 형식·중복 이름·크기를 확인하세요.','Check file type, duplicate names and size.'),REPOSITORY_URL:t('https://github.com/소유자/저장소 형식만 지원합니다.','Use https://github.com/owner/repository.'),GITHUB_RATE_LIMIT:t('GitHub 조회 한도에 도달했습니다. 기다린 뒤 다시 시도하거나 로컬 파일을 선택하세요.','GitHub rate limit reached. Wait or choose local files.'),GITHUB_NOT_FOUND:t('공개 저장소를 찾을 수 없습니다.','Public repository not found.'),GITHUB_RESPONSE_TOO_LARGE:t('저장소 목록이 조회 크기 한도를 넘었습니다. 검토할 파일을 직접 선택하세요.','Repository listing exceeds limits. Select source files directly.')} as Record<string,string>)[code]??t('검사 요청에 실패했습니다. 로그인·접근 보호 상태를 확인한 뒤 다시 시도하세요.','Inspection failed. Check sign-in and access protection, then retry.'));setConsent(false);
  }finally{if(stamp===epoch.current)setBusy(false);}
 }
 function download(){if(!result)return;const link=document.createElement('a'),object=URL.createObjectURL(new Blob([JSON.stringify(result,null,2)],{type:'application/json'}));link.href=object;link.download='repository-review.json';link.click();setTimeout(()=>URL.revokeObjectURL(object),1000);}
 return <ThemeProvider theme={platformTheme}><CssBaseline/><Container maxWidth="md" sx={{py:4}}><Stack gap={3}>
  <Button component={Link} href="/workbench" sx={{alignSelf:'start'}}>← {t('검사 선택','Assessment modules')}</Button>
  <Typography variant="h4" component="h1">{t('GitHub·소스 공급망 진단 작전실','GitHub / source supply-chain review')}</Typography>
  <Alert severity="warning">{t('저장소 코드를 실행하지 않고 위험 단서를 찾습니다. 탐지 없음은 안전 판정이 아니며, 이 화면은 PC 감염·GitHub 계정·Desktop 앱을 검사하지 않습니다.','Find risk signals without executing repository code. No findings does not mean safe. This page does not inspect PC infections, GitHub accounts or the Desktop app.')}</Alert>
  <Paper variant="outlined" sx={{p:3}}><Stack gap={2}>
   <TextField label={t('공개 GitHub 저장소 주소','Public GitHub repository URL')} value={url} disabled={busy} onChange={e=>{reset();setFiles([]);setUrl(e.target.value);}} placeholder="https://github.com/owner/repository"/>
   <Typography>{t('또는 다운로드한 소스 파일을 직접 선택하세요. ZIP·실행 파일·.env는 지원하지 않습니다.','Or select downloaded source files. ZIP, executables and .env are unsupported.')}</Typography>
   <Button component="label" variant="outlined" disabled={busy}>{t('소스 파일 선택','Choose source files')}<input hidden type="file" multiple accept=".json,.js,.ts,.tsx,.jsx,.py,.go,.ps1,.sh,.bat,.cmd,.csproj,.props,.targets,.yml,.yaml,.md,.toml" onChange={e=>{reset();const chosen=Array.from(e.target.files??[]);e.target.value='';setUrl('');if(chosen.length>30||chosen.some(f=>!reviewablePath(f.name)||f.size>repositoryFileLimit(f.name))||chosen.reduce((n,f)=>n+f.size,0)>524288){setFiles([]);setError(t('최대 30개·일반 파일 64 KiB·package-lock.json 256 KiB·합계 512 KiB만 허용합니다.','Up to 30 files: ordinary files 64 KiB, package-lock.json 256 KiB, total 512 KiB.'));}else setFiles(chosen);}}/></Button>
   {files.length>0&&<Typography sx={{overflowWrap:'anywhere'}}>{files.map(f=>f.name).join(', ')}</Typography>}
   <FormControlLabel control={<Checkbox checked={advisoryConsent} disabled={busy||(!url&&!files.length)} onChange={e=>{const enabled=e.target.checked;reset();setAdvisoryConsent(enabled);}}/>} label={t('추가 선택: 파일에서 추출한 npm 패키지명·정확한 버전을 GitHub에 보내 공개 취약점 권고와 대조합니다. 최대 5개·추가 API 조회가 발생합니다.','Optional: send extracted npm package names and exact versions to GitHub to match public vulnerability advisories. Up to five packages; additional API requests apply.')}/>
   <FormControlLabel control={<Checkbox checked={consent} disabled={busy||(!url&&!files.length)} onChange={e=>setConsent(e.target.checked)}/>} label={t('점검 권한을 확인했으며 선택한 파일의 읽기·서버 전송 또는 공개 저장소 조회에 동의합니다. 비밀정보는 포함하지 않았습니다.','I have permission and consent to reading/sending selected files or fetching this public repository. No secrets are included.')}/>
   <Stack direction="row" gap={1}><Button variant="contained" disabled={busy||!consent} onClick={()=>void inspect()}>{t('실행 없이 검사','Inspect without execution')}</Button>{busy&&<Button onClick={reset}>{t('취소','Cancel')}</Button>}</Stack>{busy&&<LinearProgress/>}{error&&<Alert severity="error" role="alert">{error}</Alert>}
  </Stack></Paper>
  <Box component="details"><Typography component="summary" sx={{cursor:'pointer',color:'primary.main'}}>{t('검사 방법·지원 범위·PC 확인 방법','How this works, coverage and checking your PC')}</Typography><Stack gap={1} mt={2}>
   <Typography>{t('GitHub 주소 조회는 기본 브랜치의 커밋을 고정하고 텍스트 최대 12개·일반 파일 32 KiB·package-lock.json 256 KiB·합계 256 KiB만 읽습니다. 공개 취약점 대조는 추가 동의 후 GitHub가 검토한 npm 권고만 조회합니다. 버전 범위·미지원 생태계·개수 한도·조회 실패는 미확인으로 남습니다. 설치·빌드·clone·실행·Release 다운로드는 하지 않습니다.','GitHub mode pins the default commit and reads up to 12 text files: ordinary files 32 KiB, package-lock.json 256 KiB, total 256 KiB. With additional consent, compare GitHub-reviewed npm advisories. Version ranges, unsupported ecosystems, package caps and lookup failures remain unverified. No install, build, clone, execution or release download.')}</Typography>
   <Typography>{t('로컬 파일은 동의 후 서버 메모리에서만 분석합니다. 파일·결과를 DB에 저장하거나 AI에 보내지 않습니다. 새로고침하면 결과가 사라지므로 JSON을 내려받으세요. 주석·문서도 단서로 탐지될 수 있습니다. 정적 문자열 규칙은 난독화·여러 파일의 실행 흐름·의존성 악성 여부·비공개 저장소·계정 설정을 판정하지 못합니다.','Local files are analyzed in server memory after consent. No database storage or AI transfer. Download JSON before reloading. Comments/documentation can trigger findings. String heuristics cannot determine obfuscated/cross-file behavior, dependency malware, private repositories or account settings.')}</Typography>
   <Alert severity="info">{t('미검사: Visual Studio .suo 바이너리, Electron 로더 내부, 실행 중인 프로세스·메모리, 실제 정보 탈취와 클립보드 변조. 별도 백신·침해 분석이 필요합니다.','Unassessed: Visual Studio .suo binaries, Electron loader internals, running processes/memory, actual data theft and clipboard tampering. Separate antivirus and incident analysis is required.')}</Alert>
   <Typography>{t('PC 확인: Windows 보안 → 바이러스 및 위협 방지 → 보호 업데이트 → 검사 옵션 → 전체 검사. 오프라인 검사는 PC를 재시작하므로 저장 후 직접 실행하세요. 의심 파일을 실행했거나 공격 지표가 확인되면 네트워크에서 분리하고 깨끗한 기기에서 세션·토큰을 폐기하고 계정을 복구하세요.','PC check: Windows Security → Virus & threat protection → Protection updates → Scan options → Full scan. Offline scan restarts your PC; save work and start it yourself. If suspicious code ran or indicators match, isolate the device and revoke sessions/tokens from a clean device.')}</Typography>
  </Stack></Box>
  {result&&<RepositoryResults result={result} locale={locale} download={download}/>}
 </Stack></Container></ThemeProvider>;
}
