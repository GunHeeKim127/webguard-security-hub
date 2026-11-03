'use client';
import InspectionProblem from './inspection-problem';
import {singleFileSelection,singleFileMessage} from '../../lib/single-file';
import {configurationFileText} from '../../lib/configuration-file';
import {infrastructureFileIssue} from '../../lib/infrastructure-format';

import {useEffect,useRef,useState} from 'react';
import {Alert,Button,Checkbox,FormControlLabel,MenuItem,Stack,TextField,Typography} from '@mui/material';
/** InfrastructureInput: 지원 인프라 설정의 선택·읽기 동의·입력 상태를 관리합니다 주요 호출: useState·parse·useRef. */ export default function InfrastructureInput({kind,locale,value,disabled,onText}:{kind:'virtualization.vmx'|'network.gns3',locale:'ko'|'en',value:string,disabled:boolean,onText:(value:string)=>void}){
 const t=/** t: 현재 화면 언어에 맞는 문구를 고릅니다 */ (ko:string,en:string)=>locale==='ko'?ko:en;
 const [mode,setMode]=useState<'topology'|'bind9'|'cisco-ios'>('topology');
 const policy=kind==='network.gns3'&&mode!=='topology';
 const emit=/** emit: 전달된 자료를 결과·상태·출력에 반영합니다 주요 호출: onText·trim·stringify. */ (text:string)=>onText(policy&&text.trim()?JSON.stringify({type:'network-security-config',schemaVersion:1,format:mode,configuration:text}):text);
 let displayed=value;if(policy&&value){try{displayed=JSON.parse(value).configuration??'';}catch{displayed='';}}
 const [file,setFile]=useState<File|null>(null),[consent,setConsent]=useState(false),[reading,setReading]=useState(false),[error,setError]=useState('');
 const generation=useRef(0),input=useRef<HTMLInputElement|null>(null);
 useEffect(/** useEffect 콜백: 의존값에 따른 부수 작업과 정리를 실행합니다 */ ()=>/** useEffect 콜백: 의존값에 따른 부수 작업과 정리를 실행합니다 */ ()=>{generation.current++;},[]);
 /** read: 요청한 자료나 현재 상태를 조회합니다 주요 호출: setError·t·setReading. */ async function read(){
  if(disabled||reading)return;
  if(!file){setError(t('읽을 설정 파일을 먼저 선택해 주세요.','Select a configuration file first.'));return;}
  if(!consent)return;
  const stamp=++generation.current;setReading(true);setError('');
  try{const issue=infrastructureFileIssue(file.name,kind,locale);if(issue){setError(issue);return;}const text=configurationFileText(new Uint8Array(await file.arrayBuffer()));if(stamp!==generation.current)return;const bytes=new TextEncoder().encode(policy?JSON.stringify({type:'network-security-config',schemaVersion:1,format:mode,configuration:text}):text).length;if(!text.trim()||bytes>65536)throw new Error();emit(text);}
  catch{if(stamp===generation.current){onText('');setError(t('비어 있거나 읽을 수 없는 설정입니다. UTF-8/UTF-16 BOM·64 KiB 제한과 지원 형식을 확인하세요.','Empty or unreadable configuration. Check UTF-8/UTF-16 BOM, the 64 KiB limit and supported formats.'));}}
  finally{if(stamp===generation.current){setReading(false);setConsent(false);}}
 }
 return <Stack gap={1.5}>
  {kind==='virtualization.vmx'&&<Alert severity="info">{t('지원 설정: .vmx, .ovf, libvirt .xml, VirtualBox .vbox 또는 해당 형식의 텍스트. 파일의 실제 구조를 확인합니다. .ova·가상 디스크는 직접 검사하지 않습니다. OVF는 설명 구조만 확인하며 실제 공유·격리 상태는 별도입니다.','Supported configuration: .vmx, .ovf, libvirt .xml, VirtualBox .vbox or equivalent text. Actual structure is checked. OVA/disks are not directly inspected; OVF structure does not establish effective isolation.')}</Alert>}
  {kind==='network.gns3'&&<><TextField select label={t('1. 확인할 자료 종류','1. Choose evidence type')} value={mode} disabled={disabled||reading} onChange={/** onChange 콜백: onChange 이벤트의 입력·상태 처리를 실행합니다 주요 호출: setMode·setFile·setConsent. */ e=>{generation.current++;setMode(e.target.value as typeof mode);setFile(null);setConsent(false);setError('');if(input.current)input.current.value='';onText('');}}><MenuItem value="topology">{t('GNS3 프로젝트 · 노드/연결','GNS3 project · nodes/links')}</MenuItem><MenuItem value="bind9">DNS · BIND 9 named.conf</MenuItem><MenuItem value="cisco-ios">{t('라우터 설정 · Cisco IOS · RIP/EIGRP/IS-IS','Router configuration · Cisco IOS · RIP/EIGRP/IS-IS')}</MenuItem></TextField><Alert severity="info">{t('2. 허가받은 설정 파일 하나를 선택하거나 붙여넣으세요. GNS3 프로젝트에는 라우터의 실제 설정이 없을 수 있습니다. 키·암호 값은 지우고, 필요한 명령 구조는 유지하세요. 3. 읽기 허용 → 설정 읽기 → 아래 권한 확인·진단 순서로 진행합니다.','2. Choose or paste one authorized configuration. GNS3 topology may not contain device configuration. Remove key/password values while retaining command structure. 3. Allow reading → read → confirm authorization and assess below.')}</Alert></>}
  <Alert severity="info">{t('설정 파일을 선택해도 자동으로 읽지 않습니다. 읽기를 허용한 뒤 확인하세요. 진단 시 설정 원문은 서버 메모리에서만 분석하며 결과에는 고정된 관찰값만 저장합니다. 서버·VM·장비에 접속하거나 설정을 변경하지 않습니다.','Selecting does not read a file. Explicitly allow reading. Assessment analyzes the configuration in server memory and saves only fixed observations. No server/VM/device access or setting changes.')}</Alert>
  <Typography variant="body2">{singleFileMessage(locale)}</Typography><Button component="label" variant="outlined" disabled={disabled||reading}>{t('설정 파일 선택 · 최대 64 KiB','Choose configuration · up to 64 KiB')}<input ref={input} type="file" multiple={false} hidden disabled={disabled||reading} accept={undefined} onChange={/** onChange 콜백: onChange 이벤트의 입력·상태 처리를 실행합니다 주요 호출: setConsent·setReading·setError. */ e=>{generation.current++;setConsent(false);setReading(false);setError('');onText('');const selection=singleFileSelection(e.target.files),selected=selection.file;if(selection.tooMany){e.target.value='';setFile(null);setError(singleFileMessage(locale));return;}if(selected&&infrastructureFileIssue(selected.name,kind,locale)){setFile(null);setError(infrastructureFileIssue(selected.name,kind,locale)!);}else if(selected&&(selected.size>65536||selected.size===0)){setFile(null);setError(t('내용이 있는 64 KiB 이하 파일을 선택하세요.','Choose a nonempty file up to 64 KiB.'));}else setFile(selected);}}/></Button>
  <Typography variant="body2">{file?file.name:t('선택된 파일 없음','No file selected')}</Typography>
  <FormControlLabel label={t('현재 설정 파일을 이 검사에 한해 읽도록 허용합니다.','Allow reading this configuration for this inspection.')} control={<Checkbox checked={consent} disabled={!file||disabled||reading} onChange={/** onChange 콜백: onChange 이벤트의 입력·상태 처리를 실행합니다 주요 호출: setConsent. */ e=>setConsent(e.target.checked)}/>}/>
  <Button disabled={disabled||reading||!!file&&!consent} onClick={/** onClick 콜백: onClick 이벤트의 입력·상태 처리를 실행합니다 주요 호출: read. */ ()=>void read()}>{reading?t('설정 읽는 중','Reading configuration'):t('허용한 설정 읽기','Read permitted configuration')}</Button>
  {file&&!consent&&!reading&&!disabled&&<Alert severity="info" role="status">{value.trim()?t('설정을 입력란에 반영했습니다. 아래 권한 확인 후 진단하세요. 파일을 다시 읽으려면 읽기를 다시 허용하세요.','Configuration is in the input below. Confirm authorization and assess. Renew read permission to read the file again.'):t('설정 파일을 읽으려면 위의 읽기 허용에 체크해 주세요.','To read the configuration file, allow reading above.')}</Alert>}
  <InspectionProblem locale={locale} message={error}/>
  <TextField label={policy?(mode==='bind9'?'BIND 9 named.conf':'Cisco IOS configuration'):kind==='virtualization.vmx'?t('VMX·OVF·libvirt XML·VirtualBox 설정','VMX / OVF / libvirt XML / VirtualBox configuration'):t('GNS3 2.x 프로젝트 JSON · 직접 입력 가능','GNS3 2.x project JSON · paste supported')} value={displayed} multiline minRows={6} maxRows={16} disabled={disabled||reading} onChange={/** onChange 콜백: 수동 입력으로 바꾸면 파일 동의와 이전 입력 오류를 초기화합니다. */ e=>{generation.current++;setFile(null);setConsent(false);setError('');if(input.current)input.current.value='';emit(e.target.value);}} helperText={t('최대 64 KiB(전송 형식 포함). 실제 실행·취약점 스캔이 아닌 제공된 설정의 정적 점검입니다.','Up to 64 KiB including transport envelope. Static review only; no execution or vulnerability scan.')}/>
 </Stack>;
}
