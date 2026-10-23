'use client';
import {useEffect,useRef,useState} from 'react';
import {Alert,Button,Checkbox,FormControlLabel,Stack,TextField,Typography} from '@mui/material';
export default function InfrastructureInput({kind,locale,value,disabled,onText}:{kind:'virtualization.vmx'|'network.gns3',locale:'ko'|'en',value:string,disabled:boolean,onText:(value:string)=>void}){
 const t=(ko:string,en:string)=>locale==='ko'?ko:en;
 const [file,setFile]=useState<File|null>(null),[consent,setConsent]=useState(false),[reading,setReading]=useState(false),[error,setError]=useState('');
 const generation=useRef(0),input=useRef<HTMLInputElement|null>(null);
 useEffect(()=>()=>{generation.current++;},[]);
 async function read(){
  if(disabled||reading)return;
  if(!file){setError(t('읽을 설정 파일을 먼저 선택해 주세요.','Select a configuration file first.'));return;}
  if(!consent)return;
  const stamp=++generation.current;setReading(true);setError('');
  try{const text=await file.text();if(stamp!==generation.current)return;if(!text.trim()||new TextEncoder().encode(text).length>65536)throw new Error();onText(text);}
  catch{if(stamp===generation.current){onText('');setError(t('비어 있거나 읽을 수 없는 설정입니다. UTF-8·64 KiB 제한을 확인하세요.','Empty or unreadable configuration. Check UTF-8 and the 64 KiB limit.'));}}
  finally{if(stamp===generation.current){setReading(false);setConsent(false);}}
 }
 return <Stack gap={1.5}>
  <Alert severity="info">{t('설정 파일을 선택해도 자동으로 읽지 않습니다. 읽기를 허용한 뒤 확인하세요. 진단 시 설정 원문은 서버 메모리에서만 분석하며 결과에는 고정된 관찰값만 저장합니다. 서버·VM·장비에 접속하거나 설정을 변경하지 않습니다.','Selecting does not read a file. Explicitly allow reading. Assessment analyzes the configuration in server memory and saves only fixed observations. No server/VM/device access or setting changes.')}</Alert>
  <Button component="label" variant="outlined" disabled={disabled||reading}>{t('설정 파일 선택 · 최대 64 KiB','Choose configuration · up to 64 KiB')}<input ref={input} type="file" hidden disabled={disabled||reading} accept={kind==='virtualization.vmx'?'.vmx':'.gns3,.json'} onChange={e=>{generation.current++;setConsent(false);setReading(false);setError('');onText('');const selected=e.target.files?.[0]??null;if(selected&&(selected.size>65536||selected.size===0)){setFile(null);setError(t('내용이 있는 64 KiB 이하 파일을 선택하세요.','Choose a nonempty file up to 64 KiB.'));}else setFile(selected);}}/></Button>
  <Typography variant="body2">{file?file.name:t('선택된 파일 없음','No file selected')}</Typography>
  <FormControlLabel label={t('현재 설정 파일을 이 검사에 한해 읽도록 허용합니다.','Allow reading this configuration for this inspection.')} control={<Checkbox checked={consent} disabled={!file||disabled||reading} onChange={e=>setConsent(e.target.checked)}/>}/>
  <Button disabled={disabled||reading||!!file&&!consent} onClick={()=>void read()}>{reading?t('설정 읽는 중','Reading configuration'):t('허용한 설정 읽기','Read permitted configuration')}</Button>
  {error&&<Alert severity="warning">{error}</Alert>}
  <TextField label={kind==='virtualization.vmx'?t('VMware VMX 설정 · 직접 입력 가능','VMware VMX · paste supported'):t('GNS3 2.x 프로젝트 JSON · 직접 입력 가능','GNS3 2.x project JSON · paste supported')} value={value} multiline minRows={6} maxRows={16} disabled={disabled||reading} onChange={e=>{generation.current++;setFile(null);setConsent(false);if(input.current)input.current.value='';onText(e.target.value);}} helperText={t('최대 64 KiB. 실제 실행·취약점 스캔이 아닌 제공된 설정의 정적 점검입니다.','Up to 64 KiB. Static review of supplied configuration; no execution or vulnerability scan.')}/>
 </Stack>;
}
