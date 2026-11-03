'use client';
import Link from '../navigation-link';
import {useState} from 'react';
import {ThemeProvider,createTheme,CssBaseline,Container,Paper,Typography,Stack,TextField,Button,Alert,Box,InputAdornment,IconButton} from '@mui/material';
import type {Locale} from '../../lib/locale';
import {messages} from '../../lib/messages';
import {registrationCopy} from '../../lib/registration-copy';
import {registrationInput} from '../../lib/registration';
import {errorText} from '../../lib/errors-i18n';
const theme=createTheme({palette:{mode:'dark',primary:{main:'#66e6c3'},background:{default:'#091321',paper:'#111f31'}},shape:{borderRadius:14}});
/** PasswordVisibility: 입력값을 변경하거나 폼을 제출하지 않고 비밀번호 표시 상태만 전환합니다. */
function PasswordVisibility({visible,toggle,label,disabled}:{visible:boolean,toggle:()=>void,label:string,disabled:boolean}){
 return <InputAdornment position="end"><IconButton type="button" aria-label={label} aria-pressed={visible} disabled={disabled} edge="end" onMouseDown={/** onMouseDown: 눈 버튼을 눌러도 입력 포커스를 유지합니다. */ e=>e.preventDefault()} onClick={toggle}><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" aria-hidden="true"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12Z"/><circle cx="12" cy="12" r="3"/>{!visible&&<path d="m3 3 18 18"/>}</svg></IconButton></InputAdornment>;
}
/** Signup: 회원가입 입력과 요청 상태를 관리합니다 주요 호출: useState. */ export default function Signup({locale}:{locale:Locale}){
 const t=registrationCopy[locale],ui=messages[locale];const [busy,setBusy]=useState(false),[done,setDone]=useState(false),[error,setError]=useState('');
 const [passwordVisible,setPasswordVisible]=useState(false),[confirmVisible,setConfirmVisible]=useState(false);
 const visibilityCopy=locale==='ko'?['보기','숨기기']:locale==='ja'?['表示','非表示']:['Show','Hide'];
 return <ThemeProvider theme={theme}><CssBaseline/><Container maxWidth="sm" sx={{py:5}}><Typography color="primary" variant="h6" mb={3}>◈ WEBGUARD</Typography><Paper sx={{p:{xs:3,sm:4}}}>
  <Typography variant="h4" fontWeight={800} mb={2}>{t.title}</Typography><Typography color="text.secondary" mb={3}>{t.intro}</Typography>
  {error&&<Alert severity="warning" role="alert" sx={{mb:2}}>{error}</Alert>}
  {done?<Alert severity="success" role="status">{t.done}</Alert>:<Box component="form" noValidate onSubmit={/** onSubmit 콜백: onSubmit 이벤트의 입력·상태 처리를 실행합니다 주요 호출: preventDefault·setError·String. */ async e=>{
   e.preventDefault();if(busy)return;setPasswordVisible(false);setConfirmVisible(false);setError('');const form=e.currentTarget,fields=new FormData(form),email=String(fields.get('email')??''),password=String(fields.get('password')??'');
   if(!registrationInput({email,password})){setError(t.validation);return;}if(password!==fields.get('confirm')){setError(t.mismatch);return;}
   setBusy(true);try{const response=await fetch('/api/register',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email,password})});const json=await response.json();if(!response.ok){setError(errorText(locale,json.errorCode));return;}form.reset();setDone(true);}catch{setError(ui.networkError);}finally{setBusy(false);}
  }}><Stack spacing={2}>
   <TextField name="email" label={ui.email} type="email" autoComplete="username" required inputProps={{maxLength:254}} disabled={busy}/>
   <TextField name="password" label={ui.password} type={passwordVisible?'text':'password'} autoComplete="new-password" required helperText={t.rule} slotProps={{htmlInput:{minLength:14,maxLength:128},input:{endAdornment:<PasswordVisibility visible={passwordVisible} disabled={busy} label={`${ui.password} ${visibilityCopy[passwordVisible?1:0]}`} toggle={/** toggle: 새 비밀번호의 표시 상태를 전환합니다. */ ()=>setPasswordVisible(!passwordVisible)}/>}}} disabled={busy}/>
   <TextField name="confirm" label={t.confirm} type={confirmVisible?'text':'password'} autoComplete="new-password" required slotProps={{htmlInput:{maxLength:128},input:{endAdornment:<PasswordVisibility visible={confirmVisible} disabled={busy} label={`${t.confirm} ${visibilityCopy[confirmVisible?1:0]}`} toggle={/** toggle: 확인 비밀번호의 표시 상태를 독립적으로 전환합니다. */ ()=>setConfirmVisible(!confirmVisible)}/>}}} disabled={busy}/>
   <Button type="submit" variant="contained" disabled={busy}>{busy?ui.loading:t.submit}</Button>
  </Stack></Box>}
  <Button component={Link} href="/" sx={{mt:2}}>{t.back}</Button><Typography variant="caption" color="text.secondary" display="block" mt={2}>{t.limitation}</Typography>
 </Paper></Container></ThemeProvider>;
}
