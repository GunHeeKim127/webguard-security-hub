'use client';
import {useState} from 'react';
import {ThemeProvider,createTheme,CssBaseline,Container,Paper,Typography,Stack,TextField,Button,Alert,Box} from '@mui/material';
import type {Locale} from '../../lib/locale';
import {messages} from '../../lib/messages';
import {registrationCopy} from '../../lib/registration-copy';
import {registrationInput} from '../../lib/registration';
import {errorText} from '../../lib/errors-i18n';
const theme=createTheme({palette:{mode:'dark',primary:{main:'#66e6c3'},background:{default:'#091321',paper:'#111f31'}},shape:{borderRadius:14}});
export default function Signup({locale}:{locale:Locale}){
 const t=registrationCopy[locale],ui=messages[locale];const [busy,setBusy]=useState(false),[done,setDone]=useState(false),[error,setError]=useState('');
 return <ThemeProvider theme={theme}><CssBaseline/><Container maxWidth="sm" sx={{py:5}}><Typography color="primary" variant="h6" mb={3}>◈ WEBGUARD</Typography><Paper sx={{p:{xs:3,sm:4}}}>
  <Typography variant="h4" fontWeight={800} mb={2}>{t.title}</Typography><Typography color="text.secondary" mb={3}>{t.intro}</Typography>
  {error&&<Alert severity="warning" role="alert" sx={{mb:2}}>{error}</Alert>}
  {done?<Alert severity="success" role="status">{t.done}</Alert>:<Box component="form" noValidate onSubmit={async e=>{
   e.preventDefault();if(busy)return;setError('');const form=e.currentTarget,fields=new FormData(form),email=String(fields.get('email')??''),password=String(fields.get('password')??'');
   if(!registrationInput({email,password})){setError(t.validation);return;}if(password!==fields.get('confirm')){setError(t.mismatch);return;}
   setBusy(true);try{const response=await fetch('/api/register',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email,password})});const json=await response.json();if(!response.ok){setError(errorText(locale,json.errorCode));return;}form.reset();setDone(true);}catch{setError(ui.networkError);}finally{setBusy(false);}
  }}><Stack spacing={2}>
   <TextField name="email" label={ui.email} type="email" autoComplete="username" required inputProps={{maxLength:254}} disabled={busy}/>
   <TextField name="password" label={ui.password} type="password" autoComplete="new-password" required helperText={t.rule} inputProps={{minLength:14,maxLength:128}} disabled={busy}/>
   <TextField name="confirm" label={t.confirm} type="password" autoComplete="new-password" required inputProps={{maxLength:128}} disabled={busy}/>
   <Button type="submit" variant="contained" disabled={busy}>{busy?ui.loading:t.submit}</Button>
  </Stack></Box>}
  <Button href="/" sx={{mt:2}}>{t.back}</Button><Typography variant="caption" color="text.secondary" display="block" mt={2}>{t.limitation}</Typography>
 </Paper></Container></ThemeProvider>;
}
