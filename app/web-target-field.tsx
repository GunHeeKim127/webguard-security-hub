'use client';
import {useId,useState} from 'react';
import {Box,Button,Dialog,DialogActions,DialogContent,DialogContentText,DialogTitle,TextField,Typography} from '@mui/material';
import {webTargetInput,webTargetReason} from '../lib/web-target-input';
/** WebTargetField: 도메인 범위 안내와 상세 주소 수정 모달을 두 웹 입력 화면에 동일하게 제공합니다. */
export default function WebTargetField({value,onChange,disabled,locale}:{value:string,onChange:(value:string)=>void,disabled?:boolean,locale:string}){
 const [open,setOpen]=useState(false),[warned,setWarned]=useState(''),title=useId(),description=useId(),ko=locale==='ko',target=webTargetInput(value);
 const issue=target.issue??'empty';
 return <Box>
  <TextField name="url" fullWidth required type="text" slotProps={{htmlInput:{inputMode:'url',autoCapitalize:'none',autoCorrect:'off',spellCheck:false}}} value={value} disabled={disabled} label={ko?'검사할 도메인 · 도메인만 허용':'Domain to inspect · domains only'} placeholder="https://example.com" helperText={target.issue&&value.trim()?webTargetReason(target.issue,locale):ko?'도메인만 허용합니다. 예: example.com 또는 https://example.com · 상세 페이지는 지원하지 않습니다.':'Domains only: example.com or https://example.com. Detailed pages are not supported.'} error={!!value.trim()&&!!target.issue} onChange={/** onChange: 새 입력의 안내 상태를 초기화하고 주소만 전달합니다. */ e=>{setWarned('');onChange(e.target.value);}} onBlur={/** onBlur: 잘못된 주소 입력을 마치면 같은 입력에 한 번만 원인과 해결책을 엽니다. */ ()=>{if(value.trim()&&target.issue&&warned!==value){setWarned(value);setOpen(true);}}}/>
  <Button type="button" size="small" disabled={disabled} aria-haspopup="dialog" onClick={/** onClick: 주소 입력 문제와 지원 범위를 설명합니다. */ ()=>setOpen(true)}>{ko?'주소 입력 도움말':'Address help'}</Button>
  <Dialog open={open} fullWidth maxWidth="sm" aria-labelledby={title} aria-describedby={description} onClose={/** onClose: 주소를 유지하며 도움말을 닫습니다. */ ()=>setOpen(false)}>
   <DialogTitle id={title}>{issue==='detail'?(ko?'도메인까지만 지원합니다':'Only the domain is supported'):(ko?'주소 입력 안내':'Address guidance')}</DialogTitle>
   <DialogContent dividers><DialogContentText id={description}>{target.issue?webTargetReason(target.issue,locale):ko?'현재 주소는 지원하는 도메인 형식입니다. 소유·점검 허가를 확인한 뒤 검사하세요.':'This address has a supported domain format. Confirm permission before inspection.'}</DialogContentText>
    <Typography fontWeight={700} sx={{mt:2}}>{ko?'해결 방법':'What to do'}</Typography>
    <Typography sx={{mt:1,overflowWrap:'anywhere'}}>{target.domain??'https://example.com'}</Typography>
    <Typography variant="body2" color="text.secondary" sx={{mt:1}}>{ko?'도메인 주소로 수정하고 소유·점검 허가를 다시 확인하세요. 주소는 자동으로 변경하거나 전송하지 않습니다.':'Use the domain address and confirm permission again. Your address is never changed or submitted automatically.'}</Typography>
   </DialogContent>
   <DialogActions><Button type="button" onClick={/** onClick: 기존 입력을 유지하고 닫습니다. */ ()=>setOpen(false)}>{ko?'닫기':'Close'}</Button>{target.domain&&<Button type="button" variant="contained" onClick={/** onClick: 사용자가 선택한 경우에만 상세 경로를 제외한 도메인으로 바꿉니다. */ ()=>{onChange(target.domain!);setOpen(false);}}>{ko?'도메인 주소로 바꾸기':'Use domain address'}</Button>}</DialogActions>
  </Dialog>
 </Box>;
}
