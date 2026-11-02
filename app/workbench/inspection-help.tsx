'use client';
import {useId,useState} from 'react';
import {Alert,Box,Button,Dialog,DialogActions,DialogContent,DialogTitle,Typography} from '@mui/material';
/** InspectionHelp: 검사 순서와 현재 빠진 조건을 입력 변경 없이 모달로 설명합니다. */
export default function InspectionHelp({locale,steps,blockers,label}:{locale:'ko'|'en',steps:readonly string[],blockers?:readonly string[],label?:string}){
 const [open,setOpen]=useState(false),title=useId(),ko=locale==='ko';
 return <>
  <Button type="button" size="small" aria-haspopup="dialog" onClick={/** onClick 콜백: 현재 입력을 유지하고 도움말을 엽니다. */ ()=>setOpen(true)}>{label??(ko?'검사 순서·진행 도움말':'Inspection steps and help')}</Button>
  <Dialog open={open} onClose={/** onClose 콜백: Escape 또는 배경 클릭으로 도움말을 닫습니다. */ ()=>setOpen(false)} aria-labelledby={title} fullWidth maxWidth="sm">
   <DialogTitle id={title}>{ko?'검사 진행 도움말':'Inspection help'}</DialogTitle>
   <DialogContent dividers>
    {blockers!==undefined&&<><Typography fontWeight={700} sx={{mb:1}}>{ko?'지금 확인할 내용':'What to check now'}</Typography>
     {blockers.length?<Alert severity="info"><Box component="ul" sx={{m:0,pl:2}}>{blockers.map(/** map 콜백: 충족하지 않은 입력·동의 조건을 표시합니다. */ (reason,index)=><li key={index}>{reason}</li>)}</Box></Alert>:<Alert severity="success">{ko?'입력과 동의가 준비됐습니다. 도움말을 닫고 검사·저장 버튼을 눌러 주세요.':'Input and consent are ready. Close help and use the inspect/save button.'}</Alert>}</>}
    <Typography fontWeight={700} sx={{mt:2,mb:1}}>{ko?'이 순서대로 진행하세요':'Follow these steps'}</Typography>
    <Box component="ol" sx={{pl:3,'& li':{mb:1}}}>{steps.map(/** map 콜백: 선택한 검사의 순서를 표시합니다. */ (step,index)=><li key={index}>{step}</li>)}</Box>
    <Typography variant="body2" color="text.secondary">{ko?'도움말을 열거나 닫아도 파일·검사 결과·입력은 유지됩니다. 동의는 자동으로 체크하지 않습니다.':'Opening or closing help preserves input and inspection results. Consent is never selected automatically.'}</Typography>
   </DialogContent>
   <DialogActions><Button type="button" onClick={/** onClick 콜백: 도움말을 닫고 입력 화면으로 돌아갑니다. */ ()=>setOpen(false)}>{ko?'닫기':'Close'}</Button></DialogActions>
  </Dialog>
 </>;
}
