'use client';
import {useState} from 'react';
import {Alert,Box,Button,Chip,Paper,Stack,Typography} from '@mui/material';
import type {Dashboard} from '../lib/inspection';
import type {Locale} from '../lib/locale';
import {defenseText} from '../lib/defense-copy';
import {protectedRequest} from '../lib/protected-request';
export default function DefensePanel({locale,blocks,accounts,onReleased}:{locale:Locale,blocks:NonNullable<Dashboard['ipBlocks']>,accounts:NonNullable<Dashboard['accountBlocks']>,onReleased:()=>void}){
 const [pending,setPending]=useState(''),[message,setMessage]=useState('');
 async function release(blockId:string){if(pending)return;setPending(blockId);setMessage('');try{
  const response=await protectedRequest('/api/admin/ip-blocks',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'release',blockId})});
  if(!response.ok)throw new Error();setMessage('release_done');onReleased();
 }catch{setMessage('release_failed');}finally{setPending('');}}
 async function releaseAccount(blockId:string){if(pending)return;setPending('account:'+blockId);setMessage('');try{
  const response=await protectedRequest('/api/admin/account-blocks',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'release',blockId})});
  if(!response.ok)throw new Error();setMessage('release_done');onReleased();
 }catch{setMessage('release_failed');}finally{setPending('');}}
 const t=(key:string)=>defenseText(locale,key),active=blocks.filter(b=>b.blacklisted||(b.blocked_until&&Date.parse(b.blocked_until)>Date.now()));
 return <><Paper sx={{p:3,mt:3}}><Typography variant="h6">{t('title')}</Typography><Typography variant="body2" color="text.secondary" my={2}>{t('policy')}</Typography>
 <Alert severity="info" sx={{mb:2}}>{t('masked_notice')}</Alert>
 {active.length>0&&<Alert severity="warning" sx={{mb:2}}>{t('title')}: {active.length}</Alert>}
 {message&&<Alert severity={message==='release_done'?'success':'warning'} sx={{mb:2}}>{t(message)}</Alert>}
 {!blocks.length?<Typography>{t('empty')}</Typography>:<Stack spacing={2}>{blocks.map(block=>{const state=block.blacklisted?'blacklist':block.blocked_until&&Date.parse(block.blocked_until)>Date.now()?'blocked':'released';return <Box key={block.blockId} sx={{borderTop:'1px solid #29384b',pt:2}}><Stack direction="row" flexWrap="wrap" gap={1}><Typography component="code">{block.address} · #{block.blockId.slice(0,8)}</Typography><Chip size="small" color={state==='blacklist'?'error':state==='blocked'?'warning':'default'} label={t(state)}/><Chip size="small" label={`${t('strikes')}: ${block.strikes}/6`}/></Stack><Typography variant="body2" mt={1}>{t(block.last_reason)} · {new Date(block.last_seen).toLocaleString(locale)}{state==='blocked'&&block.blocked_until?' → '+new Date(block.blocked_until).toLocaleString(locale):''}</Typography><Button sx={{mt:1}} variant="outlined" disabled={!!pending} onClick={()=>void release(block.blockId)}>{t(pending===block.blockId?'releasing':'release')}</Button></Box>;})}</Stack>}</Paper><Paper sx={{p:3,mt:3}}><Typography variant="h6">{t('account_title')}</Typography><Alert severity="info" sx={{my:2}}>{t('account_policy')}</Alert>{!accounts.length?<Typography>{t('account_empty')}</Typography>:<Stack gap={2}>{accounts.map(account=><Box key={account.blockId}><Typography sx={{overflowWrap:'anywhere'}}>{account.email} · #{account.blockId.slice(0,8)}</Typography><Chip size="small" color={account.blacklisted?'error':'warning'} label={account.blacklisted?t('blacklist'):t('strikes')+': '+account.strikes+'/6'}/><Typography variant="body2">{t(account.last_reason)} · {new Date(account.last_seen).toLocaleString(locale)}</Typography><Button disabled={!!pending} onClick={()=>void releaseAccount(account.blockId)}>{t(pending==='account:'+account.blockId?'releasing':'account_release')}</Button></Box>)}</Stack>}</Paper></>;
}
