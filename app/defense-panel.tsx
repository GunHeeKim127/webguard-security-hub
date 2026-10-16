'use client';
import {Alert,Box,Chip,Paper,Stack,Typography} from '@mui/material';
import type {Dashboard} from '../lib/inspection';
import type {Locale} from '../lib/locale';
import {defenseText} from '../lib/defense-copy';
export default function DefensePanel({locale,blocks}:{locale:Locale,blocks:NonNullable<Dashboard['ipBlocks']>}){
 const t=(key:string)=>defenseText(locale,key),active=blocks.filter(b=>b.blacklisted||(b.blocked_until&&Date.parse(b.blocked_until)>Date.now()));
 return <Paper sx={{p:3,mt:3}}><Typography variant="h6">{t('title')}</Typography><Typography variant="body2" color="text.secondary" my={2}>{t('policy')}</Typography>
 {active.length>0&&<Alert severity="warning" sx={{mb:2}}>{t('title')}: {active.length}</Alert>}
 {!blocks.length?<Typography>{t('empty')}</Typography>:<Stack spacing={2}>{blocks.map(block=>{const state=block.blacklisted?'blacklist':block.blocked_until&&Date.parse(block.blocked_until)>Date.now()?'blocked':'released';return <Box key={block.address} sx={{borderTop:'1px solid #29384b',pt:2}}><Stack direction="row" flexWrap="wrap" gap={1}><Typography component="code">{block.address}</Typography><Chip size="small" color={state==='blacklist'?'error':state==='blocked'?'warning':'default'} label={t(state)}/><Chip size="small" label={`${t('strikes')}: ${block.strikes}/6`}/></Stack><Typography variant="body2" mt={1}>{t(block.last_reason)} · {new Date(block.last_seen).toLocaleString(locale)}{state==='blocked'&&block.blocked_until?' → '+new Date(block.blocked_until).toLocaleString(locale):''}</Typography></Box>;})}</Stack>}</Paper>;
}
