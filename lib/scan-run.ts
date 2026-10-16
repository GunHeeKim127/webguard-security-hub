import type {CheckResult} from './inspection';
export const stages=['target','network','headers','store'] as const;
export type Stage=typeof stages[number];
export type Progress={type:'progress',stage:Stage,state:'running'|'success',at:string};
export type ScanEvent=Progress|{type:'result',id:string,result:CheckResult,at:string}|{type:'error',errorCode:string,at:string};
export type ScanLog={stage:Stage,state:'running'|'success'|'error',at:string,errorCode?:string};
export function appendLog(logs:ScanLog[],event:ScanEvent):ScanLog[]{
 if(event.type==='result')return logs;
 if(event.type==='progress')return [...logs,{stage:event.stage,state:event.state,at:event.at}].slice(-40);
 const stage=[...logs].reverse().find(log=>log.state==='running')?.stage??'target';
 return [...logs,{stage,state:'error' as const,at:event.at,errorCode:event.errorCode}].slice(-40);
}
// Chunks may split a line or a multibyte character. Never treat transport EOF as success.
export async function readScanStream(stream:ReadableStream<Uint8Array>,receive:(event:ScanEvent)=>void){
 const reader=stream.getReader(),decoder=new TextDecoder();let buffer='',terminal=false;
 function line(raw:string){if(!raw.trim())return;if(terminal)throw new Error('Unexpected trailing event');const event=JSON.parse(raw) as ScanEvent;
  if(!event||!['progress','result','error'].includes(event.type)||typeof event.at!=='string')throw new Error('Invalid scan event');
  if(event.type==='progress'&&(!stages.includes(event.stage)||!['running','success'].includes(event.state)))throw new Error('Invalid progress');
  if(event.type==='result'&&(typeof event.id!=='string'||!event.result||!Number.isInteger(event.result.status)||!Array.isArray(event.result.checks)))throw new Error('Invalid result');
  if(event.type==='error'&&typeof event.errorCode!=='string')throw new Error('Invalid error');
  terminal=event.type!=='progress';receive(event);
 }
 try{while(true){const {value,done}=await reader.read();buffer+=decoder.decode(value,{stream:!done});if(buffer.length>65536)throw new Error('Scan stream too large');let split;while((split=buffer.indexOf('\n'))>=0){line(buffer.slice(0,split));buffer=buffer.slice(split+1);}if(done)break;}if(buffer.trim())line(buffer);if(!terminal)throw new Error('Incomplete scan stream');}
 finally{await reader.cancel().catch(()=>{});reader.releaseLock();}
}
export function scanReport(target:string,logs:ScanLog[],inspection:{state:string,recordId?:string,result?:CheckResult}){
 return JSON.stringify({format:'webguard-scan-log-v1',target,exportedAt:new Date().toISOString(),state:inspection.state,recordId:inspection.recordId??null,logs,result:inspection.state==='success'?inspection.result:null},null,2);
}
