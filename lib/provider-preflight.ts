import type {PoolClient,QueryConfig} from 'pg';
import {protectionDbError} from './protection-db-error';
type RecoveryRead={run:()=>Promise<void>;close:()=>Promise<void>};
// A provider-side idle backend can hold even a new client's first reply.
// Keep that read pending while issuing one independent, read-only probe.
// Application SQL has not run yet; no mutation is replayed here.
export async function providerPreflight(client:Pick<PoolClient,'query'>,makeRecovery:()=>RecoveryRead,delayMs=750){
 let recovery:RecoveryRead|undefined,task:Promise<void>|undefined;
 const timer=setTimeout(()=>{
  try{recovery=makeRecovery();console.info('[WebGuard provider preflight]',{recoveryRead:true});task=recovery.run().catch(error=>{console.warn('[WebGuard provider preflight]',{reason:protectionDbError(error).reason});});}
  catch(error){console.warn('[WebGuard provider preflight]',{reason:protectionDbError(error).reason});}
 },delayMs);
 try{await client.query({text:'SELECT 1',query_timeout:5000} as QueryConfig & {query_timeout:number});}
 // Do not end pg.Client during its connect promise: pg does not settle that
 // promise on an intentional early end. The recovery has its own short limits.
 finally{clearTimeout(timer);await task;if(recovery)await recovery.close().catch(()=>{});}
}
