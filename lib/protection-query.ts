import type {Pool,PoolClient,QueryConfig} from 'pg';
import {ACTIVE_BLOCK_SQL} from './ingress-guard';
import {protectionDbError} from './protection-db-error';

// A managed pool can accept a connection before its upstream is ready. Give
// this one indexed, read-only lookup room to finish instead of discarding it
// at the general 5s query limit and immediately starting the same work again.
export const PROTECTION_READ_TIMEOUT_MS=10000;
export async function protectionQuery(pool:Pick<Pool,'connect'>,text:string,values:unknown[],managed:boolean){
 const started=performance.now();
 let phase='acquire';
 let client:PoolClient|undefined;
 let failed=false;
 try{
  client=await pool.connect();
  const acquired=performance.now();phase=text===ACTIVE_BLOCK_SQL?'block_read':'threat_write';
  const config:QueryConfig & {query_timeout?:number}={text,values};
  if(managed&&text===ACTIVE_BLOCK_SQL)config.query_timeout=PROTECTION_READ_TIMEOUT_MS;
  const result=await client.query(config);
  const finished=performance.now();
  if(finished-started>=1000)console.info('[WebGuard protection database]',{phase,acquireMs:Math.round(acquired-started),queryMs:Math.round(finished-acquired)});
  return result;
 }catch(error){
  failed=true;
  console.warn('[WebGuard protection database]',{phase,reason:protectionDbError(error).reason,elapsedMs:Math.round(performance.now()-started)});
  throw error;
 }finally{
  // Like pg.Pool.query, discard an errored/timed-out client. Never return a
  // connection with an in-flight query to the pool or replay a write here.
  client?.release(failed);
 }
}
