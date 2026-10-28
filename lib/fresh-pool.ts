import type {Pool,PoolClient,QueryResultRow} from 'pg';
export const MAX_IDLE_LEASE_MS=5000;
// Timers may not run while a serverless instance is suspended. Check wall time
// before lending an idle socket, independently of pg's idle-timeout callback.
export function freshConnector(pool:Pick<Pool,'connect'|'on'>,now=Date.now){
 const released=new WeakMap<PoolClient,number>();
 pool.on('release',(_error:Error|undefined,client:PoolClient)=>released.set(client,now()));
 return {async connect():Promise<PoolClient>{
  for(let attempt=0;attempt<8;attempt++){
   const client=await pool.connect(),at=released.get(client),idle=at===undefined?0:now()-at;
   if(at!==undefined&&(idle>=MAX_IDLE_LEASE_MS||idle<0)){
    client.release(true);console.info('[WebGuard database lease]',{discardedIdleMs:Math.max(0,idle)});continue;
   }
   return client;
  }
  throw new Error('Database lease refresh limit exceeded');
 }};
}
export async function leaseQuery<R extends QueryResultRow=any>(connector:Pick<Pool,'connect'>,text:string,values?:unknown[]){
 const client=await connector.connect();let failed=false;
 try{return await client.query<R>(text,values);}catch(error){failed=true;throw error;}finally{client.release(failed);}
}
