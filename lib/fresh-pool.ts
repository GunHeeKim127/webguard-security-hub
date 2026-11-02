import type {Pool,PoolClient,QueryResultRow} from 'pg';
export const MAX_IDLE_LEASE_MS=5000;
// Timers may not run while a serverless instance is suspended. Check wall time
// before lending an idle socket, independently of pg's idle-timeout callback.
/** freshConnector: 오래된 연결을 재사용하지 않도록 연결 수명 상태를 관리합니다 주요 호출: on. */ export function freshConnector(pool:Pick<Pool,'connect'|'on'>,now=Date.now){
 const released=new WeakMap<PoolClient,number>();
 pool.on('release',/** on 콜백: on에서 전달한 값을 처리하는 콜백입니다 주요 호출: set·now. */ (_error:Error|undefined,client:PoolClient)=>released.set(client,now()));
 return {/** connect: 새 연결을 만들고 재사용 상태를 갱신합니다 주요 호출: connect·get·now. */ async connect():Promise<PoolClient>{
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
/** leaseQuery: 유효한 연결을 얻어 쿼리를 실행합니다 주요 호출: connect·query·release. */ export async function leaseQuery<R extends QueryResultRow=any>(connector:Pick<Pool,'connect'>,text:string,values?:unknown[]){
 const client=await connector.connect();let failed=false;
 try{return await client.query<R>(text,values);}catch(error){failed=true;throw error;}finally{client.release(failed);}
}
