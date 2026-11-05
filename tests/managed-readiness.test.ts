import test from 'node:test';
import assert from 'node:assert/strict';
import {managedReadinessQuery} from '../lib/managed-readiness';
const connection='postgresql://test-user:test-key@pooled.db.prisma.io/postgres';
/** response: 최소 제공자 NDJSON 프레임을 만들어 실제 파서 경계를 시험합니다. */
function response(frames:unknown[]){return new Response(frames.map(/** map: 각 프레임을 별도 줄로 직렬화합니다. */ value=>JSON.stringify(value)).join('\n'),{headers:{'Content-Type':'application/x-ndjson'}});}
const valid=[{columns:[{name:'ready',typeOid:16},{name:'count',typeOid:20}]},{values:['t','9007199254740993']},{complete:true}];
test('managed readiness sends bounded buffered SELECT to the fixed HTTPS endpoint',/** test: HTTPS 목적지·리다이렉트 금지·문장 전송과 PostgreSQL 타입 계약을 대조합니다. */ async()=>{
 let calls=0;
 const result=await managedReadinessQuery(connection,'SELECT true AS ready',undefined,/** send: 실제 전송될 요청의 보안 경계를 검사합니다. */ async(url,init)=>{
  calls++;assert.equal(String(url),'https://db.prisma.io/v0/statement?db=postgres');assert.equal(init?.redirect,'error');assert.equal(init?.cache,'no-store');assert.equal(typeof init?.body,'string');assert.match(String(init?.body),/SELECT true AS ready/);assert.equal(init?.method,'POST');return response(valid);
 });assert.equal(calls,1);assert.deepEqual(result.rows,[{ready:true,count:'9007199254740993'}]);
});
test('managed readiness rejects writes and alternative credential destinations before fetch',/** test: 준비 경로의 쓰기·공격자 호스트를 전송 전에 거절합니다. */ async()=>{
 let calls=0;const send:typeof fetch=/** send: 호출되지 않아야 하는 전송입니다. */ async()=>{calls++;return response(valid);};
 await assert.rejects(managedReadinessQuery(connection,'SELECT public.archive_diagnostics_30d()',undefined,send));
 await assert.rejects(managedReadinessQuery(connection.replace('pooled.db.prisma.io','attacker.invalid'),'SELECT 1',undefined,send));assert.equal(calls,0);
});
test('managed readiness preserves permission failures without provider text',/** test: 실제 SQLSTATE를 유지하며 제공자 비밀 오류 원문은 버립니다. */ async()=>{
 for(const send of [/** send: 서버 권한 오류 프레임을 재현합니다. */ async()=>response([{error:{code:'42501',message:'private-key-text'}}]),/** send: HTTP 인증 거절을 재현합니다. */ async()=>new Response('private-key-text',{status:403})]){
  await assert.rejects(managedReadinessQuery(connection,'SELECT 1',undefined,send),/** rejects: 재시도 불가 권한 코드와 원문 비노출을 대조합니다. */ (error:unknown)=>{assert.equal((error as {code:string}).code,'42501');assert(!String(error).includes('private-key-text'));return true;});
 }
});
test('managed readiness requires a complete bounded protocol result',/** test: 완료 누락·행 길이 불일치·과도한 응답을 성공으로 간주하지 않습니다. */ async()=>{
 for(const frames of [valid.slice(0,2),[valid[0],{values:['t']},{complete:true}],[{unexpected:true}],[{columns:[{name:'x',typeOid:25}]},{values:['x'.repeat(262144)]},{complete:true}]]){
  await assert.rejects(managedReadinessQuery(connection,'SELECT 1',undefined,/** send: 손상되거나 한도를 넘는 제공자 응답을 전달합니다. */ async()=>response(frames)));
 }
});
test('managed readiness aborts stalled response headers instead of leaving background work',/** test: 시간초과 시 전송 신호가 실제로 취소되는지 확인합니다. */ async()=>{
 let aborted=false;
 const send:typeof fetch=/** send: 응답 헤더가 오지 않는 연결을 재현합니다. */ async(_url,init)=>new Promise<Response>(/** promise: 취소 이벤트가 있어야만 정리됩니다. */ (_resolve,reject)=>{
  init!.signal!.addEventListener('abort',/** abort: 실제 요청 취소를 기록합니다. */ ()=>{aborted=true;reject(new Error('aborted'));},{once:true});
 });
 await assert.rejects(managedReadinessQuery(connection,'SELECT 1',undefined,send,20),/Query read timeout/);assert.equal(aborted,true);
});
test('managed readiness aborts stalled body and releases the reader',/** test: 헤더 뒤 본문 정체도 동일한 수명 안에서 종료합니다. */ async()=>{
 let cancelled=false;
 const send:typeof fetch=/** send: 끝나지 않는 응답 스트림을 재현합니다. */ async(_url,init)=>new Response(new ReadableStream<Uint8Array>({
  start:/** start: 실제 fetch처럼 신호 취소를 본문 오류에 연결합니다. */ controller=>{init!.signal!.addEventListener('abort',/** abort: 대기 중인 본문 읽기를 종료합니다. */ ()=>{cancelled=true;controller.error(new Error('aborted'));},{once:true});},
 }),{headers:{'Content-Type':'application/x-ndjson'}});
 await assert.rejects(managedReadinessQuery(connection,'SELECT 1',undefined,send,20),/Query read timeout/);assert.equal(cancelled,true);
});
test('managed readiness respects the overall caller deadline',/** test: 개별 쿼리 제한보다 앞선 전체 준비 검사 취소를 전달합니다. */ async()=>{
 const controller=new AbortController();controller.abort();let signalled=false;
 await assert.rejects(managedReadinessQuery(connection,'SELECT 1',controller.signal,/** send: 이미 취소된 전체 수명을 전송 전에 확인합니다. */ async(_url,init)=>{signalled=init!.signal!.aborted;throw new Error('aborted');}));assert.equal(signalled,true);
});

test('slow managed readiness uses one fixed recovery read and never replays the original SQL',/** test: 느린 조회에만 고정 연결 확인 한 번을 보내며 원래 문장을 중복 실행하지 않습니다. */ async()=>{
 const {managedReadiness}=await import('../lib/managed-readiness');const calls:string[]=[];let release!:(response:Response)=>void;
 const result=await managedReadiness(connection,'SELECT true AS ready',undefined,/** send: 두 번째 고정 요청이 들어와야 첫 요청이 완료되는 정체를 재현합니다. */ async(_url,init)=>{
  const body=String(init?.body);calls.push(body);
  if(body.includes('webguard_read_probe')){release(response(valid));return response([{columns:[{name:'probe',typeOid:23}]},{values:['1']},{complete:true}]);}
  return new Promise<Response>(/** promise: 원래 읽기 결과를 독립적으로 보존합니다. */ resolve=>{release=resolve;});
 },10,200);
 assert.equal(result.rows[0].ready,true);assert.equal(calls.length,2);assert.equal(calls.filter(/** filter: 원래 SQL의 전송 횟수를 셉니다. */ body=>body.includes('SELECT true AS ready')).length,1);
});
test('managed readiness cancels and joins a pending recovery before returning',/** test: 원래 조회 완료 뒤 연결 확인이 백그라운드에 남지 않도록 합니다. */ async()=>{
 const {managedReadiness}=await import('../lib/managed-readiness');let aborted=false;
 await managedReadiness(connection,'SELECT true AS ready',undefined,/** send: 원래 조회보다 늦게 끝나는 연결 확인을 재현합니다. */ async(_url,init)=>{
  if(String(init?.body).includes('webguard_read_probe'))return new Promise<Response>(/** promise: 명시적 취소가 와야 종료합니다. */ (_resolve,reject)=>{init!.signal!.addEventListener('abort',/** abort: 연결 확인이 실제 취소된 것을 기록합니다. */ ()=>{aborted=true;reject(new Error('aborted'));},{once:true});});
  await new Promise(/** wait: 원래 읽기는 고정된 짧은 지연 후 완료합니다. */ resolve=>setTimeout(resolve,40));return response(valid);
 },5,200);assert.equal(aborted,true);
});

test('managed block lookup binds an address and still rejects the recovered blacklist',/** test: 실제 전송 프레임과 접속 차단 결과를 함께 대조합니다. */ async()=>{
 const {managedBlockRead}=await import('../lib/managed-readiness');const {vercelProtection}=await import('../lib/vercel-protection');const {ACTIVE_BLOCK_SQL}=await import('../lib/ingress-guard');let calls=0;
 const send:typeof fetch=/** send: 주소가 SQL 문자열에 합쳐지지 않고 매개변수로 전송되는지 확인합니다. */ async(_url,init)=>{
  calls++;const body=String(init?.body),descriptor=JSON.parse(body.slice(body.indexOf('{'),body.lastIndexOf('}')+1));assert.equal(descriptor.query,ACTIVE_BLOCK_SQL);assert.deepEqual(descriptor.parameters,[{type:'text',value:'203.0.113.2'}]);
  return response([{columns:[{name:'blacklisted',typeOid:16},{name:'strikes',typeOid:23},{name:'retry_after',typeOid:23}]},{values:['t','6','0']},{complete:true}]);
 };
 const rejected=await vercelProtection(new Request('https://owned.example/workbench',{headers:{'x-real-ip':'203.0.113.2'}}),/** query: 정확한 차단 조회만 새 전송에 연결합니다. */ (sql,values)=>managedBlockRead(connection,sql,values,send),{VERCEL:'1'});
 assert.equal(rejected?.status,403);assert.equal((await rejected!.json()).errorCode,'IP_BLACKLISTED');assert.equal(calls,1);
});
test('managed block lookup never accepts threat writes or unnormalized addresses',/** test: 고정 읽기 경로에 쓰기·변형 주소를 전달하지 않습니다. */ async()=>{
 const {managedBlockRead}=await import('../lib/managed-readiness');const {ACTIVE_BLOCK_SQL}=await import('../lib/ingress-guard');let calls=0;
 const send:typeof fetch=/** send: 금지된 입력이면 실행되지 않아야 합니다. */ async()=>{calls++;return response(valid);};
 for(const [sql,values] of [['UPDATE ip_blocks SET strikes=0',[]],[ACTIVE_BLOCK_SQL,['attacker.invalid']],[ACTIVE_BLOCK_SQL,["203.0.113.2'); SELECT 1"]],[ACTIVE_BLOCK_SQL,[]]] as [string,unknown[]][]){await assert.rejects(managedBlockRead(connection,sql,values,send));}assert.equal(calls,0);
});
