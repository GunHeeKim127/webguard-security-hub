import {mkdir,writeFile} from 'node:fs/promises';
// Bounded, public GET probes only; no login token or customer data is collected.
const option=/** option: 명시한 관찰 시간·간격을 읽습니다. */ (name:string,fallback:number)=>{const at=process.argv.indexOf(name);return at<0?fallback:Number(process.argv[at+1]);};
const minutes=option('--minutes',2),seconds=option('--interval-seconds',30);
if(!Number.isFinite(minutes)||minutes<1||minutes>1440||!Number.isFinite(seconds)||seconds<30||seconds>900)throw new Error('Use 1–1440 minutes and 30–900 seconds');
const start=Date.now(),until=start+minutes*60000,results:Array<{at:string;health:number|null;ready:number|null;durationMs:number}>=[];
await mkdir('work',{recursive:true});
/** probe: 고정된 운영 상태 URL만 제한 시간 안에 읽고 오류 본문은 수집하지 않습니다. */
async function probe(path:string){try{const response=await fetch('https://webguard-security-hub.vercel.app'+path,{cache:'no-store',signal:AbortSignal.timeout(15000)});await response.body?.cancel();return response.status;}catch{return null;}}
do{
 const began=Date.now(),[health,ready]=await Promise.all([probe('/api/health'),probe('/api/ready')]);results.push({at:new Date().toISOString(),health,ready,durationMs:Date.now()-began});
 const summary={startedAt:new Date(start).toISOString(),observedMinutes:(Date.now()-start)/60000,samples:results.length,failed:results.filter(/** filter: 실패 상태만 집계하며 고객 데이터는 취급하지 않습니다. */ row=>row.health!==200||row.ready!==200).length,scope:'public health/readiness only; not login/save or long-term proof',results};
 await writeFile('work/availability-observation.json',JSON.stringify(summary,null,2));console.log(JSON.stringify(results[results.length-1]));
 if(Date.now()+seconds*1000>=until)break;await new Promise(/** wait: 설정한 관찰 간격을 지킵니다. */ resolve=>setTimeout(resolve,seconds*1000));
}while(Date.now()<until);
console.log(JSON.stringify({complete:true,samples:results.length,allSuccessful:results.every(/** every: 관찰 구간의 상태만 확인합니다. */ row=>row.health===200&&row.ready===200),longTermStabilityProven:false}));
