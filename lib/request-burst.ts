import {createHash} from 'node:crypto';
/** createRequestBurstLimiter: DB 접근 전 단일 서버 인스턴스의 요청 급증을 제한하며 메모리를 고정 상한으로 유지합니다. */
export function createRequestBurstLimiter(limit=600,windowMs=60000,maxKeys=4096,clock:()=>number=Date.now){
 if(!Number.isInteger(limit)||limit<1||!Number.isInteger(windowMs)||windowMs<1||!Number.isInteger(maxKeys)||maxKeys<1)throw Error('Invalid burst limits');
 const buckets=new Map<string,{count:number,expires:number}>();let nextSweep=0;
 return /** checkBurst: 정규화된 접속 주소의 임시 요청 예산을 검사하며 원본 주소는 보관하지 않습니다. */ (address:string)=>{
  const now=clock(),key=createHash('sha256').update(address).digest('hex');let bucket=buckets.get(key);
  if(bucket&&now>=bucket.expires){buckets.delete(key);bucket=undefined;}
  if(!bucket){
   if(buckets.size>=maxKeys&&now>=nextSweep){nextSweep=now+1000;for(const [id,value] of buckets)if(now>=value.expires)buckets.delete(id);}
   if(buckets.size>=maxKeys)return {retryAfter:1};
   bucket={count:0,expires:now+windowMs};buckets.set(key,bucket);
  }
  if(bucket.count>=limit)return {retryAfter:Math.max(1,Math.ceil((bucket.expires-now)/1000))};
  bucket.count++;return null;
 };
}
// This is a per-instance supplement, not a distributed WAF or persistent blacklist.
export const requestBurst=createRequestBurstLimiter();
