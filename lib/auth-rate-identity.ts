import {createHash,createHmac,timingSafeEqual} from 'node:crypto';
import {normalizeIp} from './ingress-guard';
import {vercelClientAddress} from './vercel-protection';
const addressHeader='x-webguard-auth-peer',signatureHeader='x-webguard-auth-signature';
const signature=/** signature: 인증 출처 식별에 사용할 서명 값을 계산합니다 주요 호출: digest·update·createHmac. */ (address:string,secret:string)=>createHmac('sha256',secret).update('webguard-auth-client-v1\0'+address).digest('hex');
/** localAuthIdentity: 계정 단위 제한에 사용할 로컬 식별자를 만듭니다 주요 호출: normalizeIp·signature. */ export function localAuthIdentity(address:string,secret:string){const ip=normalizeIp(address);if(!ip||secret.length<32)throw new Error('Invalid local identity');return {[addressHeader]:ip,[signatureHeader]:signature(ip,secret)};}
/** authSourceBucket: 인증 요청의 출처 단위 제한 키를 만듭니다 주요 호출: vercelClientAddress·get·normalizeIp. */ export function authSourceBucket(action:'login'|'register'|'assessment',req:Request,env:Readonly<Record<string,string|undefined>>=process.env){
 let address:string|null=null;
 if(env.VERCEL==='1')address=vercelClientAddress(req.headers,env);
 else{const secret=env.WEBGUARD_LOCAL_AUTH_SECRET,raw=req.headers.get(addressHeader),mac=req.headers.get(signatureHeader);if(secret&&secret.length>=32&&raw&&raw.length<=64&&mac&&/^[a-f0-9]{64}$/.test(mac)){const ip=normalizeIp(raw);if(ip&&timingSafeEqual(Buffer.from(mac,'hex'),Buffer.from(signature(ip,secret),'hex')))address=ip;}}
 // Direct next start has no trusted peer channel; forged headers cannot create new buckets.
 return action+':source:'+createHash('sha256').update(address??'unverified-source').digest('hex');
}
