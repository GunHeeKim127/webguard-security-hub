import {createHash,createHmac,timingSafeEqual} from 'node:crypto';
import {normalizeIp} from './ingress-guard';
import {vercelClientAddress} from './vercel-protection';
const addressHeader='x-webguard-auth-peer',signatureHeader='x-webguard-auth-signature';
const signature=(address:string,secret:string)=>createHmac('sha256',secret).update('webguard-auth-client-v1\0'+address).digest('hex');
export function localAuthIdentity(address:string,secret:string){const ip=normalizeIp(address);if(!ip||secret.length<32)throw new Error('Invalid local identity');return {[addressHeader]:ip,[signatureHeader]:signature(ip,secret)};}
export function authSourceBucket(action:'login'|'register',req:Request,env:Readonly<Record<string,string|undefined>>=process.env){
 let address:string|null=null;
 if(env.VERCEL==='1')address=vercelClientAddress(req.headers,env);
 else{const secret=env.WEBGUARD_LOCAL_AUTH_SECRET,raw=req.headers.get(addressHeader),mac=req.headers.get(signatureHeader);if(secret&&secret.length>=32&&raw&&raw.length<=64&&mac&&/^[a-f0-9]{64}$/.test(mac)){const ip=normalizeIp(raw);if(ip&&timingSafeEqual(Buffer.from(mac,'hex'),Buffer.from(signature(ip,secret),'hex')))address=ip;}}
 // Direct next start has no trusted peer channel; forged headers cannot create new buckets.
 return action+':source:'+createHash('sha256').update(address??'unverified-source').digest('hex');
}
