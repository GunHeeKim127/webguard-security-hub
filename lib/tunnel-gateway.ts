import type {IncomingHttpHeaders} from 'node:http';
import {normalizeIp} from './ingress-guard';

/** tunnelHttpsRedirect: 공유 진입 주소의 HTTPS 전환 응답을 결정합니다 주요 호출: startsWith. */ export function tunnelHttpsRedirect(input:IncomingHttpHeaders,hostname:string,target:string){
 if(input.host!==hostname)throw new Error('Unexpected tunnel host');
 if(input['x-forwarded-proto']==='https')return null;
 if(input['x-forwarded-proto']!=='http')throw new Error('Missing edge protocol');
 // Concatenation keeps even a //evil.example request target on our own hostname.
 if(!target.startsWith('/')||/[\r\n]/.test(target))throw new Error('Invalid request target');
 return `https://${hostname}${target}`;
}

// This gateway listens only on loopback and is reached through our cloudflared child.
// Cloudflare overwrites CF-Connecting-IP at its edge. Ordinary XFF is never trusted.
/** tunnelHeaders: 공유 경계에서 전달할 응답 헤더를 정리합니다 주요 호출: normalizeIp·map·split. */ export function tunnelHeaders(input:IncomingHttpHeaders,hostname:string,secret:string){
 if(input.host!==hostname)throw new Error('Unexpected tunnel host');
 const raw=input['cf-connecting-ip'];
 const address=typeof raw==='string'?normalizeIp(raw):null;
 if(!address)throw new Error('Missing edge client IP');
 const headers:IncomingHttpHeaders={...input};
 const connection=typeof input.connection==='string'?input.connection.split(',').map(/** map 콜백: 각 항목을 필요한 값으로 변환합니다 주요 호출: toLowerCase·trim. */ v=>v.trim().toLowerCase()):[];
 for(const key of [...connection,'connection','upgrade','proxy-authorization','proxy-authenticate','keep-alive','te','trailer','transfer-encoding','x-forwarded-for','x-real-ip','forwarded','x-webguard-proxy-token','x-webguard-client-ip','x-webguard-geo-token'])delete headers[key];
 headers.host=hostname;headers['x-forwarded-host']=hostname;headers['x-forwarded-proto']='https';
 headers['x-webguard-proxy-token']=secret;headers['x-webguard-client-ip']=address;
 return headers;
}
