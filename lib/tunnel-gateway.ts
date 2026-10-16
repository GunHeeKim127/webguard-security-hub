import type {IncomingHttpHeaders} from 'node:http';
import {normalizeIp} from './ingress-guard';

// This gateway listens only on loopback and is reached through our cloudflared child.
// Cloudflare overwrites CF-Connecting-IP at its edge. Ordinary XFF is never trusted.
export function tunnelHeaders(input:IncomingHttpHeaders,hostname:string,secret:string){
 if(input.host!==hostname)throw new Error('Unexpected tunnel host');
 const raw=input['cf-connecting-ip'];
 const address=typeof raw==='string'?normalizeIp(raw):null;
 if(!address)throw new Error('Missing edge client IP');
 const headers:IncomingHttpHeaders={...input};
 const connection=typeof input.connection==='string'?input.connection.split(',').map(v=>v.trim().toLowerCase()):[];
 for(const key of [...connection,'connection','upgrade','proxy-authorization','proxy-authenticate','keep-alive','te','trailer','transfer-encoding','x-forwarded-for','x-real-ip','forwarded','x-webguard-proxy-token','x-webguard-client-ip','x-webguard-geo-token'])delete headers[key];
 headers.host=hostname;headers['x-forwarded-host']=hostname;headers['x-forwarded-proto']='https';
 headers['x-webguard-proxy-token']=secret;headers['x-webguard-client-ip']=address;
 return headers;
}
