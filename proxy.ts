import {NextResponse,type NextRequest} from 'next/server';
import {database} from './lib/database-pool';
import {vercelProtection} from './lib/vercel-protection';
import {contentSecurityPolicy} from './lib/content-security-policy';

export async function proxy(req:NextRequest){
 const rejected=await vercelProtection(req,(sql,values)=>database.protectionQuery(sql,values));
 if(rejected)return rejected;
 const nonce=Buffer.from(crypto.randomUUID()).toString('base64'),policy=contentSecurityPolicy(nonce,process.env.NODE_ENV==='development');
 const requestHeaders=new Headers(req.headers);requestHeaders.set('x-nonce',nonce);requestHeaders.set('Content-Security-Policy',policy);
 const response=NextResponse.next({request:{headers:requestHeaders}});response.headers.set('Content-Security-Policy',policy);return response;
}
export const config={matcher:['/((?!_next/static|_next/image|favicon.ico).*)']};
