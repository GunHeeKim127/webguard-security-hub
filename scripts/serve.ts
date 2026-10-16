import {createServer,type IncomingMessage,type ServerResponse} from 'node:http';
import next from 'next';
import nextEnv from '@next/env';
import {Pool} from 'pg';
import {projectDatabase} from '../lib/project-database';
import {activeBlock,clientAddress,detectThreat,recordThreat,type IpBlock} from '../lib/ingress-guard';
import {requestLocale} from '../lib/request-locale';
import {defenseText} from '../lib/defense-copy';
const dev=process.argv.includes('--dev');Object.assign(process.env,{NODE_ENV:dev?'development':'production'});
nextEnv.loadEnvConfig(process.cwd(),dev);
const option=(name:string,fallback:string)=>{const i=process.argv.indexOf(name);return i<0?fallback:process.argv[i+1]??fallback;};
const port=Number(option('--port',process.env.PORT??'3000')),hostname=option('--hostname','127.0.0.1');
if(!Number.isInteger(port)||port<1||port>65535)throw new Error('Invalid port');
const pool=new Pool({...projectDatabase('runtime'),max:5,connectionTimeoutMillis:3000,statement_timeout:5000});
const query=(sql:string,values:unknown[])=>pool.query(sql,values);
function headers(req:IncomingMessage){return new Headers(Object.entries(req.headers).flatMap(([key,value])=>value===undefined?[]:[[key,Array.isArray(value)?value.join(','):value]]));}
async function inspect(req:IncomingMessage):Promise<IpBlock|null>{
 const address=clientAddress(req.socket.remoteAddress,headers(req));
 if(!address)throw new Error('Client identity unavailable');
 const block=await activeBlock(query,address);if(block)return block;
 const reason=detectThreat(req.url??'/');return reason?recordThreat(query,address,reason):null;
}
function deny(req:IncomingMessage,res:ServerResponse,block:IpBlock|null){
 const locale=requestLocale(headers(req)).locale,code=block?(block.blacklisted?'IP_BLACKLISTED':'THREAT_BLOCKED'):'PROTECTION_UNAVAILABLE';
 const message=defenseText(locale,block?(block.blacklisted?'permanent':'temporary'):'unavailable');
 res.statusCode=block?(block.blacklisted?403:429):503;
 res.setHeader('Cache-Control','no-store');res.setHeader('Content-Language',locale);res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('X-Frame-Options','DENY');
 res.setHeader('Connection','close');
 res.setHeader('Content-Security-Policy',"default-src 'none'; frame-ancestors 'none'; base-uri 'none'");
 if(block&&!block.blacklisted)res.setHeader('Retry-After',String(Math.max(1,block.retry_after)));
 if(req.headers.accept?.includes('text/html')){res.setHeader('Content-Type','text/html; charset=utf-8');res.end(`<!doctype html><html lang="${locale}"><meta charset="utf-8"><title>WebGuard</title><h1>WebGuard</h1><p>${message}</p></html>`);}
 else{res.setHeader('Content-Type','application/json; charset=utf-8');res.end(JSON.stringify({error:message,errorCode:code,locale,retryAfter:block&&!block.blacklisted?block.retry_after:null,strikes:block?.strikes??null}));}
}
const server=createServer({maxHeaderSize:16384,requestTimeout:15000,headersTimeout:10000},async(req,res)=>{
 try{
  // A liveness endpoint carries no application data and remains available for operations.
  if(req.url!=='/api/health'){const block=await inspect(req);if(block){deny(req,res,block);return;}}
  // Never forward a gateway credential into the application or its logs.
  delete req.headers['x-webguard-proxy-token'];delete req.headers['x-webguard-client-ip'];
  await handle(req,res);
 }catch{if(!res.headersSent)deny(req,res,null);else res.destroy();}
});
const app=next({dev,hostname,port,webpack:true});const handle=app.getRequestHandler();
server.on('upgrade',async(req,socket,head)=>{try{if(await inspect(req)){socket.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n');return;}delete req.headers['x-webguard-proxy-token'];delete req.headers['x-webguard-client-ip'];await app.getUpgradeHandler()(req,socket,head);}catch{socket.destroy();}});
await app.prepare();
server.listen(port,hostname,()=>console.log(`WebGuard guarded server: http://${hostname}:${port}`));
async function stop(){server.close();await app.close();await pool.end();process.exit(0);}
process.once('SIGTERM',()=>void stop());process.once('SIGINT',()=>void stop());
