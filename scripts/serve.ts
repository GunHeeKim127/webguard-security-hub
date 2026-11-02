import {createServer,type IncomingMessage,type ServerResponse} from 'node:http';
import next from 'next';
import nextEnv from '@next/env';
import {Pool} from 'pg';
import {runtimePoolConfig} from '../lib/runtime-pool-config';
import {activeBlock,clientAddress,detectThreat,recordThreat,threatSessionHash,type IpBlock} from '../lib/ingress-guard';
import {requestLocale} from '../lib/request-locale';
import {defenseText} from '../lib/defense-copy';
import {randomBytes} from 'node:crypto';
import {localAuthIdentity} from '../lib/auth-rate-identity';
import {requestBurst} from '../lib/request-burst';
import {errorText} from '../lib/errors-i18n';
const dev=process.argv.includes('--dev');Object.assign(process.env,{NODE_ENV:dev?'development':'production'});
nextEnv.loadEnvConfig(process.cwd(),dev);
process.env.WEBGUARD_LOCAL_AUTH_SECRET=randomBytes(32).toString('hex');
const option=/** option: 로컬 실행 도구의 인자 값을 읽습니다 주요 호출: indexOf. */ (name:string,fallback:string)=>{const i=process.argv.indexOf(name);return i<0?fallback:process.argv[i+1]??fallback;};
const port=Number(option('--port',process.env.PORT??'3000')),hostname=option('--hostname','127.0.0.1');
if(!Number.isInteger(port)||port<1||port>65535)throw new Error('Invalid port');
const pool=new Pool(runtimePoolConfig());
pool.on('error',/** on 콜백: on에서 전달한 값을 처리하는 콜백입니다 주요 호출: error. */ ()=>console.error('PostgreSQL guard connection closed'));
const query=/** query: 요청한 자료나 현재 상태를 조회합니다 주요 호출: query. */ (sql:string,values:unknown[])=>pool.query(sql,values);
/** headers: 실행 서버에 전달할 헤더 구성을 준비합니다 주요 호출: flatMap·entries. */ function headers(req:IncomingMessage){return new Headers(Object.entries(req.headers).flatMap(/** flatMap 콜백: 항목을 변환하고 결과 배열을 한 단계 펼칩니다 주요 호출: isArray·join. */ ([key,value])=>value===undefined?[]:[[key,Array.isArray(value)?value.join(','):value]]));}
/** inspect: 해당 자료의 관찰·검토 결과를 계산합니다 주요 호출: clientAddress·headers·activeBlock. */ async function inspect(req:IncomingMessage):Promise<IpBlock|null>{
 const address=clientAddress(req.socket.remoteAddress,headers(req));
 if(!address)throw new Error('Client identity unavailable');
 const block=await activeBlock(query,address);if(block)return block;
 const reason=detectThreat(req.url??'/');return reason?recordThreat(query,address,reason,threatSessionHash(req.headers.cookie)):null;
}
/** deny: 허용하지 않는 요청을 거절 응답으로 종료합니다 주요 호출: requestLocale·headers·defenseText. */ function deny(req:IncomingMessage,res:ServerResponse,block:IpBlock|null){
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
const server=createServer({maxHeaderSize:16384,requestTimeout:15000,headersTimeout:10000},/** createServer 콜백: createServer에서 전달한 값을 처리하는 콜백입니다 주요 호출: inspect·deny·clientAddress. */ async(req,res)=>{
 try{
  // A liveness endpoint carries no application data and remains available for operations.
  if(req.url!=='/api/health'&&req.url!=='/api/ready'){
   const address=clientAddress(req.socket.remoteAddress,headers(req));if(!address)throw new Error('Client identity unavailable');
   const burst=requestBurst(address);if(burst){const {locale}=requestLocale(headers(req));res.writeHead(429,{'Content-Type':'application/json','Cache-Control':'no-store','Retry-After':String(burst.retryAfter)});res.end(JSON.stringify({error:errorText(locale,'RATE_LIMITED'),errorCode:'RATE_LIMITED',locale}));return;}
   const block=await inspect(req);if(block){deny(req,res,block);return;}
  }
  // Never forward a gateway credential into the application or its logs.
  const peer=clientAddress(req.socket.remoteAddress,headers(req));if(!peer)throw new Error('Client identity unavailable');
  Object.assign(req.headers,localAuthIdentity(peer,process.env.WEBGUARD_LOCAL_AUTH_SECRET!));
  delete req.headers['x-webguard-proxy-token'];delete req.headers['x-webguard-client-ip'];
  await handle(req,res);
 }catch{if(!res.headersSent)deny(req,res,null);else res.destroy();}
});
const app=next({dev,hostname,port,webpack:true});const handle=app.getRequestHandler();
server.on('upgrade',/** on 콜백: on에서 전달한 값을 처리하는 콜백입니다 주요 호출: inspect·end·getUpgradeHandler. */ async(req,socket,head)=>{try{if(await inspect(req)){socket.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n');return;}delete req.headers['x-webguard-proxy-token'];delete req.headers['x-webguard-client-ip'];await app.getUpgradeHandler()(req,socket,head);}catch{socket.destroy();}});
await app.prepare();
server.listen(port,hostname,/** listen 콜백: listen에서 전달한 값을 처리하는 콜백입니다 주요 호출: log. */ ()=>console.log(`WebGuard guarded server: http://${hostname}:${port}`));
/** stop: 작업의 완료·실패·취소에 맞춰 관련 상태와 자원을 정리합니다 주요 호출: close·end·exit. */ async function stop(){server.close();await app.close();await pool.end();process.exit(0);}
process.once('SIGTERM',/** once 콜백: once에서 전달한 값을 처리하는 콜백입니다 주요 호출: stop. */ ()=>void stop());process.once('SIGINT',/** once 콜백: once에서 전달한 값을 처리하는 콜백입니다 주요 호출: stop. */ ()=>void stop());
