// Foreground, PC-hosted HTTPS sharing. No firewall rules, persistent service or DB migration.
import {createServer,request as httpRequest} from 'node:http';
import {spawn,type ChildProcess} from 'node:child_process';
import {randomBytes,createHash} from 'node:crypto';
import {readFile,mkdir,writeFile,rename} from 'node:fs/promises';
import path from 'node:path';
import {tunnelHeaders,tunnelHttpsRedirect} from '../lib/tunnel-gateway';

const executable=path.resolve('work/tools/cloudflared.exe');
const digest='4d2490e74082c5d48dbfedaf92576fa5bd1702379ab88eb7faa0cfbe8dc891b6';
const source='https://github.com/cloudflare/cloudflared/releases/download/2026.10.1/cloudflared-windows-amd64.exe';
const children:ChildProcess[]=[];let stopping=false;
const secret=randomBytes(32).toString('hex');let hostname='',targetPort=0,ready=false;
function safeOrigin(value:string|string[]|undefined){try{return typeof value==='string'?new URL(value).origin:'missing';}catch{return 'invalid';}}
const relay=createServer({maxHeaderSize:16384,requestTimeout:15000,headersTimeout:10000},(req,res)=>{
 res.setHeader('Cache-Control','no-store');
 if(!ready){res.writeHead(503);res.end('WebGuard is starting');return;}
 let headers;try{headers=tunnelHeaders(req.headers,hostname,secret);}catch{res.writeHead(403);res.end('Forbidden');return;}
 let redirect;try{redirect=tunnelHttpsRedirect(req.headers,hostname,req.url??'/');}catch{res.writeHead(403);res.end('Forbidden');return;}
 if(redirect){res.writeHead(308,{Location:redirect});res.end();return;}
 res.setHeader('Strict-Transport-Security','max-age=86400');
 const upstream=httpRequest({host:'127.0.0.1',port:targetPort,method:req.method,path:req.url,headers},response=>{
  if(response.statusCode===403&&(req.url??'').split('?')[0]==='/api/login')console.log('Login origin diagnostic:',JSON.stringify({origin:safeOrigin(req.headers.origin),destination:hostname,protocol:req.headers['x-forwarded-proto']}));
  const output={...response.headers};delete output.connection;delete output['transfer-encoding'];
  output['strict-transport-security']='max-age=86400';res.writeHead(response.statusCode??502,output);response.pipe(res);response.on('error',()=>res.destroy());
 });
 upstream.setTimeout(30000,()=>upstream.destroy());
 upstream.on('error',()=>{if(!res.headersSent){res.writeHead(502);res.end('WebGuard unavailable');}else res.destroy();});
 res.on('close',()=>upstream.destroy());req.on('aborted',()=>upstream.destroy());req.pipe(upstream);
});
relay.on('upgrade',(_req,socket)=>socket.destroy()); // Production profile has no HMR/websocket service.
function stop(code=0){if(stopping)return;stopping=true;ready=false;relay.close();relay.closeAllConnections();for(const child of children)child.kill();setTimeout(()=>process.exit(code),1000);}
process.once('SIGINT',()=>stop());process.once('SIGTERM',()=>stop());
function run(file:string,args:string[],env=process.env){const child=spawn(file,args,{env,windowsHide:true,stdio:['ignore','pipe','pipe']});children.push(child);child.on('error',()=>stop(1));return child;}
function closed(child:ChildProcess){return new Promise<void>((resolve,reject)=>{child.once('error',reject);child.once('exit',code=>code===0?resolve():reject(new Error('Child failed')));});}
try{
 if(process.platform!=='win32'||process.arch!=='x64')throw new Error('This launcher supports Windows x64');
 await mkdir(path.dirname(executable),{recursive:true});
 let binary:Buffer;try{binary=await readFile(executable);}catch{
  console.log('Downloading pinned official Cloudflare connector (once).');
  const response=await fetch(source,{signal:AbortSignal.timeout(120000)});if(!response.ok)throw new Error('Connector download failed');binary=Buffer.from(await response.arrayBuffer());
  if(createHash('sha256').update(binary).digest('hex')!==digest)throw new Error('Connector checksum mismatch');
  await writeFile(executable+'.part',binary);await rename(executable+'.part',executable);
 }
 if(createHash('sha256').update(binary).digest('hex')!==digest)throw new Error('Connector checksum mismatch');
 if(process.argv.includes('--skip-build')){await readFile('.next-verify/BUILD_ID');}
 else{
  console.log('Building production app. Existing localhost development server is preserved.');
  const build=run(process.execPath,['node_modules/next/dist/bin/next','build','--webpack'],{...process.env,WEBGUARD_VERIFY:'true'});
  build.stdout?.pipe(process.stdout);build.stderr?.pipe(process.stderr);await closed(build);
 }
 await new Promise<void>(resolve=>relay.listen(0,'127.0.0.1',resolve));
 const relayAddress=relay.address();if(!relayAddress||typeof relayAddress==='string')throw new Error('Relay failed');
 const tunnel=run(executable,['tunnel','--no-autoupdate','--protocol','http2','--url',`http://127.0.0.1:${relayAddress.port}`]);
 tunnel.once('exit',()=>stop(1));
 const origin=await new Promise<string>((resolve,reject)=>{
  const timer=setTimeout(()=>reject(new Error('Tunnel connection timed out')),60000);let tail='';
  const capture=(data:Buffer)=>{tail=(tail+data.toString()).slice(-12000);const match=tail.match(/https:\/\/([a-z0-9-]+\.trycloudflare\.com)\b/);if(match){clearTimeout(timer);resolve(match[0]);}};
  tunnel.stdout?.on('data',capture);tunnel.stderr?.on('data',capture);
  tunnel.once('exit',()=>{clearTimeout(timer);reject(new Error('Tunnel exited'));});
 });
 hostname=new URL(origin).hostname;
 // A loopback-only ephemeral port is passed to the guard; its peer must authenticate.
 const reservation=createServer();await new Promise<void>(resolve=>reservation.listen(0,'127.0.0.1',resolve));
 const address=reservation.address();if(!address||typeof address==='string')throw new Error('Port allocation failed');targetPort=address.port;
 await new Promise<void>((resolve,reject)=>reservation.close(error=>error?reject(error):resolve()));
 const app=run(process.execPath,['--import','tsx','scripts/serve.ts','--port',String(targetPort)],{...process.env,WEBGUARD_VERIFY:'true',APP_ORIGIN:origin,APP_ADDITIONAL_ORIGINS:'',TRUSTED_PROXY_IPS:'127.0.0.1',WEBGUARD_PROXY_SECRET:secret,GEOIP_PROXY_SECRET:'',PUBLIC_REGISTRATION_ENABLED:'false'});
 app.stdout?.resume();app.stderr?.resume();
 app.once('exit',()=>stop(1));
 let appReady=false;for(let i=0;i<60;i++){if(app.exitCode!==null)throw new Error('App exited');try{if((await fetch(`http://127.0.0.1:${targetPort}/api/health`,{signal:AbortSignal.timeout(1000)})).ok){appReady=true;break;}}catch{}await new Promise(resolve=>setTimeout(resolve,500));}
 if(!appReady)throw new Error('Application startup timed out');ready=true;
 await writeFile('work/share-url.txt',origin+'\n');
 console.log(`\nExternal HTTPS address: ${origin}\nSign in with an existing account. Ctrl+C stops sharing. PC sleep/shutdown disconnects it.\n`);
}catch(error){console.error('Sharing could not start:',error instanceof Error?error.message:'Unknown failure');stop(1);}
process.once('exit',()=>{for(const child of children)child.kill();});
