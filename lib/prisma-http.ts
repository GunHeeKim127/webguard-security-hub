import {client,defaultClientConfig,type Client} from '@prisma/ppg';
import {types,type QueryResult,type QueryResultRow} from 'pg';

function parameter(value:unknown,depth=0):unknown{
 if(depth>16)throw new Error('Database parameter nesting exceeded');
 if(Array.isArray(value))return '{'+value.map(v=>v===null||v===undefined?'NULL':'"'+String(parameter(v,depth+1)).replace(/\\/g,'\\\\').replace(/"/g,'\\"')+'"').join(',')+'}';
 if(value instanceof Uint8Array)throw new Error('Binary database parameters unsupported');
 if(value&&typeof value==='object'&&!(value instanceof Date))return JSON.stringify(value);
 return value;
}
export function httpQueryAdapter(driver:Pick<Client,'query'|'exec'>,onPending:(task:Promise<unknown>)=>void=()=>{}){
 return {async query<R extends QueryResultRow=any>(text:string,values:unknown[]=[],timeoutMs=5000):Promise<QueryResult<R>>{
  const structure=text.replace(/'(?:''|[^'])*'/g,"''"),returnsRows=/^\s*(SELECT|WITH)\b/i.test(structure)||/\bRETURNING\b/i.test(structure);
  const args=values.map(v=>parameter(v));
  const task=(async():Promise<QueryResult<R>>=>{
   if(!returnsRows){const n=await driver.exec(text,...args);return {rows:[],rowCount:n,command:text.trim().split(/\s/,1)[0].toUpperCase(),oid:0,fields:[]};}
   const result=await driver.query(text,...args),data=await result.rows.collect();
   const rows=data.map(row=>Object.fromEntries(result.columns.map((col,i)=>[col.name,row.values[i]])) as R);
   return {rows,rowCount:rows.length,command:'SELECT',oid:0,fields:result.columns.map(col=>({name:col.name,dataTypeID:col.oid,tableID:0,columnID:0,dataTypeSize:-1,dataTypeModifier:-1,format:'text'}))};
  })();
  // The SDK has no cancellation API. A deadline bounds the caller's wait only;
  // keep the original operation draining and never retry an ambiguous write.
  let timer:ReturnType<typeof setTimeout>|undefined;
  try{return await Promise.race([task,new Promise<never>((_,reject)=>{timer=setTimeout(()=>{try{onPending(task);}catch{}reject(new Error('Query read timeout'));},timeoutMs);})]);}
  finally{clearTimeout(timer);}
 }};
}
export function managedHttpConfig(connectionString:string){
 const url=new URL(connectionString);
 if(!['postgres:','postgresql:'].includes(url.protocol)||!['pooled.db.prisma.io','db.prisma.io'].includes(url.hostname)||!url.username||!url.password)throw new Error('Invalid managed HTTP database configuration');
 // The SDK derives its HTTPS endpoint from this hostname. pooled.db is the
 // TCP pooler, not its documented HTTP endpoint. Prisma documents the same
 // credentials for both hosts; retain them and target the official HTTP host.
 // This never opens a direct TCP connection or uses a migration credential.
 url.hostname='db.prisma.io';
 return defaultClientConfig(url.toString());
}
export function prismaHttp(connectionString:string,onPending?:(task:Promise<unknown>)=>void){
 const config=managedHttpConfig(connectionString);
 // Match node-postgres: int8 remains a string and timestamps serialize as ISO.
 config.parsers=[16,20,21,23,700,701,25,1043,114,3802,1082,1114,1184,1700].map(oid=>({oid,parse:(value:string|null)=>value===null?null:types.getTypeParser(oid,'text')(value)}));
 return httpQueryAdapter(client(config),onPending);
}
