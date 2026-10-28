import {readdir,readFile} from 'node:fs/promises';
import path from 'node:path';
const root=path.resolve(process.env.WEBGUARD_VERIFY==='true'?'.next-verify/static':'.next/static');
async function walk(dir){return (await Promise.all((await readdir(dir,{withFileTypes:true})).map(e=>e.isDirectory()?walk(path.join(dir,e.name)):[path.join(dir,e.name)]))).flat();}
const files=await walk(root),violations=[];
const forbidden=[/sourceMappingURL\s*=/,/postgres(?:ql)?:\/\/[^\s"']+@/,/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/,/\bpassword_hash\b/,/\barchive_diagnostics_30d\b/,/\bregister_viewer\s*\(/,/\bFROM\s+(?:public\.)?(?:sessions|account_blocks|ip_blocks)\b/i];
for(const file of files){
 if(file.endsWith('.map'))violations.push(path.relative(root,file));
 if(file.endsWith('.js')){const source=await readFile(file,'utf8');if(forbidden.some(pattern=>pattern.test(source)))violations.push(path.relative(root,file));}
}
if(violations.length){console.error('Client boundary verification failed:',[...new Set(violations)]);process.exitCode=1;}
else console.log('Client boundary verified: no source maps or configured server SQL/credential patterns. Browser-delivered code remains inspectable.');
