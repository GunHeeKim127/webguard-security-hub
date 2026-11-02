import {readdir,readFile} from 'node:fs/promises';
import path from 'node:path';
const root=path.resolve(process.env.WEBGUARD_VERIFY==='true'?'.next-verify/static':'.next/static');
/** walk: 대상 폴더의 하위 파일을 재귀적으로 수집합니다 주요 호출: flat·all·map. */ async function walk(dir){return (await Promise.all((await readdir(dir,{withFileTypes:true})).map(/** map 콜백: 각 항목을 필요한 값으로 변환합니다 주요 호출: isDirectory·walk·join. */ e=>e.isDirectory()?walk(path.join(dir,e.name)):[path.join(dir,e.name)]))).flat();}
const files=await walk(root),violations=[];
const forbidden=[/sourceMappingURL\s*=/,/postgres(?:ql)?:\/\/[^\s"']+@/,/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/,/\bpassword_hash\b/,/\barchive_diagnostics_30d\b/,/\bregister_viewer\s*\(/,/\bFROM\s+(?:public\.)?(?:sessions|account_blocks|ip_blocks)\b/i];
for(const file of files){
 if(file.endsWith('.map'))violations.push(path.relative(root,file));
 if(file.endsWith('.js')){const source=await readFile(file,'utf8');if(forbidden.some(/** some 콜백: 조건을 만족하는 항목이 있는지 확인합니다 */ pattern=>pattern.test(source)))violations.push(path.relative(root,file));}
}
if(violations.length){console.error('Client boundary verification failed:',[...new Set(violations)]);process.exitCode=1;}
else console.log('Client boundary verified: no source maps or configured server SQL/credential patterns. Browser-delivered code remains inspectable.');
