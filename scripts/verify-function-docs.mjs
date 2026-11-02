import ts from 'typescript';
import {execFileSync} from 'node:child_process';
import {readFileSync,existsSync} from 'node:fs';

const files=[...new Set(execFileSync('git',['ls-files','--cached','--others','--exclude-standard'],{encoding:'utf8'}).split(/\r?\n/).filter(/** 소스 선택: 제품·테스트·도구의 실제 JavaScript/TypeScript 소스만 고릅니다. */ p=>/^(app|lib|scripts|public\/tools|tests)\//.test(p)&&/\.(?:tsx?|[mc]?js)$/.test(p)&&!p.endsWith('.d.ts')&&existsSync(p)))];
let functions=0;const missing=[];
for(const file of files){
 const text=readFileSync(file,'utf8'),source=ts.createSourceFile(file,text,ts.ScriptTarget.Latest,true,file.endsWith('tsx')?ts.ScriptKind.TSX:file.endsWith('ts')?ts.ScriptKind.TS:ts.ScriptKind.JS);
 /** visit: 함수와 콜백의 직전 설명 주석을 확인하고 누락 위치만 수집합니다. */
 function visit(node){if(ts.isFunctionLike(node)&&node.body){functions++;const start=node.getStart(source),before=text.slice(0,start).trimEnd(),open=before.lastIndexOf('/**');if(!before.endsWith('*/')||open<0||before.slice(open).length<18)missing.push({file,line:source.getLineAndCharacterOfPosition(start).line+1});}ts.forEachChild(node,visit);}
 visit(source);
}
console.log(JSON.stringify({files:files.length,functions,missing}));if(missing.length)process.exitCode=1;
