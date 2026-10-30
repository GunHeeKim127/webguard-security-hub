// Synthetic parser/browser fixtures only: no installable applications or malware.
import {mkdir,readFile,writeFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {deflateRawSync} from 'node:zlib';
import {inspectPackage} from '../public/tools/package-inspector.mjs';
import {assessmentInput} from '../lib/assessment/input';
import {runAssessment} from '../lib/assessment/registry';
const root='tests/fixtures/mobile-2026-10-30';
await mkdir(root,{recursive:true});
function crc(bytes:Uint8Array){let n=0xffffffff;for(const byte of bytes){n^=byte;for(let i=0;i<8;i++)n=(n>>>1)^((n&1)?0xedb88320:0);}return(n^0xffffffff)>>>0;}
function zip(files:Record<string,Uint8Array>){
 const local:Buffer[]=[],central:Buffer[]=[];let offset=0;
 for(const [nameString,bytes]of Object.entries(files)){
  const name=Buffer.from(nameString),packed=deflateRawSync(bytes),l=Buffer.alloc(30),c=Buffer.alloc(46),sum=crc(bytes);
  l.writeUInt32LE(0x04034b50);l.writeUInt16LE(20,4);l.writeUInt16LE(8,8);l.writeUInt32LE(sum,14);l.writeUInt32LE(packed.length,18);l.writeUInt32LE(bytes.length,22);l.writeUInt16LE(name.length,26);
  c.writeUInt32LE(0x02014b50);c.writeUInt16LE(20,4);c.writeUInt16LE(20,6);c.writeUInt16LE(8,10);c.writeUInt32LE(sum,16);c.writeUInt32LE(packed.length,20);c.writeUInt32LE(bytes.length,24);c.writeUInt16LE(name.length,28);c.writeUInt32LE(offset,42);
  local.push(l,name,packed);central.push(c,name);offset+=30+name.length+packed.length;
 }
 const directory=Buffer.concat(central),end=Buffer.alloc(22);end.writeUInt32LE(0x06054b50);end.writeUInt16LE(central.length/2,8);end.writeUInt16LE(central.length/2,10);end.writeUInt32LE(directory.length,12);end.writeUInt32LE(offset,16);
 return Buffer.concat([...local,directory,end]);
}
async function ownFile(name:string,bytes:Uint8Array){try{await writeFile(`${root}/${name}`,bytes,{flag:'wx'});}catch(e){if((e as NodeJS.ErrnoException).code!=='EEXIST')throw e;if(!Buffer.from(bytes).equals(await readFile(`${root}/${name}`)))throw new Error(`Refusing to overwrite changed fixture: ${name}`);}}
const fixtures=[];
for(const format of ['ipa','aab','apks','xapk'] as const)for(const remediated of [false,true]){
 const variant=remediated?'remediated':'vulnerable',nested=await readFile(`tests/fixtures/phase2/android-${variant}.apk`);
 const marker=Buffer.from(`SYNTHETIC NON-INSTALLABLE ${format} ${variant}. Inventory-only formats must remain unassessed.`);
 const files:Record<string,Uint8Array>=format==='ipa'?{
  'Payload/Fixture.app/Info.plist':Buffer.from(`<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>dev.velthara.synthetic</string><key>NSAppTransportSecurity</key><dict><key>NSAllowsArbitraryLoads</key><${remediated?'false':'true'}/></dict></dict></plist>`),
  'SYNTHETIC.txt':marker,
 }:format==='aab'?{'base/manifest/AndroidManifest.xml':marker,'SYNTHETIC.txt':marker}:format==='apks'?{'toc.pb':marker,'splits/base-master.apk':nested,'SYNTHETIC.txt':marker}:{'manifest.json':Buffer.from(JSON.stringify({synthetic:true,package_name:'dev.velthara.synthetic',split_apks:[{file:'base.apk',id:'base'}]})),'base.apk':nested,'SYNTHETIC.txt':marker};
 const bytes=zip(files),name=`${format}-${variant}.${format}`;await ownFile(name,bytes);
 const snapshot=await inspectPackage({size:bytes.length,read:async(o:number,n:number)=>bytes.subarray(o,o+n)});
 const report=await runAssessment(assessmentInput({moduleId:'application.package',label:`Synthetic ${format}`,authorized:true,snapshot}),{locale:'ko',signal:AbortSignal.timeout(5000)});
 fixtures.push({name,format,variant,synthetic:true,installable:false,size:bytes.length,sha256:createHash('sha256').update(bytes).digest('hex'),snapshot,report});
}
await ownFile('reject-traversal.ipa',zip({'../Payload/Fixture.app/Info.plist':Buffer.from('<plist/>')}));
await ownFile('reject-not-a-package.ipa',Buffer.from('SYNTHETIC: plain text renamed as IPA, must be rejected.'));
await writeFile(`${root}/manifest.json`,JSON.stringify({synthetic:true,originalsExecuted:false,fixtures},null,2)+'\n');
await writeFile(`${root}/README.md`, `# 모바일 합성 검증 파일\n\n실행·설치 불가능한 파서/브라우저 시험 입력입니다. 악성코드 샘플이나 정상 배포 앱이 아닙니다. 원본 앱이나 iOS 실기기 검증을 대체하지 않습니다.\n\n- IPA vulnerable/remediated: Info.plist의 NSAllowsArbitraryLoads true/false. 경고 1→0을 기대하되 보완 후에도 안전 인증/통과로 표시하지 않습니다.\n- AAB/APKS/XAPK vulnerable/remediated: 변형 이름 및 중첩 합성 APK 선언이 다릅니다. 현재 모듈은 목록만 검사하므로 두 파일 모두 설정·서명·중첩 앱은 미검사여야 합니다. AAB/toc.pb의 내용은 유효한 protobuf 빌드 산출물이 아닙니다.\n- reject-*.ipa: 경로 탈출 ZIP 또는 확장자만 IPA인 텍스트로, 검사 실패 및 저장 비활성을 기대합니다.\n\n로그인→Mobile→같은 자산 이름으로 취약 선언 파일 선택→읽기 동의→점검→별도 분석 동의→저장→보완 선언 파일로 반복→결과 비교→JSON 다운로드 순서로 확인합니다. 파일 선택/변경만으로 읽지 않아야 하며 취소하면 동의가 초기화돼야 합니다.\n\n재생성: node node_modules/tsx/dist/cli.mjs scripts/generate-mobile-review-fixtures.ts. 기존 파일 내용이 다르면 덮어쓰지 않습니다. manifest.json에 SHA-256·기대 분석값을 기록합니다.\n`);
console.log(fixtures.map(f=>({name:f.name,format:f.snapshot.format,warning:f.report.findings.filter(x=>x.status==='warning').length,unknown:f.report.findings.filter(x=>x.status==='not_assessed').length})));
