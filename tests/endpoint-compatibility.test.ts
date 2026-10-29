import test from 'node:test';
import assert from 'node:assert/strict';
import {configurationFileText,configurationCompatibility,configurationCompatibilityMessage} from '../lib/configuration-file';
import {inspectMacContainer,verifyFileStability} from '../public/tools/executable-inspector.mjs';
import {executableSnapshot} from '../lib/assessment/executable-snapshot';
import {runAssessment} from '../lib/assessment/registry';
import {compareAssessments} from '../lib/assessment/compare';
const ctx=()=>({locale:'ko' as const,signal:AbortSignal.timeout(2000)});
const bytes=(kind:'pkg'|'dmg')=>{const b=Buffer.alloc(512);b.write(kind==='pkg'?'xar!':'koly',kind==='pkg'?0:0);return {path:'/private/not-sent/target.'+kind,size:b.length,read:async(o:number,n:number)=>b.subarray(o,o+n)};};
const stat={dev:1n,ino:9007199254740992n,size:512n,mtimeNs:1234567890123456n,ctimeNs:1234567890123457n};
test('stability distinguishes metadata-only movement after matching full hashes',()=>{
 const hash='a'.repeat(64),after={...stat,ctimeNs:stat.ctimeNs+1n};
 assert.deepEqual(verifyFileStability(stat,stat,stat,hash,hash),{contentHashesMatch:true,metadataChanged:false});
 assert.deepEqual(verifyFileStability(stat,after,after,hash,hash),{contentHashesMatch:true,metadataChanged:true});
});
test('stability still rejects bytes, replacement, size and modification-time changes',()=>{
 const hash='a'.repeat(64);
 for(const delta of [{dev:2n},{ino:stat.ino+1n},{size:513n},{mtimeNs:stat.mtimeNs+1n}]){
  const changed={...stat,...delta};assert.throws(()=>verifyFileStability(stat,stat,changed,hash,hash),/FILE_CHANGED/);assert.throws(()=>verifyFileStability(stat,changed,stat,hash,hash),/FILE_CHANGED/);
 }
 assert.throws(()=>verifyFileStability(stat,stat,stat,hash,'b'.repeat(64)),/FILE_CHANGED/);
 assert.throws(()=>verifyFileStability(stat,stat,stat,'bad','bad'),/FILE_CHANGED/);
 // These different inode IDs collapse as Numbers; BigInt must distinguish them.
 assert.equal(Number(stat.ino),Number(stat.ino+1n));
});
test('failed stability diagnostics expose booleans only; schema rejects forged rechecks',async()=>{
 try{verifyFileStability(stat,stat,{...stat,ino:stat.ino+1n},'a'.repeat(64),'a'.repeat(64));assert.fail('must reject');}catch(error){const flags=(error as Error&{stability:Record<string,boolean>}).stability;assert.equal(flags.identityChanged,true);assert(Object.values(flags).every(v=>typeof v==='boolean'));}
 const s=await inspectMacContainer(bytes('pkg'),'pkg',async()=>({stdout:'Payload'}));
 const base={...s,sha256:'a'.repeat(64),stability:{contentHashesMatch:true,metadataChanged:true}};
 assert.equal(executableSnapshot(base,'macho').stability?.metadataChanged,true);
 for(const forged of [{...base,source:'browser'},{...base,sha256:undefined},{...base,stability:{contentHashesMatch:false,metadataChanged:true}},{...base,stability:{...base.stability,path:'private'}}])assert.throws(()=>executableSnapshot(forged,'macho'));
 const result=await runAssessment({moduleId:'application.macho',label:'review',snapshot:base},ctx());assert.equal(result.findings.find(f=>f.id==='local:stability')?.status,'info');assert(result.findings.every(f=>f.status!=='pass'));
});
test('configuration decoding supports Windows UTF-16 BOMs and rejects invalid/binary/oversize input',()=>{
 const text='{"schemaVersion":1,"note":"한글"}';
 assert.equal(configurationFileText(Buffer.from(text)),text);
 assert.equal(configurationFileText(Buffer.concat([Buffer.from([255,254]),Buffer.from(text,'utf16le')])),text);
 const be=Buffer.from(text,'utf16le');be.swap16();assert.equal(configurationFileText(Buffer.concat([Buffer.from([254,255]),be])),text);
 for(const b of [Buffer.alloc(0),Buffer.alloc(65537),Buffer.from([255,255]),Buffer.from('MZ\0binary')])assert.throws(()=>configurationFileText(b));
});
test('wrong configuration inputs give specific compatibility guidance without sending their contents',()=>{
 for(const [module,text,reason]of [
  ['linux.ssh','-----BEGIN '+'OPENSSH PRIVATE KEY-----\nSECRET','private-key'],
  ['linux.ssh','Host example\nUser root','ssh-client'],
  ['linux.ssh','random data','ssh-unrecognized'],
  ['windows.policy','{"schemaVersion":1}','windows-json'],
  ['windows.policy','[1,2]','windows-json'],
 ] as const){assert.equal(configurationCompatibility(module,text),reason);assert.match(configurationCompatibilityMessage(reason,'ko'),/확인 불가 파일/);assert(!configurationCompatibilityMessage(reason,'en').includes('SECRET'));}
 assert.equal(configurationCompatibility('linux.ssh','PermitRootLogin no'),null);
 assert.equal(configurationCompatibility('windows.policy','{"schemaVersion":1,"firewall":{"domain":null}}'),null);
});
test('quoted SSH directives are understood without treating unrelated quoted paths as Match',async()=>{
 const report=await runAssessment({moduleId:'linux.ssh',label:'review',text:'PermitRootLogin "no" # note\nPasswordAuthentication "no"\nPermitEmptyPasswords "no"\nPubkeyAuthentication "yes"\nMaxAuthTries "4"\nAuthorizedKeysFile ".ssh/keys#local"'},ctx());
 assert(report.findings.every(f=>f.status==='pass'));
 for(const extra of ['\nMatch User example','\nInclude "conf/*.conf"','\nBanner "unterminated']){const r=await runAssessment({moduleId:'linux.ssh',label:'review',text:'PermitRootLogin "no"'+extra},ctx());assert(r.findings.every(f=>f.status==='not_assessed'));}
});
test('SSH result comparison ignores line relocation while retaining actual policy changes',async()=>{
 const input={moduleId:'linux.ssh' as const,label:'review'};
 const a=await runAssessment({...input,text:'PermitRootLogin yes\nMaxAuthTries 6'},ctx());
 const b=await runAssessment({...input,text:'# reordered\nMaxAuthTries 6\nPermitRootLogin yes'},ctx());
 const comparison=compareAssessments(a,b);assert.equal(comparison.changes.find(f=>f.id==='permitrootlogin')?.transition,'unchanged');assert.equal(comparison.changes.find(f=>f.id==='maxauthtries')?.transition,'unchanged');
 const c=await runAssessment({...input,text:'MaxAuthTries 7\nPermitRootLogin no'},ctx());
 assert.equal(compareAssessments(b,c).changes.find(f=>f.id==='permitrootlogin')?.transition,'improved');assert.equal(compareAssessments(b,c).changes.find(f=>f.id==='maxauthtries')?.transition,'changed');
});
test('PKG inventory/native observations never execute installers or retain paths/certificates',async()=>{
 const calls:string[]=[];
 const snapshot=await inspectMacContainer(bytes('pkg'),'pkg',async(tool,args)=>{calls.push(tool+' '+args[0]);return {stdout:tool.endsWith('xar')?'PackageInfo\nScripts\nPayload':args[0]==='--payload-files'?'Applications/Example.app\n../unusual':args[0]==='--check-signature'?'Status: signed by a certificate trusted by macOS\nCertificate PRIVATE_IDENTITY':''};},true);
 const valid=executableSnapshot(snapshot,'macho');assert.equal(valid.container?.signature,'valid');assert.equal(valid.container?.scriptsPresent,true);assert.equal(valid.container?.unsafePaths,1);
 assert(!JSON.stringify(valid).includes('PRIVATE_IDENTITY'));assert(!JSON.stringify(valid).includes('/private/'));
 assert(calls.every(x=>!/installer|attach|expand|extract/.test(x)));
 const report=await runAssessment({moduleId:'application.macho',label:'review',snapshot:valid},ctx());assert(report.findings.every(f=>f.status!=='pass'));assert.equal(report.findings.find(f=>f.id==='container:contents')?.status,'not_assessed');
});
test('unsigned, unavailable and failed payload tools never become successful checks',async()=>{
 const s=await inspectMacContainer(bytes('pkg'),'pkg',async(tool,args)=>{if(args[0]==='--payload-files')throw Object.assign(new Error('PRIVATE_PATH'),{code:1});return {stdout:tool.endsWith('xar')?'Payload\n':args[0]==='--check-signature'?'Status: no signature':''};},true);
 assert.equal(s.container?.signature,'unsigned');assert.equal(s.container?.payloadListed,false);assert.equal(s.container?.payloadEntries,0);
 await assert.rejects(inspectMacContainer(bytes('pkg'),'pkg',async()=>{throw Error('unavailable');}),/CONTAINER_READ_FAILED/);
});
test('DMG checksum requires positive evidence and never mounts or installs an image',async()=>{
 for(const [output,wanted]of [['hdiutil: verify: checksum of image is VALID','verified'],['checksum INVALID','unknown'],['no checksum available','unknown']] as const){
  const calls:string[]=[];const s=await inspectMacContainer(bytes('dmg'),'dmg',async(tool,args)=>{calls.push(args[0]);return {stdout:args[0]==='verify'?output:'metadata'};});assert.equal(s.container?.integrity,wanted);assert.deepEqual(calls,['imageinfo','verify']);executableSnapshot(s,'macho');
 }
});
test('renamed fake containers and forged cross-module snapshots fail closed',async()=>{
 await assert.rejects(inspectMacContainer({...bytes('pkg'),read:async()=>Buffer.from('fake')},'pkg',async()=>{throw Error('must not run');}),/CONTAINER_FORMAT_UNSUPPORTED/);
 const s=await inspectMacContainer(bytes('pkg'),'pkg',async()=>({stdout:'Payload'}));
 for(const forged of [{...s,source:'browser'},{...s,format:'pe'},{...s,container:{...s.container,path:'secret'}},{...s,container:{...s.container,payloadEntries:-1}},{...s,native:{}}])assert.throws(()=>executableSnapshot(forged,'macho'));
 assert.throws(()=>executableSnapshot(s,'pe'));
});
