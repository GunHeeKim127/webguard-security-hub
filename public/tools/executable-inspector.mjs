/* VELTHARA read-only inspector. No dependencies; never executes the selected file.
 * Browser worker and Node.js 20+ CLI share this bounded parser. */
export const MAX_FILE_BYTES=8*1024**3,MAX_READ_BYTES=8*1024**2;
export const INSPECTOR_VERSION='2026-10-29.3';
const invalid=()=>{throw new Error('UNSUPPORTED_OR_INVALID_FILE');};
export async function inspectExecutable(source,format){
 if(!['pe','macho'].includes(format)||!Number.isSafeInteger(source.size)||source.size<32||source.size>MAX_FILE_BYTES)invalid();
 let used=0;
 const read=async(offset,length)=>{
  if(!Number.isSafeInteger(offset)||!Number.isSafeInteger(length)||offset<0||length<0||offset+length>source.size||(used+=length)>MAX_READ_BYTES)invalid();
  const bytes=await source.read(offset,length);if(bytes.byteLength!==length)invalid();return new DataView(bytes.buffer,bytes.byteOffset,bytes.byteLength);
 };
 const u64=(v,p,le)=>{const n=Number(v.getBigUint64(p,le));if(!Number.isSafeInteger(n))invalid();return n;};
 let architectures=[];
 if(format==='pe'){
  const dos=await read(0,64);if(dos.getUint16(0,true)!==0x5a4d)invalid();const offset=dos.getUint32(60,true);if(offset<64)invalid();
  const coff=await read(offset,24);if(coff.getUint32(0,true)!==0x4550)invalid();
  const count=coff.getUint16(6,true),size=coff.getUint16(20,true);if(count<1||count>96||size<96||size>4096)invalid();
  const optional=await read(offset+24,size),magic=optional.getUint16(0,true),bits=magic===0x20b?64:magic===0x10b?32:0;if(!bits||size<(bits===64?112:96))invalid();
  const sections=await read(offset+24+size,count*40);let wx=0;
  for(let n=0;n<count;n++){const s=n*40,raw=sections.getUint32(s+20,true),bytes=sections.getUint32(s+16,true);if(bytes&&(raw<offset+24+size+count*40||raw+bytes>source.size))invalid();if((sections.getUint32(s+36,true)&0xa0000000)>>>0===0xa0000000)wx++;}
  const directories=optional.getUint32(bits===64?108:92,true),base=bits===64?112:96;let certificateTable=false;
  if(directories>4){if(base+40>size)invalid();const off=optional.getUint32(base+32,true),len=optional.getUint32(base+36,true);if(off||len){if(!off||len<8||off+len>source.size)invalid();certificateTable=true;}}
  architectures=[{bits,fileType:0,flags:optional.getUint16(70,true),writableExecutable:wx,certificateTable}];
 }else{
  const first=await read(0,8),magic=first.getUint32(0,false),fat=[0xcafebabe,0xbebafeca,0xcafebabf,0xbfbafeca].includes(magic);
  let slices=[{offset:0,size:source.size}];
  if(fat){const le=[0xbebafeca,0xbfbafeca].includes(magic),wide=[0xcafebabf,0xbfbafeca].includes(magic),count=first.getUint32(4,le),entry=wide?32:20;if(!count||count>16)invalid();const table=await read(8,count*entry);slices=[];
   for(let n=0;n<count;n++){const p=n*entry,offset=wide?u64(table,p+8,le):table.getUint32(p+8,le),size=wide?u64(table,p+16,le):table.getUint32(p+12,le);if(offset<8+count*entry||size<32||offset+size>source.size||slices.some(s=>offset<s.offset+s.size&&s.offset<offset+size))invalid();slices.push({offset,size});}
  }
  for(const slice of slices){
   const h=await read(slice.offset,28),m=h.getUint32(0,false),le=[0xcefaedfe,0xcffaedfe].includes(m),bits=[0xfeedfacf,0xcffaedfe].includes(m)?64:[0xfeedface,0xcefaedfe].includes(m)?32:0;if(!bits)invalid();
   const fileType=h.getUint32(12,le),count=h.getUint32(16,le),size=h.getUint32(20,le),header=bits===64?32:28;if(![2,6,8].includes(fileType)||count>4096||size>1048576||header+size>slice.size)invalid();
   const cmds=await read(slice.offset+header,size);let p=0,wx=0,certificateTable=false;
   for(let n=0;n<count;n++){if(p+8>size)invalid();const cmd=cmds.getUint32(p,le),length=cmds.getUint32(p+4,le);if(length<8||length%4||p+length>size)invalid();
    if(cmd===1||cmd===0x19){const wide=cmd===0x19,min=wide?72:56;if(length<min)invalid();const off=wide?u64(cmds,p+40,le):cmds.getUint32(p+32,le),bytes=wide?u64(cmds,p+48,le):cmds.getUint32(p+36,le),prot=cmds.getUint32(p+(wide?60:44),le),sections=cmds.getUint32(p+(wide?64:48),le);if(min+sections*(wide?80:68)>length||off+bytes>slice.size)invalid();if((prot&6)===6)wx++;}
    if(cmd===0x1d){if(length<16)invalid();const off=cmds.getUint32(p+8,le),len=cmds.getUint32(p+12,le);if(!len||off+len>slice.size)invalid();certificateTable=true;}
    p+=length;
   }
   if(p!==size)invalid();architectures.push({bits,fileType,flags:h.getUint32(24,le),writableExecutable:wx,certificateTable});
  }
 }
 return {schemaVersion:1,source:'browser',format,size:source.size,architectures};
}

// A file object is delivered only after the page's explicit, per-file read consent.
if(typeof self!=='undefined'&&typeof self.postMessage==='function'&&typeof document==='undefined'){
 self.onmessage=async event=>{try{const {file,format}=event.data;const result=await inspectExecutable({size:file.size,read:async(o,n)=>new Uint8Array(await file.slice(o,o+n).arrayBuffer())},format);self.postMessage({ok:true,result});}catch{self.postMessage({ok:false});}};
}

// Directory names and metadata only; no candidate contents are read or executed.
export async function discoverLocalCandidates(folder,options={}){
 const fs=await import('node:fs/promises'),path=await import('node:path');
 const {maxEntries=2000,maxDepth=4,maxResults=50}=options;
 if(![maxEntries,maxDepth,maxResults].every(Number.isSafeInteger)||maxEntries<1||maxEntries>10000||maxDepth<0||maxDepth>8||maxResults<1||maxResults>100)throw new Error('INVALID_SEARCH_LIMIT');
 const root=await fs.realpath(folder);if(!(await fs.stat(root)).isDirectory())throw new Error('SEARCH_REQUIRES_FOLDER');
 const candidates=[],limits=new Set(),queue=[{dir:root,depth:0}];let entries=0,unreadable=0,symlinksSkipped=0;
 if(/\.app$/i.test(root))return {candidates:[{path:root,kind:'app-bundle'}],entries:0,truncated:false,limits:[],unreadable,symlinksSkipped};
 search:while(queue.length){const {dir,depth}=queue.shift();let stream;
  try{const resolved=await fs.realpath(dir),relative=path.relative(root,resolved);if(relative==='..'||relative.startsWith('..'+path.sep)||path.isAbsolute(relative)){symlinksSkipped++;continue;}stream=await fs.opendir(resolved);}catch{unreadable++;continue;}
  for await(const entry of stream){
   if(entries>=maxEntries){limits.add('entry-limit');break search;}entries++;
   const file=path.join(dir,entry.name);let metadata;try{metadata=await fs.lstat(file);}catch{unreadable++;continue;}
   if(metadata.isSymbolicLink()){symlinksSkipped++;continue;}
   let kind;
   if(metadata.isDirectory()){
    if(/\.app$/i.test(entry.name))kind='app-bundle';
    else if(!['.git','node_modules'].includes(entry.name)){if(depth<maxDepth)queue.push({dir:file,depth:depth+1});else limits.add('depth-limit');}
   }else if(metadata.isFile()){
    if(/^executable-inspector(?: \(\d+\))?\.mjs$/i.test(entry.name))kind='inspector-tool';
    else if(/\.(pkg|dmg)$/i.test(entry.name))kind='mac-container';
    else if(/\.(exe|dll|dylib|so)$/i.test(entry.name)||((metadata.mode&0o111)!==0&&!path.extname(entry.name)))kind='executable-candidate';
   }
   if(kind){candidates.push({path:file,kind});if(candidates.length>=maxResults){limits.add('result-limit');break search;}}
  }
 }
 candidates.sort((a,b)=>a.path.localeCompare(b.path));
 return {candidates,entries,truncated:limits.size>0,limits:[...limits],unreadable,symlinksSkipped};
}

// Container tools only query metadata. Never install, expand or mount untrusted
// archives. Raw paths, certificate subjects and tool diagnostics stay local.
export async function inspectMacContainer(source,kind,exec,native=false){
 if(!['pkg','dmg'].includes(kind)||source.size<(kind==='dmg'?512:32)||source.size>MAX_FILE_BYTES)invalid();
 const bytes=await source.read(kind==='pkg'?0:source.size-512,kind==='pkg'?4:4);
 if(new TextDecoder().decode(bytes)!==(kind==='pkg'?'xar!':'koly'))throw new Error('CONTAINER_FORMAT_UNSUPPORTED');
 const options={timeout:60000,maxBuffer:1048576,env:{...process.env,LC_ALL:'C',LANG:'C'}};
 const query=async(tool,args)=>{try{const r=await exec(tool,args,options);return {ok:true,text:r.stdout,diagnostic:r.stdout+'\n'+(r.stderr??'')};}catch(e){return {ok:false,text:'',diagnostic:'',code:typeof e.code==='number'?e.code:null};}};
 const container={kind,structure:'unknown',integrity:'unknown',signature:'unknown',gatekeeper:'unknown',payloadListed:false,payloadEntries:0,scriptsPresent:null,unsafePaths:0,scope:'metadata-only'};
 if(kind==='pkg'){
  const listing=await query('/usr/bin/xar',['-tf',source.path]);
  if(listing.ok){const entries=listing.text.split(/\r?\n/).filter(Boolean);if(entries.length>50000)throw new Error('CONTAINER_LIMIT');container.structure='observed';container.scriptsPresent=entries.some(p=>/(^|\/)Scripts(\/|$)/.test(p));container.unsafePaths=entries.filter(p=>p.startsWith('/')||p.split(/[\\/]/).includes('..')).length;}
  const payload=await query('/usr/sbin/pkgutil',['--payload-files',source.path]);
  if(payload.ok){const entries=payload.text.split(/\r?\n/).filter(Boolean);if(entries.length>50000)throw new Error('CONTAINER_LIMIT');container.payloadListed=true;container.payloadEntries=entries.length;container.unsafePaths+=entries.filter(p=>p.startsWith('/')||p.split(/[\\/]/).includes('..')).length;}
  if(native){
   const sig=await query('/usr/sbin/pkgutil',['--check-signature',source.path]);
   // Exit zero alone is not proof: unsigned packages can also return success.
   if(/Status: no signature/i.test(sig.text))container.signature='unsigned';
   else if(/Status: signed by a certificate trusted by (?:macOS|Mac OS X)/i.test(sig.text)&&sig.ok)container.signature='valid';
   else if(/Status:.*(?:invalid|untrusted|revoked)/i.test(sig.text))container.signature='invalid';
  }
 }else{
  const info=await query('/usr/bin/hdiutil',['imageinfo','-plist',source.path]);if(info.ok)container.structure='observed';
  const integrity=await query('/usr/bin/hdiutil',['verify',source.path]);
  // A successful verify without checksum evidence remains unknown.
  if(integrity.ok&&/^\s*(?:verified\s|hdiutil: verify: checksum.*\bis VALID\b)/im.test(integrity.diagnostic))container.integrity='verified';
  if(native){const sig=await query('/usr/bin/codesign',['--verify','--strict',source.path]);if(sig.ok)container.signature='valid';}
 }
 if(native){const policy=await query('/usr/sbin/spctl',['--assess','--type',kind==='pkg'?'install':'open',...(kind==='dmg'?['--context','context:primary-signature']:[]),source.path]);if(policy.ok)container.gatekeeper='accepted';else if(policy.code===3)container.gatekeeper='rejected';}
 if(container.structure!=='observed')throw new Error('CONTAINER_READ_FAILED');
 return {schemaVersion:1,source:'local',format:'macho',size:source.size,architectures:[],container};
}

async function chooseMacInputs(exec){
 const pick=async(script,args=[])=>{const r=await exec('/usr/bin/osascript',['-e',script,...args],{timeout:300000,maxBuffer:131072});return r.stdout.replace(/\r?\n$/,'');};
 const mode=await pick('set p to choose from list {"Choose one app, installer, image or executable", "Search a folder for candidates"} with prompt "Select a local inspection method. No files are uploaded."\nif p is false then error number -128\nreturn item 1 of p');
 let target;
 if(mode==='Search a folder for candidates'){
  const folder=await pick('POSIX path of (choose folder with prompt "Choose the folder to search. Only names and metadata in this folder are searched, with fixed limits.")');
  const result=await discoverLocalCandidates(folder),items=result.candidates.filter(item=>item.kind!=='inspector-tool');
  if(!items.length)throw new Error(result.truncated||result.unreadable?'SEARCH_INCOMPLETE':'NO_CANDIDATES');
  const note=result.truncated||result.unreadable||result.symlinksSkipped?'Search is limited; some folders or links were not searched. ':' ';
  target=await pick('on run argv\nset p to choose from list argv with prompt "'+note+'Select ONE candidate. Its file format will be checked next; a candidate is not a safety verdict."\nif p is false then error number -128\nreturn item 1 of p\nend run',items.map(item=>item.path));
  if(!items.some(item=>item.path===target))throw new Error('INVALID_SELECTION');
 }else target=await pick('POSIX path of (choose file with prompt "Select one .app, .pkg, .dmg or Mach-O executable. Containers receive metadata checks, not full internal code analysis.")');
 const permission=await pick('button returned of (display dialog "Allow reading the selected file and hashing its main executable? Native checks additionally use macOS signing/trust tools and may contact trust services. The app will not be launched or uploaded." buttons {"Cancel", "Static only", "Native checks"} default button "Static only" cancel button "Cancel")');
 const output=await pick('POSIX path of (choose file name with prompt "Choose a NEW report filename. Existing files will not be overwritten." default name "mac-report-'+Date.now()+'.json")');
 return [target,output,'--consent',...(permission==='Native checks'?['--native']:[])];
}

export function inspectionFailureCode(error,stage){
 const known=['APP_EXECUTABLE_NAME_INVALID','APP_EXECUTABLE_OUTSIDE_BUNDLE','APP_METADATA_READ_FAILED','TARGET_DIRECTORY_UNSUPPORTED','MAIN_EXECUTABLE_IS_SCRIPT','UNSUPPORTED_EXECUTABLE_FORMAT','FILE_CHANGED_DURING_INSPECTION','FILE_SIZE_LIMIT','CONTAINER_FORMAT_UNSUPPORTED','CONTAINER_LIMIT','CONTAINER_READ_FAILED','MACOS_REQUIRED'];
 if(known.includes(error?.message))return error.message;
 if(error?.code==='EEXIST')return 'OUTPUT_EXISTS';
 if(['EACCES','EPERM'].includes(error?.code))return 'ACCESS_DENIED';
 if(error?.code==='ENOENT')return stage==='output'?'OUTPUT_FOLDER_NOT_FOUND':stage==='native-tool'?'OS_TOOL_NOT_FOUND':stage==='bundle-metadata'?'APP_METADATA_NOT_FOUND':stage==='bundle-executable'?'APP_EXECUTABLE_NOT_FOUND':'TARGET_NOT_FOUND';
 if(stage==='structure')return 'STRUCTURE_INVALID_OR_UNSUPPORTED';
 if(stage==='bundle-metadata')return 'APP_METADATA_READ_FAILED';
 if(stage==='hash'||stage==='stability')return 'FILE_READ_OR_CHANGE_CHECK_FAILED';
 if(stage==='output')return 'REPORT_WRITE_FAILED';
 return 'INSPECTION_STEP_FAILED';
}

async function main(){
 const fs=await import('node:fs/promises'),path=await import('node:path'),cp=await import('node:child_process'),util=await import('node:util');
 const exec=util.promisify(cp.execFile);let args=process.argv.slice(2);
 if(args.length===1&&args[0]==='--version'){console.log('VELTHARA executable inspector '+INSPECTOR_VERSION);return;}
 if(args.length===1&&args[0]==='--choose'){
  if(process.platform!=='darwin'){console.error('MAC_CHOOSER_UNAVAILABLE: --choose requires macOS. Use explicit quoted tool, target and new output paths.');process.exitCode=1;return;}
  try{args=await chooseMacInputs(exec);}catch(e){if(/\(-128\)/.test(e.stderr??'')){console.log('Selection canceled. No inspection report written.');return;}console.error('Selection could not finish. '+(['SEARCH_INCOMPLETE','NO_CANDIDATES','INVALID_SELECTION'].includes(e.message)?e.message:'Check local file access and macOS dialog permissions.'));process.exitCode=1;return;}
 }
 if(args.includes('--discover')){
  const selected=args.filter(a=>!a.startsWith('--'));if(!args.includes('--consent')||selected.length!==1||args.some(a=>a.startsWith('--')&&!['--discover','--consent'].includes(a))){console.error('Usage: node <actual-tool-path> --discover <selected-folder> --consent. Searches names/metadata only; no upload or candidate execution.');process.exitCode=1;return;}
  try{console.log(JSON.stringify(await discoverLocalCandidates(selected[0]),null,2));}catch{console.error('SEARCH_UNAVAILABLE: select an existing readable folder. No full-disk fallback was attempted.');process.exitCode=1;}return;
 }
 const native=args.includes('--native');
 const positional=args.filter(a=>!a.startsWith('--'));
 if(!args.includes('--consent')||positional.length!==2||args.some(a=>a.startsWith('--')&&!['--consent','--native'].includes(a))){console.error('Node.js 20+ required. Usage: node executable-inspector.mjs <file.exe|Mach-O|app.app|installer.pkg|image.dmg> <new-report.json> --consent [--native]\n--consent permits reading this target and hashing its main executable. --native also permits OS signature/policy checks (may contact OS trust services). No upload, installation or target execution.');process.exitCode=1;return;}
 let handle,stage='target',targetKind='file',detectedFormat='unknown';
 try{
  const out=path.resolve(positional[1]);stage='output';
  try{await fs.lstat(out);const error=new Error('Output already exists');error.code='EEXIST';throw error;}catch(e){if(e.code!=='ENOENT')throw e;}
  await fs.access(path.dirname(out));stage='target';
  const target=await fs.realpath(positional[0]);let binary=target;
  if((await fs.stat(target)).isDirectory()){
   if(process.platform!=='darwin'||!/\.app$/i.test(target))throw new Error('TARGET_DIRECTORY_UNSUPPORTED');targetKind='app-bundle';stage='bundle-metadata';
   const metadata=path.join(target,'Contents/Info.plist');await fs.access(metadata);stage='native-tool';await fs.access('/usr/bin/plutil');stage='bundle-metadata';
   // Read only the declared executable name: unrelated plist data/date fields
   // or a large full-plist JSON conversion must not block this lookup.
   let name;try{name=(await exec('/usr/bin/plutil',['-extract','CFBundleExecutable','raw','-expect','string','-o','-',metadata],{timeout:10000,maxBuffer:8192})).stdout.replace(/\r?\n$/,'');}catch{throw new Error('APP_METADATA_READ_FAILED');}
   if(!name||name==='.'||name==='..'||/[\\/\0]/.test(name))throw new Error('APP_EXECUTABLE_NAME_INVALID');
   stage='bundle-executable';binary=await fs.realpath(path.join(target,'Contents/MacOS',name));if(!binary.startsWith(target+path.sep))throw new Error('APP_EXECUTABLE_OUTSIDE_BUNDLE');
  }
  stage='executable';handle=await fs.open(binary,'r');const before=await handle.stat();if(!before.isFile())throw new Error('UNSUPPORTED_EXECUTABLE_FORMAT');if(before.size<32||before.size>MAX_FILE_BYTES)throw new Error('FILE_SIZE_LIMIT');
  const head=new Uint8Array(4);await handle.read(head,0,4,0);const magic=new DataView(head.buffer).getUint32(0,false),format=head[0]===0x4d&&head[1]===0x5a?'pe':[0xfeedface,0xcefaedfe,0xfeedfacf,0xcffaedfe,0xcafebabe,0xbebafeca,0xcafebabf,0xbfbafeca].includes(magic)?'macho':'unknown';
  const containerKind=/\.(pkg|dmg)$/i.exec(binary)?.[1].toLowerCase();
  if(head[0]===0x23&&head[1]===0x21)throw new Error('MAIN_EXECUTABLE_IS_SCRIPT');if(format==='unknown'&&!containerKind)throw new Error('UNSUPPORTED_EXECUTABLE_FORMAT');detectedFormat=containerKind??format;stage='structure';
  const source={path:binary,size:before.size,read:async(o,n)=>{if(o<0||o+n>before.size)invalid();const b=new Uint8Array(n);let done=0;while(done<n){const r=await handle.read(b,done,n-done,o+done);if(!r.bytesRead)invalid();done+=r.bytesRead;}return b;}};
  if(containerKind&&process.platform!=='darwin')throw new Error('MACOS_REQUIRED');
  const result=containerKind?await inspectMacContainer(source,containerKind,exec,native):await inspectExecutable(source,format);result.source='local';
  stage='hash';const crypto=await import('node:crypto'),hash=crypto.createHash('sha256'),chunk=new Uint8Array(1048576);let offset=0;
  while(offset<before.size){const r=await handle.read(chunk,0,Math.min(chunk.length,before.size-offset),offset);if(!r.bytesRead)invalid();hash.update(chunk.subarray(0,r.bytesRead));offset+=r.bytesRead;}result.sha256=hash.digest('hex');
  if(native&&!containerKind){
   result.native={signature:'unknown',gatekeeper:'unknown',hardenedRuntime:'unknown',debugEntitlement:'unknown'};
   if(format==='pe'&&process.platform==='win32'){
    const shell=path.join(process.env.SystemRoot??'C:/Windows','System32/WindowsPowerShell/v1.0/powershell.exe');
    try{const r=await exec(shell,['-NoProfile','-NonInteractive','-Command','$ErrorActionPreference="Stop"; Import-Module (Join-Path $PSHOME "Modules/Microsoft.PowerShell.Security/Microsoft.PowerShell.Security.psd1") -ErrorAction Stop; (Get-AuthenticodeSignature -LiteralPath $env:VELTHARA_INSPECT_PATH).Status.ToString()'],{env:{...process.env,VELTHARA_INSPECT_PATH:binary},timeout:60000,maxBuffer:4096,windowsHide:true});const s=r.stdout.trim();result.native.signature=s==='Valid'?'valid':s==='NotSigned'?'unsigned':['HashMismatch','NotTrusted','NotSupportedFileFormat','Incompatible'].includes(s)?'invalid':'unknown';}catch{}
   }else if(format==='macho'&&process.platform==='darwin'){
    try{await exec('/usr/bin/codesign',['--verify','--deep','--strict',target],{timeout:60000,maxBuffer:65536});result.native.signature='valid';}catch(e){result.native.signature=typeof e.code==='number'?'invalid':'unknown';}
    try{await exec('/usr/sbin/spctl',['--assess','--type','execute',target],{timeout:60000,maxBuffer:65536});result.native.gatekeeper='accepted';}catch(e){result.native.gatekeeper=typeof e.code==='number'?'rejected':'unknown';}
    try{const r=await exec('/usr/bin/codesign',['--display','--verbose=4',target],{timeout:10000,maxBuffer:65536});result.native.hardenedRuntime=/flags=.*\bruntime\b/.test(r.stderr)?'enabled':'disabled';}catch{}
    try{const r=await exec('/usr/bin/codesign',['--display','--entitlements',':-',target],{timeout:10000,maxBuffer:65536});if(r.stdout.includes('<plist'))result.native.debugEntitlement=/<key>com\.apple\.security\.get-task-allow<\/key>\s*<true\s*\/>/.test(r.stdout)?'allowed':'denied';}catch{}
   }
  }
  stage='stability';const after=await handle.stat(),current=await fs.stat(binary);if(before.size!==after.size||before.mtimeMs!==after.mtimeMs||before.ctimeMs!==after.ctimeMs||before.ino!==current.ino||before.mtimeMs!==current.mtimeMs)throw new Error('FILE_CHANGED_DURING_INSPECTION');
  stage='output';await fs.writeFile(out,JSON.stringify(result,null,2),{flag:'wx',encoding:'utf8'});console.log('Read-only inspection complete. New JSON report written. No file uploaded or executed. A valid signature is not a malware-free verdict.');
 }catch(e){const code=inspectionFailureCode(e,stage);console.error('Inspection stopped: '+code+'. No target was executed or uploaded.');console.error('Diagnostic: '+JSON.stringify({toolVersion:INSPECTOR_VERSION,stage,code,targetKind,detectedFormat,platform:process.platform}));process.exitCode=1;}finally{await handle?.close();}
}
if(typeof process!=='undefined'&&process.versions?.node&&process.argv[1]){
 const fs=await import('node:fs/promises'),url=await import('node:url');
 let entry,current;try{[entry,current]=await Promise.all([fs.realpath(process.argv[1]),fs.realpath(url.fileURLToPath(import.meta.url))]);}catch{}
 if(entry&&entry===current)await main();
}
