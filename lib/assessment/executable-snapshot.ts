// Client/local observations are untrusted self-reports, never remote attestation.
export type MacContainer={kind:'pkg'|'dmg',structure:'observed'|'unknown',integrity:'verified'|'unknown',signature:'valid'|'invalid'|'unsigned'|'unknown',gatekeeper:'accepted'|'rejected'|'unknown',payloadListed:boolean,payloadEntries:number,scriptsPresent:boolean|null,unsafePaths:number,scope:'metadata-only'};
export type ExecutableSnapshot={schemaVersion:1,source:'browser'|'local',format:'pe'|'macho',size:number,architectures:{bits:32|64,fileType:number,flags:number,writableExecutable:number,certificateTable:boolean}[],sha256?:string,stability?:{contentHashesMatch:true,metadataChanged:boolean},container?:MacContainer,native?:{signature:'valid'|'invalid'|'unsigned'|'unknown',gatekeeper:'accepted'|'rejected'|'unknown',hardenedRuntime:'enabled'|'disabled'|'unknown',debugEntitlement:'allowed'|'denied'|'unknown'}};
export type PackageSnapshot={schemaVersion:1,source:'browser',format:'apk'|'aab'|'ipa'|'apks'|'xapk',size:number,entries:number,nestedPackages:number,settings:{decoded:boolean,debuggable:boolean|null,allowBackup:boolean|null,cleartext:boolean|null,arbitraryLoads:boolean|null,permissionCount:number|null}};
const bad=():never=>{throw new Error('INPUT_INVALID');};
const obj=(v:unknown):Record<string,unknown>=>v!==null&&typeof v==='object'&&!Array.isArray(v)?v as Record<string,unknown>:bad();
const keys=(o:Record<string,unknown>,allowed:string[])=>{if(Object.keys(o).some(k=>!allowed.includes(k)))bad();};
const integer=(v:unknown,min:number,max:number)=>{if(typeof v!=='number'||!Number.isSafeInteger(v)||v<min||v>max)bad();return v as number;};
export function executableSnapshot(value:unknown,format:'pe'|'macho'):ExecutableSnapshot{
 const v=obj(value);keys(v,['schemaVersion','source','format','size','architectures','sha256','native','container','stability']);
 if(v.schemaVersion!==1||!['browser','local'].includes(v.source as string)||v.format!==format||!Array.isArray(v.architectures)||(!v.architectures.length&&!v.container)||v.architectures.length>(format==='pe'?1:16))bad();
 let container:MacContainer|undefined;
 if(v.container!==undefined){
  if(format!=='macho'||v.source!=='local'||(v.architectures as unknown[]).length!==0||v.native!==undefined)bad();
  const c=obj(v.container);keys(c,['kind','structure','integrity','signature','gatekeeper','payloadListed','payloadEntries','scriptsPresent','unsafePaths','scope']);
  for(const [k,values]of Object.entries({kind:['pkg','dmg'],structure:['observed','unknown'],integrity:['verified','unknown'],signature:['valid','invalid','unsigned','unknown'],gatekeeper:['accepted','rejected','unknown'],scope:['metadata-only']}))if(!values.includes(c[k] as string))bad();
  if(typeof c.payloadListed!=='boolean'||(!c.payloadListed&&c.payloadEntries!==0))bad();integer(c.payloadEntries,0,50000);integer(c.unsafePaths,0,100000);if(c.scriptsPresent!==null&&typeof c.scriptsPresent!=='boolean')bad();
  if(c.kind==='dmg'&&(c.payloadListed||c.payloadEntries!==0||c.scriptsPresent!==null||c.unsafePaths!==0))bad();
  if(c.kind==='pkg'&&c.integrity!=='unknown')bad();container={...c} as MacContainer;
 }
 integer(v.size,32,8*1024**3);
 const architectures=(v.architectures as unknown[]).map(raw=>{const a=obj(raw);keys(a,['bits','fileType','flags','writableExecutable','certificateTable']);if(![32,64].includes(a.bits as number)||typeof a.certificateTable!=='boolean'||(format==='macho'?![2,6,8].includes(a.fileType as number):a.fileType!==0))bad();integer(a.flags,0,format==='pe'?65535:0xffffffff);integer(a.writableExecutable,0,format==='pe'?96:4096);return {...a} as ExecutableSnapshot['architectures'][number];});
 if(v.sha256!==undefined&&(v.source!=='local'||typeof v.sha256!=='string'||!/^[a-f0-9]{64}$/.test(v.sha256)))bad();
 if(v.stability!==undefined){if(v.source!=='local'||!v.sha256)bad();const s=obj(v.stability);keys(s,['contentHashesMatch','metadataChanged']);if(s.contentHashesMatch!==true||typeof s.metadataChanged!=='boolean')bad();}
 if(v.native!==undefined){if(v.source!=='local')bad();const n=obj(v.native);keys(n,['signature','gatekeeper','hardenedRuntime','debugEntitlement']);for(const [k,values]of Object.entries({signature:['valid','invalid','unsigned','unknown'],gatekeeper:['accepted','rejected','unknown'],hardenedRuntime:['enabled','disabled','unknown'],debugEntitlement:['allowed','denied','unknown']}))if(!values.includes(n[k] as string))bad();if(format==='pe'&&['gatekeeper','hardenedRuntime','debugEntitlement'].some(k=>n[k]!=='unknown'))bad();}
 return {schemaVersion:1,source:v.source as ExecutableSnapshot['source'],format,size:v.size as number,architectures,...(container?{container}:{}),...(v.stability?{stability:{...v.stability as NonNullable<ExecutableSnapshot['stability']>}}:{}),...(v.sha256?{sha256:v.sha256 as string}:{}),...(v.native?{native:{...v.native as NonNullable<ExecutableSnapshot['native']>}}:{})};
}
export function packageSnapshot(value:unknown):PackageSnapshot{
 const v=obj(value);keys(v,['schemaVersion','source','format','size','entries','nestedPackages','settings']);if(v.schemaVersion!==1||v.source!=='browser'||!['apk','aab','ipa','apks','xapk'].includes(v.format as string))bad();integer(v.size,32,8*1024**3);integer(v.entries,1,50000);integer(v.nestedPackages,0,50000);
 const s=obj(v.settings);keys(s,['decoded','debuggable','allowBackup','cleartext','arbitraryLoads','permissionCount']);if(typeof s.decoded!=='boolean')bad();for(const k of ['debuggable','allowBackup','cleartext','arbitraryLoads'])if(s[k]!==null&&typeof s[k]!=='boolean')bad();if(s.permissionCount!==null)integer(s.permissionCount,0,10000);
 if((!s.decoded||['aab','apks','xapk'].includes(v.format as string))&&Object.entries(s).some(([k,val])=>k!=='decoded'&&val!==null))bad();
 if(v.format==='ipa'&&['debuggable','allowBackup','cleartext','permissionCount'].some(k=>s[k]!==null))bad();if(v.format!=='ipa'&&s.arbitraryLoads!==null)bad();
 return JSON.parse(JSON.stringify(v)) as PackageSnapshot;
}
