export const MAX_FILE_BYTES:number,MAX_READ_BYTES:number;
export const INSPECTOR_VERSION:string;
export function inspectionFailureCode(error:unknown,stage:string):string;
export function verifyFileStability(before:{dev:bigint,ino:bigint,size:bigint,mtimeNs:bigint,ctimeNs:bigint},after:{dev:bigint,ino:bigint,size:bigint,mtimeNs:bigint,ctimeNs:bigint},current:{dev:bigint,ino:bigint,size:bigint,mtimeNs:bigint,ctimeNs:bigint},initialHash:string,finalHash:string):{contentHashesMatch:true,metadataChanged:boolean};
export function inspectMacContainer(source:{path:string,size:number,read:(offset:number,length:number)=>Promise<Uint8Array>},kind:'pkg'|'dmg',exec:(tool:string,args:string[],options:unknown)=>Promise<{stdout:string,stderr?:string}>,native?:boolean):Promise<import('../../lib/assessment/executable-snapshot').ExecutableSnapshot>;
export function inspectExecutable(source:{size:number,read:(offset:number,length:number)=>Promise<Uint8Array>},format:'pe'|'macho'):Promise<import('../../lib/assessment/executable-snapshot').ExecutableSnapshot>;
export function discoverLocalCandidates(folder:string,options?:{maxEntries?:number,maxDepth?:number,maxResults?:number}):Promise<{candidates:{path:string,kind:string}[],entries:number,truncated:boolean,limits:string[],unreadable:number,symlinksSkipped:number}>;
