export const MAX_FILE_BYTES:number,MAX_READ_BYTES:number;
export const INSPECTOR_VERSION:string;
export function inspectionFailureCode(error:unknown,stage:string):string;
export function inspectExecutable(source:{size:number,read:(offset:number,length:number)=>Promise<Uint8Array>},format:'pe'|'macho'):Promise<import('../../lib/assessment/executable-snapshot').ExecutableSnapshot>;
export function discoverLocalCandidates(folder:string,options?:{maxEntries?:number,maxDepth?:number,maxResults?:number}):Promise<{candidates:{path:string,kind:string}[],entries:number,truncated:boolean,limits:string[],unreadable:number,symlinksSkipped:number}>;
