export const MAX_FILE_BYTES:number,MAX_READ_BYTES:number;
export function inspectExecutable(source:{size:number,read:(offset:number,length:number)=>Promise<Uint8Array>},format:'pe'|'macho'):Promise<import('../../lib/assessment/executable-snapshot').ExecutableSnapshot>;
