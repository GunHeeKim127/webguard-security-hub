export function inspectPackage(source:{size:number,read:(offset:number,length:number)=>Promise<Uint8Array>}):Promise<import('../../lib/assessment/executable-snapshot').PackageSnapshot>;
export function androidSettings(bytes:Uint8Array):import('../../lib/assessment/executable-snapshot').PackageSnapshot['settings'];
export function plistValue(bytes:Uint8Array):unknown;
