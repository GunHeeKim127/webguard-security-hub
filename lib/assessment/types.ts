export type AssessmentStatus='pass'|'warning'|'info'|'not_assessed';
export type Finding={id:string,title:string,status:AssessmentStatus,severity:'info'|'low'|'medium'|'high',evidence:string[],remediation:string,reference?:string};
export type ModuleId='web.compare'|'linux.ssh'|'windows.policy'|'application.pe'|'application.apk';
export type AssessmentInput={moduleId:ModuleId,label:string,url?:string,text?:string,base64?:string};
export type AssessmentContext={signal:AbortSignal,locale:'ko'|'en'};
export type AssessmentReport={schemaVersion:1,moduleId:ModuleId,moduleVersion:string,ruleVersion:string,targetKind:string,findings:Finding[],scope:string[],limitations:string[],observedAt:string};
export interface SecurityScanner{id:ModuleId;version:string;targetKind:string;maxBytes:number;validate(input:AssessmentInput):void;scan(input:AssessmentInput,context:AssessmentContext):Promise<AssessmentReport>;}
export const pick=(context:AssessmentContext,ko:string,en:string)=>context.locale==='ko'?ko:en;
export function report(module:SecurityScanner,findings:Finding[],scope:string[],limitations:string[]):AssessmentReport{return {schemaVersion:1,moduleId:module.id,moduleVersion:module.version,ruleVersion:'2026-10-19.1',targetKind:module.targetKind,findings,scope,limitations,observedAt:new Date().toISOString()};}
export function checkpoint(context:AssessmentContext){context.signal.throwIfAborted();}
export function textInput(input:AssessmentInput){if(typeof input.text!=='string'||!input.text.trim()||Buffer.byteLength(input.text)>65536||input.text.includes('\0'))throw new Error('INPUT_INVALID');return input.text.replace(/^\uFEFF/,'');}
export function binaryInput(input:AssessmentInput){if(typeof input.base64!=='string'||input.base64.length>2796204)throw new Error('INPUT_INVALID');const bytes=Buffer.from(input.base64,'base64');if(!bytes.length||bytes.length>2097152||bytes.toString('base64')!==input.base64)throw new Error('INPUT_INVALID');return bytes;}
