import {webCompare} from './web-module';
import {linuxSsh,windowsPolicy} from './config-modules';
import {peScanner,apkScanner} from './binary-modules';
import {type AssessmentContext,type AssessmentInput,type SecurityScanner} from './types';
export const scanners:readonly SecurityScanner[]=[webCompare,linuxSsh,windowsPolicy,peScanner,apkScanner];
export const scannerCatalog=scanners.map(({id,version,targetKind,maxBytes})=>({id,version,targetKind,maxBytes}));
export function scannerFor(id:unknown){const module=scanners.find(s=>s.id===id);if(!module)throw new Error('MODULE_UNSUPPORTED');return module;}
export async function runAssessment(input:AssessmentInput,context:AssessmentContext){
 const scanner=scannerFor(input.moduleId);context.signal.throwIfAborted();scanner.validate(input);
 const result=await scanner.scan(input,context);context.signal.throwIfAborted();return result;
}
