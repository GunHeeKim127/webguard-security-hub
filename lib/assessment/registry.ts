import {webCompare} from './web-module';
import {linuxSsh,windowsPolicy} from './config-modules';
import {peScanner,apkScanner} from './binary-modules';
import {machoScanner,packageScanner} from './local-modules';
import {vmwareConfig,gns3Topology} from './infrastructure-modules';
import {type AssessmentContext,type AssessmentInput,type SecurityScanner} from './types';
import {inspectOriginal} from './original-integrity';
import {createHash} from 'node:crypto';
import {binaryInput} from './types';
export const scanners:readonly SecurityScanner[]=[webCompare,linuxSsh,windowsPolicy,peScanner,apkScanner,machoScanner,packageScanner,vmwareConfig,gns3Topology];
export const scannerCatalog=scanners.map(/** map 콜백: 각 항목을 필요한 값으로 변환합니다 */ ({id,version,targetKind,maxBytes})=>({id,version,targetKind,maxBytes}));
/** scannerFor: 등록된 모듈 식별자에 맞는 검사기를 찾습니다 주요 호출: find. */ export function scannerFor(id:unknown){const module=scanners.find(/** find 콜백: 조건에 맞는 첫 항목을 찾습니다 */ s=>s.id===id);if(!module)throw new Error('MODULE_UNSUPPORTED');return module;}
/** runAssessment: 선택한 모듈을 실행하고 입력 검증 근거를 결과에 연결합니다 주요 호출: inspectOriginal·scannerFor·throwIfAborted. */ export async function runAssessment(input:AssessmentInput,context:AssessmentContext){
 if(input.originalUpload)return inspectOriginal(input,context);
 const scanner=scannerFor(input.moduleId);context.signal.throwIfAborted();scanner.validate(input);
 const result=await scanner.scan(input,context);context.signal.throwIfAborted();
 if(input.snapshot!==undefined)result.integrity={status:'unverified-summary'};
 else if(input.moduleId!=='web.compare'){
  const bytes=input.text!==undefined?Buffer.from(input.text,'utf8'):binaryInput(input);
  result.integrity={status:'server-recomputed',basis:input.text!==undefined?'received-utf8-text':'received-file-bytes',sha256:createHash('sha256').update(bytes).digest('hex'),bytes:bytes.length};
 }
 return result;
}
