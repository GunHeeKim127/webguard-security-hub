import {createHash} from 'node:crypto';
import {inspectExecutable} from '../../public/tools/executable-inspector.mjs';
import {inspectPackage} from '../../public/tools/package-inspector.mjs';
import {peScanner} from './binary-modules';
import {machoScanner,packageScanner} from './local-modules';
import {binaryInput,checkpoint,pick,type AssessmentInput,type AssessmentContext} from './types';

// Only server-recomputed observations reach the scanner in this path. No client
// hash, native signature assertion, snapshot or integrity claim is accepted.
export async function inspectOriginal(input:AssessmentInput,ctx:AssessmentContext){
 checkpoint(ctx);
 if(input.originalUpload!==true||input.snapshot!==undefined||input.text!==undefined||input.url!==undefined)throw new Error('INPUT_INVALID');
 const scanner=input.moduleId==='application.pe'?peScanner:input.moduleId==='application.macho'?machoScanner:input.moduleId==='application.package'?packageScanner:null;
 if(!scanner)throw new Error('INPUT_INVALID');
 const bytes=binaryInput(input),source={size:bytes.length,read:async(offset:number,length:number)=>{checkpoint(ctx);return new Uint8Array(bytes.subarray(offset,offset+length));}};
 const snapshot=input.moduleId==='application.package'?await inspectPackage(source):await inspectExecutable(source,input.moduleId==='application.pe'?'pe':'macho');
 const report=await scanner.scan({moduleId:input.moduleId,label:input.label,snapshot},ctx);checkpoint(ctx);
 report.integrity={status:'server-recomputed',basis:'received-file-bytes',sha256:createHash('sha256').update(bytes).digest('hex'),bytes:bytes.length};
 report.scope=[pick(ctx,'동의 후 전송된 원본 바이트를 서버에서 재분석 · 최대 2 MiB','Server analysis of explicitly uploaded original bytes · max 2 MiB')];
 report.limitations=[pick(ctx,'수신 파일과 결과를 SHA-256으로 연결합니다. 기기의 다른 원본과 동일함·배포자 진위·OS 서명 신뢰·악성코드 부재는 증명하지 않습니다. 원본은 앱 DB에 저장하거나 실행하지 않습니다.','SHA-256 binds this result to received bytes, not another file on the device, publisher authenticity, OS signature trust or absence of malware. Originals are not stored in the app database or executed.')];
 report.findings=report.findings.filter(f=>f.id!=='provenance');
 for(const f of report.findings){
  if(f.id==='package-inventory'){
   f.evidence=f.evidence.filter(v=>!v.startsWith('source=')).concat('source=server-recomputed');
   f.remediation=pick(ctx,'수신 원본의 구조 관찰입니다. 서명 신뢰·설치 가능성·안전성은 별도 검증이 필요합니다.','Structure observed from received original bytes. Signature trust, installability and safety require separate verification.');
  }
 }
 return report;
}
