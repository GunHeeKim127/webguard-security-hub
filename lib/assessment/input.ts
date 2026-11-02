import {scannerFor} from './registry';
import {scanTarget,approvedHosts,targetPolicy} from '../scan-policy';
import type {AssessmentInput} from './types';
import {binaryInput} from './types';
/** assessmentInput: 요청 필드와 모듈별 입력 계약을 검증합니다 주요 호출: some·keys·trim. */ export function assessmentInput(data:Record<string,unknown>):AssessmentInput{
 for(const key of ['moduleId','label','url','text','base64'])if(key in data&&typeof data[key]!=='string')throw new Error('INPUT_INVALID');
 if(Object.keys(data).some(/** some 콜백: 조건을 만족하는 항목이 있는지 확인합니다 주요 호출: includes. */ k=>!['moduleId','label','url','text','base64','snapshot','authorized','originalUpload'].includes(k))||data.authorized!==true||typeof data.label!=='string'||!data.label.trim()||data.label.length>80||!/^[\p{L}\p{N} ._()-]+$/u.test(data.label))throw new Error('INPUT_INVALID');
 const module=scannerFor(data.moduleId);
 const input:AssessmentInput={moduleId:module.id,label:data.label.trim(),...(typeof data.url==='string'?{url:data.url}:{}),...(typeof data.text==='string'?{text:data.text}:{}),...(typeof data.base64==='string'?{base64:data.base64}:{}),...(data.snapshot!==undefined?{snapshot:data.snapshot}:{})};
 if('originalUpload' in data){
  if(data.originalUpload!==true||!['application.pe','application.macho','application.package'].includes(module.id)||['snapshot','url','text'].some(/** some 콜백: 조건을 만족하는 항목이 있는지 확인합니다 */ k=>k in data))throw new Error('INPUT_INVALID');
  binaryInput(input);return {...input,originalUpload:true};
 }
 if(input.snapshot!==undefined){if(!['application.pe','application.macho','application.package'].includes(module.id)||['url','text','base64'].some(/** some 콜백: 조건을 만족하는 항목이 있는지 확인합니다 */ k=>k in data)||JSON.stringify(input.snapshot).length>65536)throw new Error('INPUT_INVALID');module.validate(input);return input;}
 if(module.id==='web.compare'){
  if(!input.url||input.url.length>300||input.text!==undefined||input.base64!==undefined)throw new Error('INPUT_INVALID');
  try{input.url=scanTarget(input.url,targetPolicy()==='approved'?approvedHosts():undefined).href;}catch{throw new Error('INPUT_INVALID');}
 }else if(input.url!==undefined||(module.id.startsWith('application.')?input.text!==undefined:input.base64!==undefined))throw new Error('INPUT_INVALID');
 try{module.validate(input);}catch{throw new Error('INPUT_INVALID');}return input;
}
