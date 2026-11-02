import type {ModuleId} from './types';
export const assessmentCategories=['web','mobile','endpoint','virtualization','network'] as const;
export type AssessmentCategory=typeof assessmentCategories[number];
/** categoryFor: 검사 모듈을 화면의 자산 분류로 연결합니다 주요 호출: includes. */ export function categoryFor(module:ModuleId):AssessmentCategory{return module==='virtualization.vmx'?'virtualization':module==='network.gns3'?'network':module==='web.compare'?'web':['application.package','application.apk'].includes(module)?'mobile':'endpoint';}
