import type {ModuleId} from './types';
export const assessmentCategories=['web','mobile','endpoint','virtualization','network'] as const;
export type AssessmentCategory=typeof assessmentCategories[number];
export function categoryFor(module:ModuleId):AssessmentCategory{return module==='virtualization.vmx'?'virtualization':module==='network.gns3'?'network':module==='web.compare'?'web':['application.package','application.apk'].includes(module)?'mobile':'endpoint';}
