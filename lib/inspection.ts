export type CheckResult={status:number,checks:{header:string,present:boolean}[]};
export type SavedScan={id:string,hostname:string,result:CheckResult,created_at:string};
export type Inspection={state:'idle'|'running'|'success'|'error',target:string,result?:CheckResult,recordId?:string};
export type Operation='refresh'|'scan'|'ai'|'login'|'logout';
export type OperationState={kind:Operation,state:'running'|'success'|'error',at:string}|null;
export type Dashboard={user:{email:string,role:string},scans:SavedScan[],events:{category:string,count:number}[],recentEvents:{category:string,created_at:string}[],aiEnabled:boolean,overview:{approvedCount:number,approvedHosts:string[],savedCount:number,updatedAt:string}};
export function inspectionSummary(inspection:Inspection){
 // A failed/pending attempt never borrows a previous successful result.
 const complete=inspection.state==='success'&&!!inspection.result;
 return {complete,httpStatus:complete?inspection.result!.status:null,missing:complete?inspection.result!.checks.filter(c=>!c.present).length:null};
}
