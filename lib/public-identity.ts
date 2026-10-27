// Apply at server response/RSC boundaries; never send raw values and hide with CSS.
export type PublicUser={email:string,role:string};
export function maskEmail(value:string){
 const at=value.lastIndexOf('@');if(at<1||at===value.length-1)return '***';
 const local=Array.from(value.slice(0,at))[0],domain=value.slice(at+1),dot=domain.lastIndexOf('.');
 const suffix=dot>0&&/^[a-z]{2,24}$/i.test(domain.slice(dot+1))?'.'+domain.slice(dot+1):'';
 return local+'***@***'+suffix;
}
export function publicUser(user:{email:string,role:string}):PublicUser{return {email:maskEmail(user.email),role:user.role};}
export function publicIpBlock(row:{management_id:string,address:string,strikes:number,blacklisted:boolean,blocked_until:string|null,last_reason:string,last_seen:string}){
 return {blockId:row.management_id,address:row.address.includes(':')?'****:****:****:****':'***.***.***.***',strikes:row.strikes,blacklisted:row.blacklisted,blocked_until:row.blocked_until,last_reason:row.last_reason,last_seen:row.last_seen};
}
export function publicAccountBlock(row:{management_id:string,email:string,strikes:number,blacklisted:boolean,last_reason:string,last_seen:string}){
 return {blockId:row.management_id,email:maskEmail(row.email),strikes:row.strikes,blacklisted:row.blacklisted,last_reason:row.last_reason,last_seen:row.last_seen};
}
const eventNames=new Set(['login_failed','login_success','scan_rejected','scan_completed','ai_advice','decoy_visit','suspicious_path','threat_blocked','ip_blacklisted','ip_unblocked','registration_requested','assessment_completed','assessment_rejected','telemetry_key_rotated','account_blacklisted','account_threat_recorded','account_unblocked','account_unblocked_local']);
export function publicEventCategory(category:string){
 if(/^ip_unblocked_target:[a-f0-9]{64}$/.test(category))return 'ip_unblocked_audit';
 if(/^account_unblocked_target:[a-f0-9]{64}$/.test(category))return 'account_unblocked_audit';
 return eventNames.has(category)?category:'other';
}
export function publicEvents(rows:{category:string,count:number}[]){
 const counts=new Map<string,number>();for(const row of rows){const key=publicEventCategory(row.category);counts.set(key,(counts.get(key)??0)+Number(row.count));}
 return [...counts].map(([category,count])=>({category,count}));
}
