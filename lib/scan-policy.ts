import ipaddr from 'ipaddr.js';
/** targetPolicy: 현재 대상 점검 정책을 결정합니다 */ export function targetPolicy(){const policy=process.env.SCAN_TARGET_POLICY??'public';if(policy!=='public'&&policy!=='approved')throw new Error('Invalid SCAN_TARGET_POLICY');return policy;}
/** scanTarget: 점검 대상 URL의 형식과 접근 정책을 검증합니다 주요 호출: isValid·replace·includes. */ export function scanTarget(raw:string,allowed?:string[]){
 const u=new URL(raw);
 if(u.protocol!=='https:'||u.username||u.password||(u.port&&u.port!=='443')||u.pathname!=='/'||u.search||u.hash)throw new Error('Only HTTPS origin on port 443 is allowed');
 if(ipaddr.isValid(u.hostname.replace(/^\[|\]$/g,''))||!u.hostname.includes('.')||u.hostname.length>253||!u.hostname.split('.').every(/** every 콜백: 모든 항목이 조건을 만족하는지 확인합니다 */ label=>/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))||(allowed&&!allowed.includes(u.hostname)))throw new Error('Hostname is not allowed');
 return u;
}
/** approvedHosts: 허용된 점검 호스트 목록을 읽습니다 주요 호출: slice·filter·map. */ export function approvedHosts(raw=process.env.ALLOWED_SCAN_HOSTS??''){
 return [...new Set(raw.split(',').map(/** map 콜백: 각 항목을 필요한 값으로 변환합니다 주요 호출: toLowerCase·trim. */ value=>value.trim().toLowerCase()).filter(/** filter 콜백: 조건에 맞는 항목만 고릅니다 주요 호출: includes·isValid·every. */ host=>host.length<=253&&host.includes('.')&&!ipaddr.isValid(host)&&host.split('.').every(/** every 콜백: 모든 항목이 조건을 만족하는지 확인합니다 */ label=>/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))))].slice(0,100);
}
