import ipaddr from 'ipaddr.js';
export function targetPolicy(){const policy=process.env.SCAN_TARGET_POLICY??'public';if(policy!=='public'&&policy!=='approved')throw new Error('Invalid SCAN_TARGET_POLICY');return policy;}
export function scanTarget(raw:string,allowed?:string[]){
 const u=new URL(raw);
 if(u.protocol!=='https:'||u.username||u.password||(u.port&&u.port!=='443')||u.pathname!=='/'||u.search||u.hash)throw new Error('Only HTTPS origin on port 443 is allowed');
 if(ipaddr.isValid(u.hostname.replace(/^\[|\]$/g,''))||!u.hostname.includes('.')||u.hostname.length>253||!u.hostname.split('.').every(label=>/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))||(allowed&&!allowed.includes(u.hostname)))throw new Error('Hostname is not allowed');
 return u;
}
export function approvedHosts(raw=process.env.ALLOWED_SCAN_HOSTS??''){
 return [...new Set(raw.split(',').map(value=>value.trim().toLowerCase()).filter(host=>host.length<=253&&host.includes('.')&&!ipaddr.isValid(host)&&host.split('.').every(label=>/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))))].slice(0,100);
}
