import ipaddr from 'ipaddr.js';
export function approvedHosts(raw=process.env.ALLOWED_SCAN_HOSTS??''){
 return [...new Set(raw.split(',').map(value=>value.trim().toLowerCase()).filter(host=>host.length<=253&&host.includes('.')&&!ipaddr.isValid(host)&&host.split('.').every(label=>/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))))].slice(0,100);
}
