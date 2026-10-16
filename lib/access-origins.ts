export function accessOrigins(env:Readonly<Record<string,string|undefined>>=process.env){
 // The production host comes only from server configuration, never from request headers.
 const production=env.VERCEL==='1'&&env.VERCEL_ENV==='production'?'https://webguard-security-hub.vercel.app':'';
 const values=[env.APP_ORIGIN??production,...(env.APP_ADDITIONAL_ORIGINS??'').split(',')].map(v=>v.trim()).filter(Boolean);
 return [...new Set(values.map(raw=>{const url=new URL(raw);if(!['http:','https:'].includes(url.protocol)||url.username||url.password||url.pathname!=='/'||url.search||url.hash||url.hostname.includes('*'))throw new Error('Invalid application origin');return url.origin;}))];
}
export function secureOriginCookie(req:Request){
 const origin=req.headers.get('origin');if(!origin||!accessOrigins().includes(origin))throw new Error('Untrusted cookie origin');return origin.startsWith('https:');
}
