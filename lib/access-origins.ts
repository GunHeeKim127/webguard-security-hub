/** accessOrigins: 허용 서비스 출처 목록을 구성합니다 주요 호출: filter·map·split. */ export function accessOrigins(env:Readonly<Record<string,string|undefined>>=process.env){
 // The production host comes only from server configuration, never from request headers.
 const production=env.VERCEL==='1'&&env.VERCEL_ENV==='production'?'https://securitywebguard.vercel.app':'';
 const values=[production,env.APP_ORIGIN??'',...(env.APP_ADDITIONAL_ORIGINS??'').split(',')].map(/** map 콜백: 각 항목을 필요한 값으로 변환합니다 주요 호출: trim. */ v=>v.trim()).filter(Boolean);
 return [...new Set(values.map(/** map 콜백: 각 항목을 필요한 값으로 변환합니다 주요 호출: includes. */ raw=>{const url=new URL(raw);if(!['http:','https:'].includes(url.protocol)||url.username||url.password||url.pathname!=='/'||url.search||url.hash||url.hostname.includes('*'))throw new Error('Invalid application origin');return url.origin;}))];
}
/** secureOriginCookie: 서비스 출처에 맞는 보안 쿠키 설정을 계산합니다 주요 호출: get·includes·accessOrigins. */ export function secureOriginCookie(req:Request){
 const origin=req.headers.get('origin');if(!origin||!accessOrigins().includes(origin))throw new Error('Untrusted cookie origin');return origin.startsWith('https:');
}
