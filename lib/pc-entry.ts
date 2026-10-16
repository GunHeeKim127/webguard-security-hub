// Optional Vercel landing redirect. The database stays on the user's PC.
export function pcEntryRedirects(env:Readonly<Record<string,string|undefined>>=process.env){
 if(env.VERCEL!=='1'||!env.PC_APP_ORIGIN?.trim())return [];
 const url=new URL(env.PC_APP_ORIGIN.trim());
 if(url.protocol!=='https:'||url.username||url.password||url.port||url.pathname!=='/'||url.search||url.hash||!(/^[a-z0-9]+(?:-[a-z0-9]+)*\.trycloudflare\.com$/).test(url.hostname))throw new Error('PC_APP_ORIGIN must be an exact HTTPS Quick Tunnel origin');
 return ['/','/signup'].map(source=>({source,destination:url.origin+source,permanent:false as const}));
}
