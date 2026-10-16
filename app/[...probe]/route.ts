import { suspiciousPath } from '../../lib/traffic';
import { event,limit,failure } from '../../lib/security';
export async function GET(req:Request){try{const path=new URL(req.url).pathname;if(suspiciousPath(path)){await limit('probe:global',60,60);await event('suspicious_path');}return new Response('Resource unavailable',{status:404,headers:{'Content-Type':'text/plain; charset=utf-8','Cache-Control':'no-store'}});}catch(e){return failure(e);}}
