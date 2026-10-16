import { event,limit,failure } from '../../lib/security';
export async function GET(){try{await limit('decoy:global',60,60);await event('decoy_visit');return new Response('Resource unavailable',{status:404,headers:{'Cache-Control':'no-store','Content-Type':'text/plain; charset=utf-8'}});}catch(e){return failure(e);}}
