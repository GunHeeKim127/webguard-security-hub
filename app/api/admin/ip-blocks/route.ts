import {body,sameOrigin,requireUser,limit,failure,HttpError} from '../../../../lib/security';
import {db} from '../../../../lib/db';
import {releaseIpBlock} from '../../../../lib/ip-block-management';
export const runtime='nodejs';
export const dynamic='force-dynamic';
export async function POST(req:Request){try{
 sameOrigin(req);const admin=await requireUser(['admin']);await limit('admin:ip-release:'+admin.id,10,60);
 const data=await body(req);
 if(Object.keys(data).some(k=>!['action','blockId'].includes(k))||data.action!=='release'||typeof data.blockId!=='string'||!/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(data.blockId))throw new HttpError(400,'Invalid request');
 const target=(await db.query('SELECT host(address) AS address FROM public.ip_blocks WHERE management_id=$1::uuid',[data.blockId])).rows[0];
 if(!target||!await releaseIpBlock((sql,values)=>db.query(sql,values),target.address,admin.id,data.blockId))throw new HttpError(404,'Not found');
 return Response.json({released:true},{headers:{'Cache-Control':'no-store'}});
 }catch(error){return failure(error,req);}}
