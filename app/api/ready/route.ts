import {db} from '../../../lib/db';
import {deploymentReadiness} from '../../../lib/deployment-readiness';
export const runtime='nodejs';
export const dynamic='force-dynamic';
export const maxDuration=30;
export async function GET(){
 const result=await deploymentReadiness(sql=>db.query(sql));
 return Response.json({status:result.ready?'ready':'not_ready',code:result.code,...('permissionModel' in result?{permissionModel:result.permissionModel}:{})},{status:result.ready?200:503,headers:{'Cache-Control':'no-store'}});
}
