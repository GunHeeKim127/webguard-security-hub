import {db} from '../../../../lib/db';
import {maintenanceAuthorized,archiveDiagnostics} from '../../../../lib/retention';
export const runtime='nodejs';
export const dynamic='force-dynamic';
export const maxDuration=60;
export async function GET(req:Request){
 const headers={'Cache-Control':'no-store'};
 if(!process.env.CRON_SECRET||process.env.CRON_SECRET.length<32)return Response.json({code:'MAINTENANCE_NOT_CONFIGURED'},{status:503,headers});
 if(!maintenanceAuthorized(req.headers.get('authorization'),process.env.CRON_SECRET))return Response.json({code:'UNAUTHORIZED'},{status:401,headers});
 try{
  let moved=0,complete=false;const deadline=Date.now()+45000;
  for(let batch=0;batch<20&&Date.now()<deadline;batch++){
   const result=await archiveDiagnostics(sql=>db.query(sql)) as {moved:number,skipped:boolean};
   moved+=result.moved;if(result.skipped||result.moved===0){complete=!result.skipped;break;}
  }
  return Response.json({ok:true,result:{moved,complete}},{headers});
 }
 catch{return Response.json({code:'ARCHIVE_UNAVAILABLE'},{status:503,headers});}
}
