import {Pool} from 'pg';
import {projectDatabase} from '../lib/project-database';
import {archiveDiagnostics} from '../lib/retention';
const pool=new Pool({...projectDatabase('migration'),connectionTimeoutMillis:15000,query_timeout:60000});
try{
 for(let batch=0;batch<100;batch++){
  const result=await archiveDiagnostics(/** archiveDiagnostics 콜백: archiveDiagnostics에서 전달한 값을 처리하는 콜백입니다 주요 호출: query. */ sql=>pool.query(sql)) as {moved:number,skipped:boolean};
  console.log(JSON.stringify(result));if(result.skipped||result.moved===0)break;
 }
}catch{console.error('Diagnostic archive failed; no connection secrets are logged.');process.exitCode=1;}
finally{await pool.end();}
