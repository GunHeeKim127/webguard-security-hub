import {Pool} from 'pg';
import {projectDatabase} from '../lib/project-database';
import {releaseAccountBlock} from '../lib/account-block-management';
const id=process.argv[2];if(!id||!/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(id))throw new Error('Provide one account UUID');
const pool=new Pool(projectDatabase('migration'));
try{console.log(await releaseAccountBlock(/** releaseAccountBlock 콜백: releaseAccountBlock에서 전달한 값을 처리하는 콜백입니다 주요 호출: query. */ (sql,values)=>pool.query(sql,values),id,null)?'Account block reset; sessions revoked and local recovery audit recorded.':'No matching active account block.');}finally{await pool.end();}
