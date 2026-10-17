import {createInterface} from 'node:readline/promises';
import {Writable} from 'node:stream';
import {Pool} from 'pg';
import {projectDatabase} from '../lib/project-database';
import {hashPassword,tokenHash} from '../lib/password';
import {resetAccountPassword} from './support/reset-account-password';

// Administrative local recovery only. No public reset endpoint or password arguments.
const email=process.argv[2]?.trim().toLowerCase();
if(!email||process.argv.length!==3||!/^\S+@\S+\.\S+$/.test(email)){
 console.error('사용법: npm run user:password:production -- 계정이메일');process.exitCode=1;
}else if(!process.stdin.isTTY){
 console.error('비밀번호 보호를 위해 직접 열린 터미널에서 실행해 주세요.');process.exitCode=1;
}else{
 const output=new Writable({write(_chunk,_encoding,done){done();}});
 const terminal=createInterface({input:process.stdin,output,terminal:true,historySize:0});
 const abort=new AbortController();terminal.on('SIGINT',()=>abort.abort());terminal.on('close',()=>abort.abort());
 let pool:Pool|undefined;
 try{
  console.log(`계정: ${email} / 대상: ${process.env.DATABASE_PROVIDER==='prisma-postgres'?'Prisma 운영 DB':'로컬 PostgreSQL'}`);
  console.log('계정·역할·진단 기록을 유지하고 비밀번호를 변경합니다. 기존 로그인 세션은 종료됩니다.');
  console.log('입력하는 비밀번호는 화면에 표시하거나 파일에 저장하지 않습니다. # 등 특수문자는 그대로 입력하세요.');
  process.stdout.write('새 비밀번호 (14~128자): ');const password=await terminal.question('',{signal:abort.signal});process.stdout.write('\n');
  process.stdout.write('새 비밀번호 다시 입력: ');const confirmation=await terminal.question('',{signal:abort.signal});process.stdout.write('\n');
  if(password!==confirmation)throw new Error('PASSWORD_MISMATCH');
  if(password.length<14||password.length>128)throw new Error('PASSWORD_LENGTH');
  const hash=hashPassword(password);
  pool=new Pool({...projectDatabase('migration'),max:1,connectionTimeoutMillis:12000});
  const client=await pool.connect();try{await resetAccountPassword(client,email,hash,tokenHash(email));}finally{client.release();}
  console.log('변경 완료. 사이트에서 새 비밀번호로 로그인해 주세요. 기존 계정·권한·진단 기록은 유지했습니다.');
 }catch(error){
  const code=error instanceof Error?error.message:'';
  console.error(code==='PASSWORD_MISMATCH'?'두 비밀번호가 일치하지 않습니다. 변경하지 않았습니다.':code==='PASSWORD_LENGTH'?'비밀번호는 14~128자여야 합니다. 변경하지 않았습니다.':code==='ACCOUNT_NOT_FOUND'?'해당 DB에 등록된 계정이 없습니다. 새 계정을 생성하지 않았습니다.':abort.signal.aborted?'입력을 취소했습니다.':'변경 실패. DB 연결·관리 권한과 환경설정을 확인해 주세요.');process.exitCode=1;
 }finally{terminal.close();output.end();await pool?.end();}
}
