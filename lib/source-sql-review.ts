import type {Finding} from './assessment/types';
type Token={kind:'word'|'string'|'symbol',value:string,line:number,interpolated?:boolean};
// Bounded lexical hints, not an AST, taint analysis or a database connection.
function tokenize(text:string):Token[]{
 const out:Token[]=[];let i=0,line=1;const php=/<\?php\b/i.test(text);
 while(i<text.length){const c=text[i];
  if(/\s/.test(c)){if(c==='\n')line++;i++;continue;}
  if(text.startsWith('//',i)||c==='#'||text.startsWith('--',i)){while(i<text.length&&text[i]!=='\n')i++;continue;}
  if(text.startsWith('/*',i)){i+=2;while(i<text.length&&!text.startsWith('*/',i)){if(text[i++]==='\n')line++;}i+=2;continue;}
  const startLine=line;
  const dollar=/^\$(?:[a-z_][a-z0-9_]*)?\$/i.exec(text.slice(i));
  if(dollar){const end=text.indexOf(dollar[0],i+dollar[0].length);if(end>=0){const value=text.slice(i+dollar[0].length,end);line+=(value.match(/\n/g)??[]).length;out.push({kind:'string',value,line:startLine});i=end+dollar[0].length;continue;}}
  if(c==='"'||c==="'"||c==='`'){let value='';i++;
   while(i<text.length){const n=text[i++];if(n==='\n')line++;if(n==='\\'&&i<text.length){value+=n+text[i++];continue;}if(n===c){if(text[i]===c&&c!=='`'){value+=c;i++;continue;}break;}value+=n;}
   out.push({kind:'string',value,line:startLine,interpolated:c==='`'?/(?<!\\)\$\{/.test(value):c==='"'&&php&&/(?<!\\)\$[a-z_{]/i.test(value)});continue;
  }
  const word=/^[\w$]+/.exec(text.slice(i));if(word){out.push({kind:'word',value:word[0],line});i+=word[0].length;}else{out.push({kind:'symbol',value:c,line});i++;}
 }return out;
}
function argument(ts:Token[],start:number){let depth=0;const result:Token[]=[];
 for(let i=start;i<ts.length&&result.length<512;i++){const v=ts[i].value;if(depth===0&&[',',')',';'].includes(v))break;if(['(','[','{'].includes(v))depth++;if([')',']','}'].includes(v))depth--;result.push(ts[i]);}return result;
}
const sqlHint=(v:string)=>/\b(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|CREATE\s+TABLE|GRANT|REVOKE)\b/i.test(v);
export function sourceSqlFindings(text:string,locale:'ko'|'en'):Finding[]{
 const t=(ko:string,en:string)=>locale==='ko'?ko:en,ts=tokenize(text),findings:Finding[]=[];
 const add=(id:string,line:number,status:Finding['status'],ko:string,en:string,fixKo:string,fixEn:string)=>findings.push({id:'source:sql:'+id,title:t(ko,en)+(line?t(` · ${line}행`,` · line ${line}`):''),status,severity:status==='warning'?'medium':'info',evidence:[`line=${line}`,'analysis=lexical-hint','exploitTested=false','deploymentVerified=false'],remediation:t(fixKo,fixEn)});
 let calls=0;
 for(let i=0;i<ts.length&&calls<32;i++){
  const api=ts[i].value;if(ts[i].kind!=='word'||!/^(?:query|execute|prepare|raw|mysqli_query|pg_query|pg_query_params|\$queryRawUnsafe|\$executeRawUnsafe|\$queryRaw|\$executeRaw)$/i.test(api))continue;
  const tagged=ts[i+1]?.kind==='string'&&/^\$(?:query|execute)Raw$/.test(api);
  if(!tagged&&ts[i+1]?.value!=='(')continue;
  let expr=tagged?[ts[i+1]]:argument(ts,i+2);
  if(/^(?:mysqli_query|pg_query|pg_query_params)$/.test(api)&&ts[i+2+expr.length]?.value===',')expr=argument(ts,i+3+expr.length);
  if(expr.length===1&&expr[0].kind==='word'){
   const name=expr[0].value,assignments=ts.slice(0,i).map((v,k)=>v.value===name&&ts[k+1]?.value==='='&&ts[k+2]?.value!=='='?k:-1).filter(k=>k>=0);
   if(assignments.length===1)expr=argument(ts,assignments[0]+2);
  }
  const hasSql=expr.some(v=>v.kind==='string'&&sqlHint(v.value));
  if(!hasSql&&expr.length===1&&expr[0].kind==='string')continue;
  calls++;
  // Prisma's tagged templates bind interpolations; Unsafe calls do not.
  const objectConfig=expr[0]?.value==='{';
  const rawFragment=tagged&&expr.some(v=>/\$\{[^}]*\b(?:raw|unsafe)\s*\(/i.test(v.value));
  const dynamic=hasSql&&(rawFragment||!tagged&&!objectConfig&&(expr.some(v=>v.interpolated)||expr.length>1&&expr.some(v=>v.kind!=='string'&&!['(',')'].includes(v.value))));
  if(dynamic)add('dynamic-'+calls,ts[i].line,'warning','SQL 문장에 값이 섞이는 조합 흔적','Possible dynamic SQL construction','SQL 인수에서 템플릿 삽입·문자열 연결을 관찰했습니다. 외부 입력인지 확정된 것은 아닙니다. 값은 PostgreSQL $1 또는 드라이버의 ? 매개변수로 분리하고 식별자·정렬은 고정 허용 목록을 사용하세요. PHP PDO는 prepare 후 execute에 값을 따로 전달하세요.','Interpolation or concatenation was observed; external input flow is unverified. Bind values separately with PostgreSQL $1 or driver ? parameters, allowlist identifiers and ordering, and connect PDO prepare to execute with separate values.');
  else if(/Unsafe$/.test(api))add('unsafe-'+calls,ts[i].line,'warning','ORM의 Unsafe SQL 실행 API 사용','Unsafe ORM SQL execution API','현재 인수가 고정이어도 이후 변경 시 위험합니다. 매개변수화된 tagged template 등 안전한 API를 사용하고 외부 입력으로 SQL 조각을 받지 마세요.','Even a currently constant argument is fragile. Prefer parameterized tagged templates and never accept external SQL fragments.');
  else if(hasSql)add('binding-'+calls,ts[i].line,'info','SQL 호출 흔적 · 바인딩 연결 확인 필요','SQL call observed; verify binding flow','SQL 문장 흔적이 있습니다. 고정 문장이나 prepare만으로 안전을 보증하지 않습니다. 모든 외부 값이 별도 매개변수로 전달되는지와 prepare-to-execute 연결, 다른 고객 자산 접근 거절을 추가 검증하세요.','SQL syntax was observed. Constant SQL or prepare alone does not prove safety. Verify binding of all external values, prepare-to-execute flow and rejection of another customer’s asset ID.');
  else add('unresolved-'+calls,ts[i].line,'not_assessed','SQL 호출 후보의 실제 문장 미확인','Candidate SQL call has unresolved statement','호출 이름만으로 SQL 사용을 확정하지 않습니다. 드라이버 종류와 문장 생성부터 실행까지의 코드 및 매개변수 전달 부분을 추가하세요.','An API name alone does not establish SQL use. Supply the driver type, statement construction, execution and parameter-binding code.');
 }
 const rawSql=ts[0]?.kind==='word'&&/^(?:SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|GRANT|REVOKE|BEGIN)$/i.test(ts[0].value);
 if(rawSql){let statement:Token[]=[];const statements:Token[][]=[];for(const token of ts){if(token.value===';'){statements.push(statement);statement=[];}else statement.push(token);}statements.push(statement);
  for(const s of statements.slice(0,64)){const joined=s.filter(v=>v.kind!=='string').map(v=>v.value.toUpperCase()).join(' '),line=s[0]?.line??0;
   if(/^GRANT\b/.test(joined)&&/\bTO PUBLIC\b/.test(joined)&&/\b(?:ALL|CREATE|INSERT|UPDATE|DELETE|TRUNCATE|EXECUTE)\b/.test(joined))add('public-grant-'+line,line,'warning','PUBLIC에 변경·실행 권한 부여 흔적','Mutation or execution privilege granted to PUBLIC','PUBLIC은 모든 DB 역할에 적용됩니다. 필요한 실행 역할에 테이블·열·함수 권한만 명시적으로 부여하고 실제 ACL·기본 권한을 별도 확인하세요.','PUBLIC includes every role. Grant only necessary table, column and function privileges to the application role; verify effective ACLs and default privileges separately.');
   if(/\bSECURITY DEFINER\b/.test(joined)&&!/\bSET SEARCH_PATH\b/.test(joined))add('definer-'+line,line,'warning','권한 상승 함수의 고정 검색 경로 미확인','Definer function has no observed fixed search path','이 문장에서 SET search_path를 확인하지 못했습니다. 신뢰한 스키마로 경로를 고정하고 객체 이름에 스키마를 명시하세요. 함수 소유자·실행 권한과 별도 ALTER 설정도 확인하세요. 달러 인용 본문은 별도 검토가 필요합니다.','No SET search_path was observed in this statement. Fix the path to trusted schemas, qualify objects and review owner/EXECUTE grants and separate ALTER settings. Dollar-quoted bodies require separate review.');
  }
 }
 if(/(?:postgres(?:ql)?|mysql):\/\/[^\s'"`]+@/i.test(text))add('credential',0,'warning','소스에 DB 인증 URL 형태 관찰','Database credential URL pattern observed','인증 URL 원문은 표시하지 않습니다. 비밀 설정으로 분리하고 실제 값이 공개됐다면 자격증명을 교체하세요. 주석·예시일 수도 있어 사용 여부는 확인이 필요합니다.','The URL is redacted. Move credentials into private configuration; rotate real published values. Comments or examples may match, so verify actual use.');
 add('coverage',0,'not_assessed',calls||rawSql?'SQL 검토 범위와 추가 자료':'이 파일에서 SQL 호출을 확인하지 못함',calls||rawSql?'SQL review scope and required evidence':'No SQL call established in this file',calls||rawSql?'한 파일의 정적 단서만 검사했습니다. DB 실행 권한·TLS·백업 테이블 접근·고객별 조회 조건·실제 입력 경로는 미검증입니다. 민감 값을 지운 권한 내역과 관련 API·쿼리 코드를 추가하세요.':'SQL 호출이 안 보인다고 DB를 사용하지 않거나 안전하다는 뜻은 아닙니다. 실제 DB 접근 코드와 매개변수 전달 부분을 추가하세요.',calls||rawSql?'Only static hints in one file were reviewed. Runtime privileges, TLS, backup access, tenant filters and input flow remain unverified. Supply redacted grants and related API/query code.':'No observed call does not establish absence of a database or safety. Supply actual DB access and parameter-binding code.');
 const coverage=findings.find(f=>f.id==='source:sql:coverage');coverage?.evidence.push(`sqlCallsObserved=${calls}`,`sqlDocumentObserved=${!!rawSql}`);
 return findings;
}
