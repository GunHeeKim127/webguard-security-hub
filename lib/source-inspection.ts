import {createHash} from 'node:crypto';
import {technologyFindings,reactPackageFindings,technologyCatalogVersion,type TechnologyObservation} from './web-technology';
import type {AssessmentReport,Finding} from './assessment/types';
import {sourceSqlFindings} from './source-sql-review';
const object=(v:unknown):v is Record<string,unknown>=>!!v&&typeof v==='object'&&!Array.isArray(v);
const packages=['react','react-dom','next','react-server-dom-webpack','react-server-dom-parcel','react-server-dom-turbopack','typescript'] as const;
const exact=(v:unknown)=>typeof v==='string'&&/^\d{1,4}\.\d{1,4}\.\d{1,4}$/.test(v)?v:null;
export function inspectSource(text:string,locale:'ko'|'en'):AssessmentReport{
 if(typeof text!=='string'||!text.trim()||Buffer.byteLength(text)>65536||text.includes('\0'))throw new Error('INPUT_INVALID');
 const t=(ko:string,en:string)=>locale==='ko'?ko:en,findings:Finding[]=[],observations:TechnologyObservation['products']=[],versions=new Map<string,Set<string|null>>(),languages=new Set<string>();
 const add=(name:string,value:unknown)=>{if(!packages.includes(name as typeof packages[number]))return;const entries=versions.get(name)??new Set();entries.add(exact(value));versions.set(name,entries);};
 let parsed:unknown;
 if(/^[\s\uFEFF]*[\[{]/.test(text)){try{parsed=JSON.parse(text.replace(/^\uFEFF/,''));}catch{throw new Error('INPUT_INVALID');}}
 if(object(parsed)){
  for(const group of ['dependencies','devDependencies','optionalDependencies'])if(object(parsed[group]))for(const [name,value]of Object.entries(parsed[group]))add(name,object(value)?value.version:value);
  if(object(parsed.packages))for(const [path,value]of Object.entries(parsed.packages)){if(!object(value))continue;const name=path.split('node_modules/').at(-1);if(name)add(name,value.version);}
  if(object(parsed.require)&&('php' in parsed.require||Object.keys(parsed.require).some(k=>k.includes('/'))))languages.add('PHP');
  if(object(parsed.config)&&object(parsed.config.platform)&&'php' in parsed.config.platform)languages.add('PHP');
  if(object(parsed.runtime)){if('php' in parsed.runtime){languages.add('PHP');observations.push({product:'PHP',language:'PHP',version:exact(parsed.runtime.php)});}if('node' in parsed.runtime)observations.push({product:'Node.js',language:'JavaScript / TypeScript',version:exact(parsed.runtime.node)});}
  if(object(parsed.engines)&&'node' in parsed.engines&&!observations.some(p=>p.product==='Node.js'))observations.push({product:'Node.js',language:'JavaScript / TypeScript',version:null});
 }else if(parsed!==undefined)throw new Error('INPUT_INVALID');
 else {
  if(/<\?php\b/i.test(text))languages.add('PHP');
  // Syntax hints only: do not execute code or infer server use from a file suffix.
  if(/\b(?:import\s|export\s|(?:const|let|var)\s+[$\w]+|function\s*[$\w]*\s*\()/.test(text))languages.add('JavaScript / TypeScript');
  if(/(?:from\s*|require\s*\(\s*)['"]react(?:\/[^'"]*)?['"]/.test(text)){add('react',null);languages.add('JavaScript / TypeScript');}
  if(/(?:from\s*|require\s*\(\s*)['"]next(?:\/[^'"]*)?['"]/.test(text)){add('next',null);languages.add('JavaScript / TypeScript');}
 }
 if(parsed===undefined)findings.push(...sourceSqlFindings(text,locale));
 for(const [name,values]of versions){languages.add('JavaScript / TypeScript');const version=values.size===1?[...values][0]:null;
  findings.push({id:'source:package:'+name,title:t('의존성 선언: ','Declared dependency: ')+name,status:'info',severity:'info',evidence:[`product=${name}`,`declaredVersion=${version??'unknown'}`,'runtimeVerified=false'],remediation:t('제공된 파일의 선언입니다. 실제 설치·배포 목록과 대조하세요. 버전 범위·충돌 값은 정확한 설치 버전으로 취급하지 않습니다.','A declaration from the supplied file. Compare with installed deployment inventory. Ranges or conflicts are not exact installed versions.')});
  findings.push(...reactPackageFindings(name,version,locale));
 }
 if(versions.has('next'))observations.push({product:'Next.js',language:'JavaScript / TypeScript',version:null});
 if(versions.has('react')&&!versions.has('next')&&!packages.filter(p=>p.startsWith('react-server-dom-')).some(p=>versions.has(p)))findings.push({id:'source:rsc-applicability',title:t('React 서버 기능 사용 여부 미확인','React server-feature usage unknown'),status:'not_assessed',severity:'info',evidence:['reactCoreDeclared=true','rscUsageVerified=false'],remediation:t('React 코어 선언만으로 RSC 사용을 판단하지 않습니다. 서버 기능을 사용한다면 실제 react-server-dom 패키지와 버전 자료를 추가하세요. 브라우저 전용 React에는 서버 전용 취약점을 적용하지 않습니다.','React core does not establish RSC usage. If server features are used, provide the deployed react-server-dom package and version. Server-only issues do not apply to client-only React.')});
 if(languages.has('PHP')&&!observations.some(p=>p.product==='PHP'))observations.push({product:'PHP',language:'PHP',version:null});
 for(const language of languages)findings.unshift({id:'source:language:'+language,title:t('언어 단서: ','Language hint: ')+language,status:'info',severity:'info',evidence:[`languageHint=${language}`,'syntaxOrDeclarationOnly=true'],remediation:t('문법·의존성 선언의 단서입니다. 주석·혼합 언어·생성 파일일 수 있어 실제 실행 언어를 확정하지 않습니다.','Syntax or dependency hints only. Comments, mixed languages or generated files may differ from actual runtime.')});
 if(observations.length)for(const f of technologyFindings({catalogVersion:technologyCatalogVersion,responseEligible:true,products:observations},locale)){
  if(f.id==='technology:coverage')continue;
  findings.push({...f,id:'source:'+f.id,evidence:[...f.evidence,'evidenceSource=supplied-source'],remediation:f.remediation+' '+t('이 자료는 파일의 선언·문법에 한정됩니다. Node.js 및 RSC 사용 여부를 실제 배포에서 확인하세요.','Evidence is limited to supplied declarations / syntax. Confirm Node.js and RSC usage in the actual deployment.')});
 }
 findings.push({id:'source:coverage',title:t('추가로 필요한 확인 자료','Additional verification evidence'),status:'not_assessed',severity:'info',evidence:[`recognizedLanguages=${languages.size}`,`recognizedPackages=${versions.size}`],remediation:t('소스 한 파일로 전체 코드를 보안 감사하지 않습니다. PHP는 실제 php --version, Node.js는 node --version, React·Next.js는 실제 배포 잠금 파일과 react-server-dom 패키지 버전·서버 기능 사용 자료가 필요합니다. JavaScript 문법만으로 Node.js·RSC 사용을 확정하지 않습니다.','One source file is not a full code security audit. Obtain deployed php --version, node --version, deployment lockfile, react-server-dom versions and server-feature usage. JavaScript syntax alone does not establish Node.js or RSC usage.')});
 return {schemaVersion:1,moduleId:'web.compare',moduleVersion:'source-1.1.0',ruleVersion:technologyCatalogVersion,targetKind:'supplied-source',observedAt:new Date().toISOString(),findings,scope:[t('명시적으로 제공한 UTF-8 파일 한 개 · 최대 64 KiB · 문법/의존성 선언 정적 검토','One explicitly supplied UTF-8 file up to 64 KiB; static syntax / dependency review')],limitations:[t('실행·외부 요청·전체 SAST·실제 배포 상태·침해 여부는 미검증. 원문과 결과를 저장하지 않습니다.','No execution, external requests, full SAST, live deployment attestation or compromise testing. Source and results are not stored.')],integrity:{status:'server-recomputed',basis:'received-utf8-text',sha256:createHash('sha256').update(text,'utf8').digest('hex'),bytes:Buffer.byteLength(text)}};
}
