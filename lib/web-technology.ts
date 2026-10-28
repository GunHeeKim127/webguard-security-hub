import type {Finding} from './assessment/types';
type Headers=Record<string,string|string[]|undefined>;
type Product='PHP'|'Next.js'|'React RSC'|'Django'|'Spring'|'Java servlet'|'ASP.NET'|'Ruby on Rails'|'Node.js'|'Go';
export const technologyCatalogVersion='2026-10-28.1' as const;
export type TechnologyObservation={catalogVersion:string,responseEligible:boolean,products:{product:Product,language:string,version:string|null}[]};
const header=(headers:Headers,key:string)=>{const v=headers[key];return (Array.isArray(v)?v.join(','):v??'').slice(0,16384);};
// Hints only. Never retain cookie identities/values or arbitrary server banners.
export function observeTechnology(headers:Headers,status:number):TechnologyObservation{
 const products:TechnologyObservation['products']=[],powered=header(headers,'x-powered-by'),server=header(headers,'server');
 const add=(product:Product,language:string,pattern:RegExp,text=powered)=>{
  const matches=[...text.matchAll(new RegExp(pattern.source,'ig'))];
  if(matches.length){const versions=new Set(matches.map(m=>m[1]&&/^\d{1,4}\.\d{1,4}\.\d{1,4}$/.test(m[1])?m[1]:null));products.push({product,language,version:versions.size===1?[...versions][0]:null});}
 };
 add('PHP','PHP',/\bPHP(?:\/([\d.]+)(?=$|[\s,;]))?\b/i,powered+' '+server);
 add('Next.js','JavaScript / TypeScript',/\bNext\.js\b/i);
 if(/(?:^|,)\s*rsc\s*(?:,|$)/i.test(header(headers,'vary')))products.push({product:'React RSC',language:'JavaScript / TypeScript',version:null});
 add('Django','Python',/\bDjango(?:\/([\d.]+)(?=$|[\s,;]))?\b/i);
 add('Spring','Java / JVM',/\bSpring(?:\/([\d.]+)(?=$|[\s,;]))?\b/i);
 add('Java servlet','Java / JVM',/\b(?:Servlet|Tomcat)\b/i,powered+' '+server);
 add('ASP.NET','C# / .NET (language unconfirmed)',/\bASP\.NET\b/i);
 if(header(headers,'x-aspnet-version')&&!products.some(p=>p.product==='ASP.NET'))products.push({product:'ASP.NET',language:'C# / .NET (language unconfirmed)',version:null});
 add('Ruby on Rails','Ruby',/\b(?:Ruby|Rails)\b/i);
 // Express has its own version; never interpret that as the Node.js runtime version.
 add('Node.js','JavaScript / TypeScript',/\bNode\.js(?:\/v?([\d.]+(?:[-+][^\s,;]+)?)(?=$|[\s,;]))?\b/i,powered+' '+server);
 if(/\bExpress\b/i.test(powered)&&!products.some(p=>p.product==='Node.js'))products.push({product:'Node.js',language:'JavaScript / TypeScript',version:null});
 add('Go','Go',/\bGo\b/i);
 return {catalogVersion:technologyCatalogVersion,responseEligible:status>=200&&status<300,products:status>=200&&status<300?products:[]};
}
const php='https://www.php.net/archive/2026.php';
const react='https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components';
const django='https://www.djangoproject.com/weblog/2025/nov/05/security-releases/';
const spring='https://spring.io/security/cve-2022-22965/';
function older(version:string|null,fixes:Record<string,number>):boolean|null{
 if(!version)return null;const [major,minor,patch]=version.split('.').map(Number),fixed=fixes[`${major}.${minor}`];return fixed===undefined?null:patch<fixed;
}
const nodeJanuary='https://nodejs.org/en/blog/vulnerability/december-2025-security-releases';
const nodeOctober='https://nodejs.org/en/blog/vulnerability/october-2026-security-releases';
function nodeOlder(version:string|null,fixes:Record<number,readonly [number,number]>):boolean|null{
 if(!version||!/^\d{1,4}\.\d{1,4}\.\d{1,4}$/.test(version))return null;
 const [major,minor,patch]=version.split('.').map(Number),fix=fixes[major];
 return fix?minor<fix[0]||(minor===fix[0]&&patch<fix[1]):null;
}
type JavascriptRule={id:string;reference:string;ko:string;en:string;fixes?:Record<number,readonly [number,number]>};
const reactRules:JavascriptRule[]=[
 {id:'CVE-2026-23864',reference:'https://github.com/react/react/security/advisories/GHSA-83fc-fqcc-2hmg',ko:'RSC 서비스 중단',en:'RSC denial of service'},
 {id:'CVE-2025-55183',reference:'https://react.dev/blog/2025/12/11/denial-of-service-and-source-code-exposure-in-react-server-components',ko:'서버 함수 소스 노출',en:'Server Function source disclosure'},
 {id:'GHSA-xqc2-xf4c-x3h3',reference:'https://github.com/react/react/security/advisories/GHSA-xqc2-xf4c-x3h3',ko:'RSC 원격 코드 실행',en:'RSC remote code execution'},
 {id:'GHSA-h3gv-c5rc-p453',reference:'https://github.com/react/react/security/advisories/GHSA-h3gv-c5rc-p453',ko:'서버 함수 서비스 중단',en:'Server Function denial of service'},
];
const januaryFixes={20:[20,0],22:[22,0],24:[13,0],25:[3,0]} as const;
const octoberFixes={22:[23,4],24:[22,1],26:[12,1]} as const;
const nodeRules:JavascriptRule[]=[
 {id:'CVE-2025-55131',reference:nodeJanuary,ko:'버퍼 초기화·메모리 노출',en:'Buffer initialization / memory disclosure',fixes:januaryFixes},
 {id:'CVE-2025-55130',reference:nodeJanuary,ko:'파일 접근 권한 우회',en:'Filesystem permission bypass',fixes:januaryFixes},
 {id:'CVE-2025-59465',reference:nodeJanuary,ko:'HTTP/2 서비스 중단',en:'HTTP/2 denial of service',fixes:januaryFixes},
 {id:'CVE-2026-111497',reference:nodeOctober,ko:'Brotli 메모리 손상·코드 실행',en:'Brotli memory corruption / code execution',fixes:octoberFixes},
 {id:'CVE-2026-105482',reference:nodeOctober,ko:'DNS 이름 검증 불일치',en:'DNS hostname validation mismatch',fixes:octoberFixes},
 {id:'CVE-2026-105483',reference:nodeOctober,ko:'TLS 인증서 호스트명 검증 우회',en:'TLS certificate hostname verification bypass',fixes:{24:[22,1],26:[12,1]}},
 {id:'CVE-2026-106069',reference:nodeOctober,ko:'비표준 IP의 TLS 검증 우회',en:'TLS verification bypass for non-canonical IPs',fixes:octoberFixes},
];
export function technologyFindings(observation:TechnologyObservation,locale:'ko'|'en'):Finding[]{
 const t=(ko:string,en:string)=>locale==='ko'?ko:en;
 const findings:Finding[]=[{id:'technology:coverage',title:t('웹 언어·프레임워크 관찰 범위','Web language / framework observation scope'),status:'not_assessed',severity:'info',evidence:[`catalog=${observation.catalogVersion}`,`responseEligible=${observation.responseEligible}`,`observedProducts=${observation.products.length}`],remediation:t('공개 HEAD 헤더의 기술 흔적만 관찰합니다. 숨겨진 언어·내부 의존성·서버 실효 버전·침해 여부·모든 CVE는 확인하지 못합니다. 헤더는 위조될 수 있습니다. 소유 서버의 배포 목록·SBOM과 공식 권고를 별도로 대조하세요.','Only public HEAD header hints are observed. Hidden languages, internal dependencies, effective server versions, compromise and all CVEs are not verified. Headers can be forged. Cross-check an owner-controlled deployment inventory/SBOM and official advisories.')}];
 for(const item of observation.products){
  const base={severity:'info' as const,evidence:[`product=${item.product}`,`languageHint=${item.language}`,`declaredVersion=${item.version??'unknown'}`,'runtimeVerified=false'],remediation:t('기술 흔적이며 실제 사용 언어·버전의 증명이 아닙니다. 서버 배포 목록과 해당 제품의 최신 공식 보안 권고를 확인하세요.','A technology hint, not proof of deployed language/version. Check deployment inventory and current official product advisories.')};
  findings.push({...base,id:'technology:'+item.product,title:t('기술 흔적: ','Technology hint: ')+item.product,status:'info'});
  for(const rule of item.product==='Node.js'?nodeRules:item.product==='React RSC'||item.product==='Next.js'?reactRules:[]){
   // An RSC/Next.js banner never establishes an installed react-server-dom package version.
   const affected=item.product==='Node.js'?nodeOlder(item.version,rule.fixes??{}):null;
   const fixed=item.version&&rule.fixes?.[Number(item.version.split('.')[0])];
   findings.push({...base,id:`technology:${item.product}:${rule.id}`,title:`${rule.id} · ${t(rule.ko,rule.en)}`,status:affected===true?'warning':affected===false?'info':'not_assessed',severity:affected===true?'high':'info',reference:rule.reference,evidence:[...base.evidence,`versionRangeMatch=${affected??'unknown'}`,`catalog=${technologyCatalogVersion}`,...(fixed?[`fixedVersion=${item.version!.split('.')[0]}.${fixed[0]}.${fixed[1]}`]:[]),'exploitTested=false'],remediation:item.product==='Node.js'?t('담당자에게 실제 실행 중인 node --version 결과와 배포 이미지를 요청하세요. 위 공식 공지의 영향 기능과 공급자 백포트를 대조하세요. Express 버전은 Node.js 버전이 아닙니다. 수정 기준 이상이어도 다른 취약점까지 안전하다는 뜻은 아닙니다.','Request the deployed node --version output and deployment image. Check affected functionality and vendor backports in the linked advisory. Express versions are not Node.js versions. Meeting this fix baseline does not establish overall safety.'):t('실제 배포의 react-server-dom-webpack / react-server-dom-parcel / react-server-dom-turbopack 이름·정확한 버전과 RSC·서버 함수 사용 여부를 추가로 확인하세요. React 또는 Next.js 표시만으로 해당 패키지 버전을 추정하지 않습니다. 서버 기능을 사용하지 않는 React 앱에 그대로 적용하지 마세요.','Verify the exact deployed react-server-dom-webpack / react-server-dom-parcel / react-server-dom-turbopack package and version, plus RSC / Server Function usage. Do not infer these versions from a React or Next.js banner or apply server-only issues to client-only apps.')});
  }
  let ids:string[]=[],affected:boolean|null=null,reference='';
  if(item.product==='PHP'){ids=['CVE-2026-109618','CVE-2026-109619'];reference=php;affected=older(item.version,{'8.2':35,'8.3':36,'8.4':27,'8.5':12});}
  if(item.product==='Next.js'||item.product==='React RSC'){ids=['CVE-2025-55182'];reference=react;/* Next.js banner cannot establish an RSC package version. */}
  if(item.product==='Django'){ids=['CVE-2025-64459'];reference=django;affected=older(item.version,{'4.2':26,'5.1':14,'5.2':8});}
  if(item.product==='Spring'){ids=['CVE-2022-22965'];reference=spring;affected=older(item.version,{'5.2':20,'5.3':18});}
  if(!ids.length){findings.push({...base,id:'technology:advisory:'+item.product,title:t('제품별 CVE 대조 미완료: ','Product CVE matching incomplete: ')+item.product,status:'not_assessed'});continue;}
  for(const id of ids)findings.push({...base,id:'technology:'+item.product+':'+id,title:id+(affected===true?t(' · 영향 버전 가능성',' · potentially affected version'):t(' · 적용 여부 검토',' · applicability review')),status:affected===true?'warning':affected===false?'info':'not_assessed',severity:affected===true?'high':'info',reference,evidence:[...base.evidence,`versionRangeMatch=${affected??'unknown'}`,'exploitTested=false'],remediation:t('공식 권고와 서버 패키지·실효 구성·공급자 백포트를 확인하세요. 버전 표시는 위조되거나 프록시의 값일 수 있습니다. 범위 밖 버전은 안전 판정이 아니며, 영향 버전 일치도 실제 공격 성공을 증명하지 않습니다.','Check the official advisory, effective deployment/configuration and vendor backports. Banners may be forged or belong to a proxy. Outside a listed range is not a safety verdict; a version match is not proof of exploitability.')});
 }
 return findings;
}
