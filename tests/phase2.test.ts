import test from 'node:test';
import {assessmentReportText} from '../lib/assessment/report-text';
import type {AssessmentReport} from '../lib/assessment/types';
import {remediationInput,remediationBaseline,remediationVerification,type RemediationRecord} from '../lib/assessment/remediation';
import {assessmentTrend,reportBundleHtml} from '../lib/assessment/report-bundle';
test('remediation distinguishes manual closure, incompatible retest and actual later evidence',/** test: 사용자 종료 선언이 재검증을 대체하지 않고 호환성·시각·중복을 확인합니다. */ ()=>{
 const report:AssessmentReport={schemaVersion:1,moduleId:'linux.ssh',moduleVersion:'1',ruleVersion:'1',targetKind:'config',observedAt:'2026-11-04',scope:[],limitations:[],findings:[{id:'root',title:'Root',status:'warning',severity:'medium',evidence:[],remediation:''}]};
 const row:RemediationRecord={id:'a',asset_id:'b',run_id:'old',finding_id:'root',state:'closed',owner_label:'',note:'Reviewed',version:1,baseline:remediationBaseline(report,'root'),created_at:'2026-11-04T00:00:00Z',updated_at:'2026-11-04T00:00:00Z'};
 const run={id:'new',created_at:'2026-11-04T00:01:00Z',report:{...report,findings:[{...report.findings[0],status:'pass' as const}]}};
 assert.equal(remediationVerification(row,{...run,id:'old'}),'pending');assert.equal(remediationVerification(row,run),'passed');assert.equal(remediationVerification(row,{...run,report:{...run.report,ruleVersion:'2'}}),'incompatible');assert.equal(remediationVerification(row,{...run,report:{...run.report,findings:[]}}),'unknown');
 assert.equal(remediationVerification(row,{...run,report:{...run.report,findings:[...run.report.findings,...run.report.findings]}}),'unknown');
 const html=reportBundleHtml([run], [{...row,note:'<script>alert(1)</script>\nFORGED'}],'en');assert(!html.includes('<script>'));assert(html.includes('&lt;script&gt;'));assert(html.includes('Closed · user decision'));assert(html.includes('default-src'));
 const trend=assessmentTrend([run,{id:'old',created_at:'2026-11-03',report}]);assert.equal(trend[0].improved,1);assert.equal(trend[1].comparable,false);
});
test('remediation input rejects invented verification, extra identity and unsafe versions',/** test: 사용자 입력으로 검증 판정·계정·원본 근거를 위조하지 못하게 합니다. */ ()=>{
 const input={assetId:'11111111-1111-4111-8111-111111111111',runId:'22222222-2222-4222-8222-222222222222',findingId:'root',state:'open',ownerLabel:'',note:'',version:0};
 assert.equal(remediationInput(input).state,'open');for(const change of [{state:'verified'},{userId:'other'},{version:2147483647},{state:'closed'},{note:'a'.repeat(1001)}])assert.throws(/** throws: 잘못된 조치 입력을 거절합니다. */ ()=>remediationInput({...input,...change}));
});
test('draft report preserves uncertainty, bounds injected lines and never mutates results',/** test: 초안이 안전 판정이나 조치 완료를 만들어내지 않고 원본을 보존하는지 확인합니다. */ ()=>{
 const report:AssessmentReport={schemaVersion:1,moduleId:'linux.ssh',moduleVersion:'1',ruleVersion:'1',targetKind:'config',observedAt:'2026-11-03',scope:['Supplied settings only'],limitations:['No live authentication'],findings:[{id:'passwordauthentication',title:'Password',status:'not_assessed',severity:'info',evidence:['value=unknown\nFORGED SECTION\u202e'],remediation:'Check configuration'}]};
 const original=JSON.stringify(report),text=assessmentReportText(report,'ko');
 assert.match(text,/초안/);assert.match(text,/아직 확인하지 못함: 1/);assert.match(text,/No live authentication/);assert(!text.includes('\nFORGED SECTION'));assert(!text.includes('\u202e'));assert.match(text,/조치 완료는 수정 후 재검증/);assert.equal(JSON.stringify(report),original);
 const en=assessmentReportText(report,'en');assert.match(en,/Not yet verified: 1/);assert.match(en,/not a safety certificate/);
});
import {inspectSource} from '../lib/source-inspection';
import {sourceSqlFindings} from '../lib/source-sql-review';

test('SQL source hints distinguish PHP/JS construction, parameters and tagged ORM templates',/** test 콜백: 테스트: SQL source hints distinguish PHP/JS construction, parameters and tagged ORM templates 주요 호출: assert·some·sourceSqlFindings. */ ()=>{
 for(const text of ['const sql = "SELECT * FROM items WHERE id=" + req.query.id; db.query(sql);','<?php $db->query("SELECT * FROM items WHERE id=$id");','<?php mysqli_query($conn, "SELECT * FROM items WHERE id=" . $_GET["id"]);','db.query(`SELECT * FROM items WHERE id=${input}`);','prisma.$queryRaw`SELECT * FROM items WHERE id=${Prisma.raw(input)}`;'])assert(sourceSqlFindings(text,'en').some(/** some 콜백: 조건을 만족하는 항목이 있는지 확인합니다 주요 호출: includes. */ f=>f.id.includes('dynamic-')&&f.status==='warning'),text);
 for(const text of ['db.query("SELECT * FROM items WHERE id=$1",[input]);','<?php $stmt=$pdo->prepare("SELECT * FROM items WHERE id=?"); $stmt->execute([$id]);','prisma.$queryRaw`SELECT * FROM items WHERE id=${input}`;','db.query({text:"SELECT * FROM items WHERE id=$1",values:[input]});'])assert(!sourceSqlFindings(text,'en').some(/** some 콜백: 조건을 만족하는 항목이 있는지 확인합니다 */ f=>f.status==='warning'),text);
 assert(sourceSqlFindings('prisma.$queryRawUnsafe("SELECT 1")','en').some(/** some 콜백: 조건을 만족하는 항목이 있는지 확인합니다 주요 호출: includes. */ f=>f.id.includes('unsafe-')));
});
test('SQL source results redact source and distinguish comments and unresolved code from absence',/** test 콜백: 테스트: SQL source results redact source and distinguish comments and unresolved code from absence 주요 호출: inspectSource·assert·some. */ ()=>{
 const secret='PRIVATE_SQL_MARKER';
 const report=inspectSource('db.query("SELECT * FROM '+secret+' WHERE id=" + input);','ko');assert(report.findings.some(/** some 콜백: 조건을 만족하는 항목이 있는지 확인합니다 주요 호출: includes. */ f=>f.id.includes('dynamic-')));assert(!JSON.stringify(report).includes(secret));
 for(const text of ['// db.query(`SELECT ${input}`);','const sample = "db.query(SELECT secret)";','db.query("query { viewer { id } }");'])assert(!sourceSqlFindings(text,'en').some(/** some 콜백: 조건을 만족하는 항목이 있는지 확인합니다 */ f=>f.status==='warning'));
 assert(sourceSqlFindings('db.query(statementFromOtherFile);','en').some(/** some 콜백: 조건을 만족하는 항목이 있는지 확인합니다 주요 호출: includes. */ f=>f.id.includes('unresolved-')&&f.status==='not_assessed'));
 const creds=sourceSqlFindings('const url="postgres://private:PRIVATE_SQL_MARKER@host/db";','en');assert(creds.some(/** some 콜백: 조건을 만족하는 항목이 있는지 확인합니다 주요 호출: endsWith. */ f=>f.id.endsWith('credential')));assert(!JSON.stringify(creds).includes(secret));
});
test('SQL guidance exposes observed counts and line-specific hints without inventing backend facts',/** test 콜백: 테스트: SQL guidance exposes observed counts and line-specific hints without inventing backend facts 주요 호출: inspectSource·find·match. */ ()=>{
 const report=inspectSource('const sql="SELECT * FROM records WHERE id="+input;\ndb.query(sql);','ko'),item=report.findings.find(/** find 콜백: 조건에 맞는 첫 항목을 찾습니다 주요 호출: includes. */ f=>f.id.includes('source:sql:dynamic-'))!;
 assert.match(findingContext(item,report,'ko').observed,/2행/);assert.match(findingContext(report.findings.find(/** find 콜백: 조건에 맞는 첫 항목을 찾습니다 */ f=>f.id==='source:sql:coverage')!,report,'ko').observed,/1개/);
 const none=inspectSource('const value=1;','ko');assert.match(findingContext(none.findings.find(/** find 콜백: 조건에 맞는 첫 항목을 찾습니다 */ f=>f.id==='source:sql:coverage')!,none,'ko').observed,/0개/);
});
test('SQL permission hints review PUBLIC grants and definer search paths without asserting live ACLs',/** test 콜백: 테스트: SQL permission hints review PUBLIC grants and definer search paths without asserting live ACLs 주요 호출: sourceSqlFindings·assert·some. */ ()=>{
 const unsafe=sourceSqlFindings('GRANT ALL ON TABLE private_table TO PUBLIC; CREATE FUNCTION f() RETURNS int LANGUAGE sql SECURITY DEFINER AS $$SELECT 1$$;','ko');
 assert(unsafe.some(/** some 콜백: 조건을 만족하는 항목이 있는지 확인합니다 주요 호출: includes. */ f=>f.id.includes('public-grant-')));assert(unsafe.some(/** some 콜백: 조건을 만족하는 항목이 있는지 확인합니다 주요 호출: includes. */ f=>f.id.includes('definer-')));assert(unsafe.some(/** some 콜백: 조건을 만족하는 항목이 있는지 확인합니다 주요 호출: endsWith. */ f=>f.id.endsWith('coverage')&&f.status==='not_assessed'));
 assert(!sourceSqlFindings('GRANT SELECT ON public_catalog TO PUBLIC; CREATE FUNCTION f() RETURNS int LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$SELECT 1$$;','en').some(/** some 콜백: 조건을 만족하는 항목이 있는지 확인합니다 */ f=>f.status==='warning'));
 assert(!JSON.stringify(unsafe).includes('private_table'));
});

test('source inspection distinguishes PHP, JavaScript and React core from server runtime packages',/** test 콜백: 테스트: source inspection distinguishes PHP, JavaScript and React core from server runtime packages 주요 호출: inspectSource·assert·some. */ ()=>{
 const php=inspectSource('<?php echo "PRIVATE_TEST_MARKER";','ko');assert(php.findings.some(/** some 콜백: 조건을 만족하는 항목이 있는지 확인합니다 주요 호출: endsWith. */ f=>f.id.endsWith('CVE-2026-109618')&&f.status==='not_assessed'));assert(!JSON.stringify(php).includes('PRIVATE_TEST_MARKER'));
 const js=inspectSource('const greeting = "PRIVATE_TEST_MARKER";','en');assert(js.findings.some(/** some 콜백: 조건을 만족하는 항목이 있는지 확인합니다 주요 호출: startsWith. */ f=>f.id.startsWith('source:language:')));assert(!js.findings.some(/** some 콜백: 조건을 만족하는 항목이 있는지 확인합니다 */ f=>/CVE-|GHSA-/.test(f.id)));
 const react=inspectSource(JSON.stringify({dependencies:{react:'19.0.0','react-dom':'19.0.0'}}),'en');assert(react.findings.some(/** some 콜백: 조건을 만족하는 항목이 있는지 확인합니다 */ f=>f.id==='source:rsc-applicability'));assert(!react.findings.some(/** some 콜백: 조건을 만족하는 항목이 있는지 확인합니다 */ f=>/CVE-|GHSA-/.test(f.id)));
});
test('supplied dependency locks compare exact RSC package versions without persisting source fields',/** test 콜백: 테스트: supplied dependency locks compare exact RSC package versions without persisting source fields 주요 호출: stringify·inspectSource·equal. */ ()=>{
 for(const [version,status]of [['19.0.3','warning'],['19.0.4','info'],['19.1.4','warning'],['19.1.5','info'],['19.2.3','warning'],['19.2.4','info'],['^19.2.4','not_assessed']] as const){
  const text=JSON.stringify({lockfileVersion:3,packages:{'node_modules/react-server-dom-webpack':{version,resolved:'https://PRIVATE_TEST_MARKER',integrity:'PRIVATE_TEST_MARKER'}}});const r=inspectSource(text,'en');assert.equal(r.findings.find(/** find 콜백: 조건에 맞는 첫 항목을 찾습니다 주요 호출: endsWith. */ f=>f.id.endsWith('CVE-2026-23864'))?.status,status);assert(!JSON.stringify(r).includes('PRIVATE_TEST_MARKER'));assert.equal(r.integrity?.bytes,Buffer.byteLength(text));
 }
 const conflicting=inspectSource(JSON.stringify({packages:{'node_modules/react-server-dom-webpack':{version:'19.2.3'},'node_modules/nested/node_modules/react-server-dom-webpack':{version:'19.2.4'}}}),'en');assert.equal(conflicting.findings.find(/** find 콜백: 조건에 맞는 첫 항목을 찾습니다 주요 호출: endsWith. */ f=>f.id.endsWith('CVE-2026-23864'))?.status,'not_assessed');
});
test('source inspection never substitutes engines ranges or PHP language hints for deployed runtime versions',/** test 콜백: 테스트: source inspection never substitutes engines ranges or PHP language hints for deployed runtime versions 주요 호출: inspectSource·stringify·equal. */ ()=>{
 const range=inspectSource(JSON.stringify({engines:{node:'>=24.22.1'}}),'en');assert.equal(range.findings.find(/** find 콜백: 조건에 맞는 첫 항목을 찾습니다 주요 호출: endsWith. */ f=>f.id.endsWith('CVE-2026-111497'))?.status,'not_assessed');
 const declared=inspectSource(JSON.stringify({runtime:{node:'24.22.0',php:'8.4.26'}}),'en');assert.equal(declared.findings.find(/** find 콜백: 조건에 맞는 첫 항목을 찾습니다 주요 호출: endsWith. */ f=>f.id.endsWith('CVE-2026-111497'))?.status,'warning');assert.equal(declared.findings.find(/** find 콜백: 조건에 맞는 첫 항목을 찾습니다 주요 호출: endsWith. */ f=>f.id.endsWith('CVE-2026-109618'))?.status,'warning');
 for(const invalid of ['', '[1,2]', '{not json}', 'x'.repeat(65537),'\0'])assert.throws(/** throws 콜백: throws에서 전달한 값을 처리하는 콜백입니다 주요 호출: inspectSource. */ ()=>inspectSource(invalid,'en'));
});
import assert from 'node:assert/strict';
import dns from 'node:dns/promises';
import https from 'node:https';
import {EventEmitter} from 'node:events';
import {assessmentInput} from '../lib/assessment/input';
import {scannerFor,runAssessment} from '../lib/assessment/registry';
import {compareAssessments} from '../lib/assessment/compare';
import {peMetadata,apkMetadata} from '../lib/assessment/binary-modules';
import {trafficSignals} from '../lib/assessment/store';
import {body} from '../lib/request';
import {explainFinding,orderedFindings,statusCopy} from '../lib/assessment/explanation';
import type {Finding} from '../lib/assessment/types';
import {findingContext} from '../lib/assessment/finding-context';

test('SSH contextual guidance uses actual allowed values and explains the exact baseline difference',/** test 콜백: 테스트: SSH contextual guidance uses actual allowed values and explains the exact baseline difference 주요 호출: runAssessment·find·findingContext. */ async()=>{
 const report=await runAssessment({moduleId:'linux.ssh',label:'Context',text:'MaxAuthTries 6\nPermitRootLogin yes\nPasswordAuthentication no\nPermitEmptyPasswords no\nPubkeyAuthentication yes'}, {locale:'ko',signal:new AbortController().signal});
 const f=report.findings.find(/** find 콜백: 조건에 맞는 첫 항목을 찾습니다 */ f=>f.id==='maxauthtries')!,context=findingContext(f,report,'ko');
 assert.equal(f.status,'warning');assert.match(context.observed,/MaxAuthTries = 6/);assert.match(context.reason!,/2회 많습니다/);assert.match(context.expected,/1~4회/);
 const old={...f,evidence:f.evidence.filter(/** filter 콜백: 조건에 맞는 항목만 고릅니다 주요 호출: startsWith. */ v=>!v.startsWith('inputValue='))};
 const missing=findingContext(old,report,'ko');assert.match(missing.observed,/실제 값이 없습니다/);assert.doesNotMatch(missing.observed,/= 6/);assert.match(missing.reason!,/설정 자체가 없다는 뜻은 아니/);
});
test('missing, conditional and unrecognized SSH input never becomes an invented current value',/** test 콜백: 테스트: missing, conditional and unrecognized SSH input never becomes an invented current value 주요 호출: runAssessment·find·equal. */ async()=>{
 const ctx={locale:'ko' as const,signal:new AbortController().signal};
 const missing=await runAssessment({moduleId:'linux.ssh',label:'Missing',text:'PasswordAuthentication no'},ctx);
 const missingRoot=missing.findings.find(/** find 콜백: 조건에 맞는 첫 항목을 찾습니다 */ f=>f.id==='permitrootlogin')!;assert.equal(missingRoot.status,'not_assessed');assert.match(findingContext(missingRoot,missing,'ko').nextStep!,/추가로 확인/);
 const conditional=await runAssessment({moduleId:'linux.ssh',label:'Conditional',text:'Include /review/example\nMaxAuthTries 6'},ctx);
 const item=conditional.findings.find(/** find 콜백: 조건에 맞는 첫 항목을 찾습니다 */ f=>f.id==='maxauthtries')!;assert.equal(item.status,'not_assessed');assert.match(findingContext(item,conditional,'ko').reason!,/Include/);
 const invalid=await runAssessment({moduleId:'linux.ssh',label:'Invalid',text:'PasswordAuthentication SECRET_DO_NOT_SAVE'},ctx);
 assert.equal(invalid.findings.find(/** find 콜백: 조건에 맞는 첫 항목을 찾습니다 */ f=>f.id==='passwordauthentication')!.status,'not_assessed');assert(!JSON.stringify(invalid).includes('SECRET_DO_NOT_SAVE'));
});
test('context distinguishes missing Windows data from disabled protection and inactive RDP',/** test 콜백: 테스트: context distinguishes missing Windows data from disabled protection and inactive RDP 주요 호출: runAssessment·stringify·find. */ async()=>{
 const report=await runAssessment({moduleId:'windows.policy',label:'Windows',text:JSON.stringify({schemaVersion:1,firewall:{domain:false},defender:{},rdp:{enabled:false}})},{locale:'ko',signal:new AbortController().signal});
 const firewall=report.findings.find(/** find 콜백: 조건에 맞는 첫 항목을 찾습니다 */ f=>f.id==='firewall.domain')!;assert.match(findingContext(firewall,report,'ko').observed,/꺼짐/);
 const missing=report.findings.find(/** find 콜백: 조건에 맞는 첫 항목을 찾습니다 */ f=>f.id==='defender.antivirus')!;assert.equal(missing.status,'not_assessed');assert.match(findingContext(missing,report,'ko').reason!,/실제 보호 기능이 꺼졌다고 판단하지 않습니다/);
 const rdp=report.findings.find(/** find 콜백: 조건에 맞는 첫 항목을 찾습니다 */ f=>f.id==='rdp.nla')!;assert.equal(rdp.status,'info');assert.match(findingContext(rdp,report,'ko').reason!,/요구하는 경고로 처리하지 않았습니다/);
});
test('web contextual guidance reports actual header values and requests missing version evidence',/** test 콜백: 테스트: web contextual guidance reports actual header values and requests missing version evidence 주요 호출: runAssessment·findingContext·match. */ async()=>{
 const base=await runAssessment({moduleId:'windows.policy',label:'Context',text:'{"schemaVersion":1}'},{locale:'ko',signal:new AbortController().signal});
 const report={...base,moduleId:'web.compare' as const};
 const f:Finding={id:'desktop:hsts',title:'HSTS',status:'warning',severity:'medium',evidence:['max-age=60'],remediation:'Review'};
 const result=findingContext(f,report,'ko');assert.match(result.observed,/60초/);assert.match(result.reason!,/15551940초 짧습니다/);
 const missing=findingContext({...f,id:'desktop:technology:PHP:CVE-test',status:'not_assessed',evidence:['product=PHP','declaredVersion=unknown']},report,'ko');assert.match(missing.reason!,/버전 자료 추가/);assert.match(missing.observed,/설치 여부 미검증/);
 const conflicting=findingContext({...f,id:'desktop:nosniff',evidence:['nosniff=true','nosniff=false']},report,'ko');assert.match(conflicting.observed,/확인 기록이 없습니다/);
});

test('readable findings prioritize warnings without changing stored verdicts or evidence',/** test 콜백: 테스트: readable findings prioritize warnings without changing stored verdicts or evidence 주요 호출: freeze·make·stringify. */ ()=>{
 const make=/** make: 검증 시나리오에서 make에 필요한 입력·호출·기대 결과 처리를 제공합니다 주요 호출: freeze. */ (id:string,status:Finding['status'],severity:Finding['severity']):Finding=>Object.freeze({id,title:id,status,severity,evidence:['explicit=true'],remediation:'Original guidance'});
 const original=Object.freeze([make('pass','pass','info'),make('medium-a','warning','medium'),make('unknown','not_assessed','info'),make('high','warning','high'),make('medium-b','warning','medium'),make('observed','info','info')]);
 const before=JSON.stringify(original),sorted=orderedFindings(original);
 assert.deepEqual(sorted.map(/** map 콜백: 각 항목을 필요한 값으로 변환합니다 */ f=>f.id),['high','medium-a','medium-b','unknown','observed','pass']);
 assert.equal(JSON.stringify(original),before);assert.equal(sorted[0],original[3]);assert.equal(sorted[3].status,'not_assessed');
});
test('plain explanations preserve profile and architecture identity with original fallback',/** test 콜백: 테스트: plain explanations preserve profile and architecture identity with original fallback 주요 호출: match·explainFinding·equal. */ ()=>{
 const f:Finding={id:'arch-2:nx',title:'DEP/NX',status:'warning',severity:'medium',evidence:['declared=false'],remediation:'Original next step'};
 assert.match(explainFinding(f,'application.pe','ko').title,/실행 형식 2/);
 assert.match(explainFinding(f,'application.pe','ko').action,/제작자/);
 assert.match(explainFinding({...f,id:'mobile:content-security-policy'},'web.compare','ko').title,/^모바일/);
 const unknown={...f,id:'future-check',title:'Future check'};
 assert.equal(explainFinding(unknown,'application.pe','en').action,unknown.remediation);
 assert.equal(f.status,'warning');assert.deepEqual(f.evidence,['declared=false']);
});
test('unverified advisory presentation does not claim a confirmed vulnerability or pass',/** test 콜백: 테스트: unverified advisory presentation does not claim a confirmed vulnerability or pass 주요 호출: explainFinding·match·equal. */ ()=>{
 const f:Finding={id:'desktop:technology:PHP:CVE-2026-109618',title:'Advisory',status:'not_assessed',severity:'info',evidence:['versionRangeMatch=unknown'],remediation:'Check provider guidance'};
 const copy=explainFinding(f,'web.compare','ko');
 assert.match(copy.why,/확정된 것은 아닙니다/);assert.match(copy.action,/실제 설치 버전/);
 assert.equal(statusCopy[f.status].ko,'아직 확인하지 못함');assert.equal(f.status,'not_assessed');
});

test('GNS3 version gate rejects unsupported majors and malformed versions before analysis',/** test 콜백: 테스트: GNS3 version gate rejects unsupported majors and malformed versions before analysis 주요 호출: throws·equal·runAssessment. */ async()=>{
 const context={locale:'en' as const,signal:new AbortController().signal},input=/** input: 검증 시나리오에서 input에 필요한 입력·호출·기대 결과 처리를 제공합니다 주요 호출: stringify. */ (version:unknown)=>({moduleId:'network.gns3',label:'Version boundary',authorized:true,text:JSON.stringify({type:'topology',version,topology:{nodes:[],links:[]}})});
 for(const version of ['999.0','3.0.0','1.5','2','2.x','2.2.61<script>',null])assert.throws(/** throws 콜백: throws에서 전달한 값을 처리하는 콜백입니다 주요 호출: assessmentInput·input. */ ()=>assessmentInput(input(version)));
 for(const version of ['2.2','2.2.61','2.2.61-beta.1'])assert.equal((await runAssessment(assessmentInput(input(version)),context)).moduleId,'network.gns3');
});
import {protectedRequest} from '../lib/protected-request';
import {parseVmx,parseGns3} from '../lib/assessment/infrastructure-modules';

test('VMX explicit unsafe flags warn; missing values remain unassessed and private fields never enter reports',/** test 콜백: 테스트: VMX explicit unsafe flags warn; missing values remain unassessed and private fields never enter reports 주요 호출: assessmentInput·runAssessment·equal. */ async()=>{
 const text='config.version = "8"\nvirtualHW.version = "21"\nisolation.tools.copy.disable = "FALSE"\nisolation.tools.paste.disable = "TRUE"\nethernet0.connectionType = "bridged"\nRemoteDisplay.vnc.enabled = "TRUE"\ndisplayName = "PRIVATE_VM_NAME"\nsharedFolder0.hostPath = "PRIVATE_HOST_PATH"';
 const input=assessmentInput({moduleId:'virtualization.vmx',label:'VMX check',authorized:true,text});
 const result=await runAssessment(input,{locale:'ko',signal:new AbortController().signal});
 assert.equal(result.findings.find(/** find 콜백: 조건에 맞는 첫 항목을 찾습니다 */ f=>f.id==='copy')?.status,'warning');assert.equal(result.findings.find(/** find 콜백: 조건에 맞는 첫 항목을 찾습니다 */ f=>f.id==='paste')?.status,'pass');
 assert.equal(result.findings.find(/** find 콜백: 조건에 맞는 첫 항목을 찾습니다 */ f=>f.id==='dragDrop')?.status,'not_assessed');assert.equal(result.findings.find(/** find 콜백: 조건에 맞는 첫 항목을 찾습니다 */ f=>f.id==='networkBoundary')?.status,'warning');
 assert.equal(result.findings.find(/** find 콜백: 조건에 맞는 첫 항목을 찾습니다 */ f=>f.id==='remoteConsole')?.status,'warning');
 assert(!JSON.stringify(result).includes('PRIVATE_'));assert.throws(/** throws 콜백: throws에서 전달한 값을 처리하는 콜백입니다 주요 호출: parseVmx. */ ()=>parseVmx({...input,text:text+'\nCONFIG.VERSION = "9"'}));
 assert.throws(/** throws 콜백: throws에서 전달한 값을 처리하는 콜백입니다 주요 호출: parseVmx. */ ()=>parseVmx({...input,text:'something = "not a VMX"'}));assert.throws(/** throws 콜백: throws에서 전달한 값을 처리하는 콜백입니다 주요 호출: parseVmx·repeat. */ ()=>parseVmx({...input,text:'x'.repeat(65537)}));
});

test('GNS3 topology flags explicit external boundaries and non-loopback consoles without claiming device security',/** test 콜백: 테스트: GNS3 topology flags explicit external boundaries and non-loopback consoles without claiming device security 주요 호출: assessmentInput·stringify·runAssessment. */ async()=>{
 const topology={type:'topology',version:'2.2.61',name:'PRIVATE_LAB',topology:{nodes:[{node_id:'a',node_type:'vpcs',console_host:'127.0.0.1',name:'PRIVATE_NODE'},{node_id:'b',node_type:'cloud',console_host:'0.0.0.0',properties:{password:'PRIVATE_SECRET'}}],links:[{nodes:[{node_id:'a'},{node_id:'b'}]}]}};
 const input=assessmentInput({moduleId:'network.gns3',label:'Lab check',authorized:true,text:JSON.stringify(topology)});
 const result=await runAssessment(input,{locale:'en',signal:new AbortController().signal});
 assert.equal(result.findings.find(/** find 콜백: 조건에 맞는 첫 항목을 찾습니다 */ f=>f.id==='externalBoundary')?.status,'warning');assert.equal(result.findings.find(/** find 콜백: 조건에 맞는 첫 항목을 찾습니다 */ f=>f.id==='consoleBinding')?.status,'warning');
 assert.equal(result.findings.find(/** find 콜백: 조건에 맞는 첫 항목을 찾습니다 */ f=>f.id==='devicePolicy')?.status,'not_assessed');assert(!JSON.stringify(result).includes('PRIVATE_'));
 delete (topology.topology.nodes[1] as any).console_host;
 const missing=await runAssessment({...input,text:JSON.stringify(topology)},{locale:'en',signal:new AbortController().signal});assert.equal(missing.findings.find(/** find 콜백: 조건에 맞는 첫 항목을 찾습니다 */ f=>f.id==='consoleBinding')?.status,'not_assessed');
 topology.topology.links[0].nodes[1].node_id='missing';assert.throws(/** throws 콜백: throws에서 전달한 값을 처리하는 콜백입니다 주요 호출: parseGns3·stringify. */ ()=>parseGns3({...input,text:JSON.stringify(topology)}));
 assert.throws(/** throws 콜백: throws에서 전달한 값을 처리하는 콜백입니다 주요 호출: parseGns3·stringify. */ ()=>parseGns3({...input,text:JSON.stringify({type:'not-topology',topology:{nodes:[],links:[]}})}));
});

test('infrastructure inspection remains bounded and rejects cancellation before parsing',/** test 콜백: 테스트: infrastructure inspection remains bounded and rejects cancellation before parsing 주요 호출: abort·rejects·runAssessment. */ async()=>{
 const stop=new AbortController();stop.abort();
 await assert.rejects(runAssessment({moduleId:'network.gns3',label:'lab',text:'{}'},{locale:'en',signal:stop.signal}));
 assert.throws(/** throws 콜백: throws에서 전달한 값을 처리하는 콜백입니다 주요 호출: assessmentInput. */ ()=>assessmentInput({moduleId:'virtualization.vmx',label:'lab',authorized:false,text:'config.version = "8"'}));
 assert.throws(/** throws 콜백: throws에서 전달한 값을 처리하는 콜백입니다 주요 호출: assessmentInput. */ ()=>assessmentInput({moduleId:'network.gns3',label:'lab',authorized:true,snapshot:{}}));
});
import type {AssessmentContext} from '../lib/assessment/types';
const context=/** context: 검증 시나리오에서 context에 필요한 입력·호출·기대 결과 처리를 제공합니다 주요 호출: timeout. */ ():AssessmentContext=>({locale:'ko',signal:AbortSignal.timeout(20000)});
const ssh=/** ssh: 검증 시나리오에서 ssh에 필요한 입력·호출·기대 결과 처리를 제공합니다 주요 호출: assessmentInput. */ (text:string)=>assessmentInput({moduleId:'linux.ssh',label:'router lab',text,authorized:true});
const safe='PermitRootLogin no\nPasswordAuthentication no\nPermitEmptyPasswords no\nPubkeyAuthentication yes\nMaxAuthTries 4';
test('assessment retry only replays an explicit pre-handler protection failure, once',/** test 콜백: 테스트: assessment retry only replays an explicit pre-handler protection failure, once 주요 호출: stringify·protectedRequest·equal. */ async()=>{
 const payload=JSON.stringify({moduleId:'linux.ssh',authorized:true});let calls=0;
 const response=await protectedRequest('/api/assessments',{method:'POST',body:payload},/** protectedRequest 콜백: protectedRequest에서 전달한 값을 처리하는 콜백입니다 주요 호출: equal·json. */ async(_url,init)=>{
  calls++;assert.equal(init?.body,payload);
  return calls===1?Response.json({errorCode:'PROTECTION_UNAVAILABLE'},{status:503}):Response.json({saved:true});
 });
 assert.equal(calls,2);assert.deepEqual(await response.json(),{saved:true});
 calls=0;const unavailable=await protectedRequest('/api/assessments',{},/** protectedRequest 콜백: protectedRequest에서 전달한 값을 처리하는 콜백입니다 주요 호출: json. */ async()=>{calls++;return Response.json({errorCode:'PROTECTION_UNAVAILABLE'},{status:503});});
 assert.equal(calls,2);assert.equal(unavailable.status,503);
 for(const [status,errorCode]of [[503,'SERVICE_UNAVAILABLE'],[403,'IP_BLACKLISTED'],[429,'THREAT_BLOCKED'],[400,'INPUT_INVALID'],[200,'PROTECTION_UNAVAILABLE']] as const){
  calls=0;await protectedRequest('/api/assessments',{},/** protectedRequest 콜백: protectedRequest에서 전달한 값을 처리하는 콜백입니다 주요 호출: json. */ async()=>{calls++;return Response.json({errorCode},{status});});assert.equal(calls,1);
 }
 calls=0;await assert.rejects(protectedRequest('/api/assessments',{},/** protectedRequest 콜백: protectedRequest에서 전달한 값을 처리하는 콜백입니다 */ async()=>{calls++;throw new Error('AMBIGUOUS_NETWORK_FAILURE');}),/AMBIGUOUS_NETWORK_FAILURE/);assert.equal(calls,1);
 calls=0;await protectedRequest('/api/assessments',{},/** protectedRequest 콜백: protectedRequest에서 전달한 값을 처리하는 콜백입니다 */ async()=>{calls++;return new Response('not JSON',{status:503});});assert.equal(calls,1);
});
test('cancelled assessments never replay during the protection retry wait',/** test 콜백: 테스트: cancelled assessments never replay during the protection retry wait 주요 호출: protectedRequest·setTimeout·rejects. */ async()=>{
 const controller=new AbortController();let calls=0;
 const pending=protectedRequest('/api/assessments',{signal:controller.signal},/** protectedRequest 콜백: protectedRequest에서 전달한 값을 처리하는 콜백입니다 주요 호출: json. */ async()=>{calls++;return Response.json({errorCode:'PROTECTION_UNAVAILABLE'},{status:503});});
 setTimeout(/** setTimeout 콜백: setTimeout의 이전 상태로부터 다음 상태를 계산합니다 주요 호출: abort. */ ()=>controller.abort(),30);
 await assert.rejects(pending,{name:'AbortError'});assert.equal(calls,1);
});
/** pe: 검증 시나리오에서 pe에 필요한 입력·호출·기대 결과 처리를 제공합니다 주요 호출: alloc·write·writeUInt32LE. */ function pe(){const b=Buffer.alloc(1024);b.write('MZ');b.writeUInt32LE(64,60);b.writeUInt32LE(0x4550,64);b.writeUInt16LE(0x8664,68);b.writeUInt16LE(1,70);b.writeUInt16LE(240,84);const o=88;b.writeUInt16LE(0x20b,o);b.writeUInt16LE(0x140,o+70);b.writeUInt32LE(16,o+108);b.writeUInt32LE(512,o+240+16);b.writeUInt32LE(512,o+240+20);b.writeUInt32LE(0x60000020,o+240+36);return b;}
/** apk: 검증 시나리오에서 apk에 필요한 입력·호출·기대 결과 처리를 제공합니다 주요 호출: from·alloc·writeUInt32LE. */ function apk(){const name=Buffer.from('AndroidManifest.xml'),data=Buffer.alloc(4),local=Buffer.alloc(30);local.writeUInt32LE(0x04034b50);local.writeUInt16LE(name.length,26);local.writeUInt32LE(4,18);local.writeUInt32LE(4,22);const central=Buffer.alloc(46);central.writeUInt32LE(0x02014b50);central.writeUInt16LE(name.length,28);central.writeUInt32LE(4,20);central.writeUInt32LE(4,24);const end=Buffer.alloc(22);end.writeUInt32LE(0x06054b50);end.writeUInt16LE(1,8);end.writeUInt16LE(1,10);end.writeUInt32LE(central.length+name.length,12);end.writeUInt32LE(local.length+name.length+data.length,16);return Buffer.concat([local,name,data,central,name,end]);}
test('module catalog is allowlisted; permission, target type and size validation cannot be bypassed',/** test 콜백: 테스트: module catalog is allowlisted; permission, target type and size validation cannot be bypassed 주요 호출: throws. */ ()=>{
 assert.throws(/** throws 콜백: throws에서 전달한 값을 처리하는 콜백입니다 주요 호출: scannerFor. */ ()=>scannerFor('../../evil'));
 assert.throws(/** throws 콜백: throws에서 전달한 값을 처리하는 콜백입니다 주요 호출: assessmentInput. */ ()=>assessmentInput({moduleId:'linux.ssh',label:'lab',text:safe,authorized:false}));
 assert.throws(/** throws 콜백: throws에서 전달한 값을 처리하는 콜백입니다 주요 호출: assessmentInput. */ ()=>assessmentInput({moduleId:'linux.ssh',label:'lab',text:safe,url:'https://example.com',authorized:true}));
 assert.throws(/** throws 콜백: throws에서 전달한 값을 처리하는 콜백입니다 주요 호출: ssh·repeat. */ ()=>ssh('PermitRootLogin no\n'+'#'.repeat(65536)));
 assert.throws(/** throws 콜백: throws에서 전달한 값을 처리하는 콜백입니다 주요 호출: assessmentInput. */ ()=>assessmentInput({moduleId:'linux.ssh',label:'<script>',text:safe,authorized:true}));
 assert.throws(/** throws 콜백: throws에서 전달한 값을 처리하는 콜백입니다 주요 호출: assessmentInput. */ ()=>assessmentInput({moduleId:'web.compare',label:'lab',url:'https://127.0.0.1',authorized:true}));
 assert.throws(/** throws 콜백: throws에서 전달한 값을 처리하는 콜백입니다 주요 호출: assessmentInput. */ ()=>assessmentInput({moduleId:'linux.ssh',label:'lab',text:safe,userId:'other',authorized:true}));
});
test('SSH snapshots use explicit first values, report Include/Match as unassessed and never retain secrets',/** test 콜백: 테스트: SSH snapshots use explicit first values, report Include/Match as unassessed and never retain secrets 주요 호출: runAssessment·ssh·context. */ async()=>{
 const report=await runAssessment(ssh(safe+'\n# secret-token-123\nHostKey /private/secret-key'),context());assert(report.findings.every(/** every 콜백: 모든 항목이 조건을 만족하는지 확인합니다 */ f=>f.status==='pass'));assert(!JSON.stringify(report).includes('secret'));
 const duplicate=await runAssessment(ssh('PermitRootLogin yes\n'+safe),context());assert.equal(duplicate.findings[0].status,'warning');
 for(const extra of ['Include /etc/ssh/*.conf','Match User private-user']){const conditional=await runAssessment(ssh(safe+'\n'+extra),context());assert(conditional.findings.every(/** every 콜백: 모든 항목이 조건을 만족하는지 확인합니다 */ f=>f.status==='not_assessed'));assert(!JSON.stringify(conditional).includes('private-user'));}
});
test('Windows snapshot distinguishes unknowns, disabled states and RDP NLA and ignores extra private values',/** test 콜백: 테스트: Windows snapshot distinguishes unknowns, disabled states and RDP NLA and ignores extra private values 주요 호출: runAssessment·assessmentInput·stringify. */ async()=>{
 const a=await runAssessment(assessmentInput({moduleId:'windows.policy',label:'pc',authorized:true,text:JSON.stringify({schemaVersion:1,firewall:{public:false},rdp:{enabled:false},password:'never-persist-this'})}),context());
 assert.equal(a.findings.find(/** find 콜백: 조건에 맞는 첫 항목을 찾습니다 */ f=>f.id==='firewall.public')?.status,'warning');assert.equal(a.findings.find(/** find 콜백: 조건에 맞는 첫 항목을 찾습니다 */ f=>f.id==='firewall.domain')?.status,'not_assessed');assert.equal(a.findings.find(/** find 콜백: 조건에 맞는 첫 항목을 찾습니다 */ f=>f.id==='rdp.nla')?.status,'info');assert(!JSON.stringify(a).includes('never-persist'));
});
test('PE parser validates offsets and bounds; certificate presence never becomes a signature trust verdict',/** test 콜백: 테스트: PE parser validates offsets and bounds; certificate presence never becomes a signature trust verdict 주요 호출: pe·equal·peMetadata. */ async()=>{
 const valid=pe();assert.equal(peMetadata(valid).flags,0x140);const r=await runAssessment(assessmentInput({moduleId:'application.pe',label:'app',authorized:true,base64:valid.toString('base64')}),context());assert.equal(r.findings.find(/** find 콜백: 조건에 맞는 첫 항목을 찾습니다 */ f=>f.id==='authenticode')?.status,'not_assessed');
 for(const cut of [0,10,64,90,300])assert.throws(/** throws 콜백: throws에서 전달한 값을 처리하는 콜백입니다 주요 호출: peMetadata·subarray. */ ()=>peMetadata(valid.subarray(0,cut)));
 const bad=Buffer.from(valid);bad.writeUInt32LE(0xffffffff,60);assert.throws(/** throws 콜백: throws에서 전달한 값을 처리하는 콜백입니다 주요 호출: peMetadata. */ ()=>peMetadata(bad));
});
test('APK inventory is bounded, rejects corrupt/encrypted/ZIP64 containers and never claims permission or signature inspection',/** test 콜백: 테스트: APK inventory is bounded, rejects corrupt/encrypted/ZIP64 containers and never claims permission or signature inspection 주요 호출: apk·equal·apkMetadata. */ async()=>{
 const valid=apk();assert.equal(apkMetadata(valid).entries,1);const r=await runAssessment(assessmentInput({moduleId:'application.apk',label:'apk',authorized:true,base64:valid.toString('base64')}),context());assert(r.findings.filter(/** filter 콜백: 조건에 맞는 항목만 고릅니다 */ f=>f.id!=='package-structure').every(/** every 콜백: 모든 항목이 조건을 만족하는지 확인합니다 */ f=>f.status==='not_assessed'));
 const encrypted=Buffer.from(valid);encrypted.writeUInt16LE(1,6);assert.throws(/** throws 콜백: throws에서 전달한 값을 처리하는 콜백입니다 주요 호출: apkMetadata. */ ()=>apkMetadata(encrypted));
 const central=30+Buffer.byteLength('AndroidManifest.xml')+4;
 const split=Buffer.from(valid);split.writeUInt16LE(1,central+34);assert.throws(/** throws 콜백: throws에서 전달한 값을 처리하는 콜백입니다 주요 호출: apkMetadata. */ ()=>apkMetadata(split));
 const zip64=Buffer.from(valid);zip64.writeUInt32LE(0xffffffff,central+24);assert.throws(/** throws 콜백: throws에서 전달한 값을 처리하는 콜백입니다 주요 호출: apkMetadata. */ ()=>apkMetadata(zip64));
 const bad=Buffer.from(valid);bad.writeUInt32LE(0xffffffff,bad.length-6);assert.throws(/** throws 콜백: throws에서 전달한 값을 처리하는 콜백입니다 주요 호출: apkMetadata. */ ()=>apkMetadata(bad));assert.throws(/** throws 콜백: throws에서 전달한 값을 처리하는 콜백입니다 주요 호출: apkMetadata·subarray. */ ()=>apkMetadata(valid.subarray(0,valid.length-1)));
});
test('retest comparison never treats missing/unassessed evidence or incompatible rule versions as remediation',/** test 콜백: 테스트: retest comparison never treats missing/unassessed evidence or incompatible rule versions as remediation 주요 호출: runAssessment·ssh·context. */ async()=>{
 const a=await runAssessment(ssh('PermitRootLogin yes'),context()),b=await runAssessment(ssh(safe),context());
 assert.equal(compareAssessments(a,b).changes.find(/** find 콜백: 조건에 맞는 첫 항목을 찾습니다 */ c=>c.id==='permitrootlogin')?.transition,'improved');
 const c=await runAssessment(ssh('Include extra.conf\n'+safe),context());assert(compareAssessments(b,c).changes.every(/** every 콜백: 모든 항목이 조건을 만족하는지 확인합니다 */ v=>v.transition==='unknown'));
 assert.equal(compareAssessments(a,{...b,ruleVersion:'next'}).compatible,false);
});
test('deadline cancellation stops even offline modules and opt-in request body size never weakens ordinary JSON limits',/** test 콜백: 테스트: deadline cancellation stops even offline modules and opt-in request body size never weakens ordinary JSON limits 주요 호출: abort·rejects·runAssessment. */ async()=>{
 const c=new AbortController();c.abort();await assert.rejects(runAssessment(ssh(safe),{locale:'ko',signal:c.signal}));
 const request=/** request: 검증 시나리오에서 request에 필요한 입력·호출·기대 결과 처리를 제공합니다 주요 호출: stringify·repeat. */ ()=>new Request('https://hub.example/api/assessments',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({text:'a'.repeat(5000)})});
 await assert.rejects(body(request()),{status:413});assert.equal((await body(request(),8192)).text.length,5000);
});
test('aggregate-only detection applies documented thresholds without an identity or blocking verdict',/** test 콜백: 테스트: aggregate-only detection applies documented thresholds without an identity or blocking verdict 주요 호출: deepEqual·trafficSignals·assert. */ ()=>{
 assert.deepEqual(trafficSignals({requests:999,login_failures:4,probes:2,server_errors:4}),{loginFailures:false,probes:false,serverErrors:false,highVolume:false});assert(Object.values(trafficSignals({requests:1000,login_failures:5,probes:3,server_errors:5})).every(Boolean));
});
test('web module performs exactly two pinned HEAD requests with separate User-Agents, no credentials and redacted evidence',/** test 콜백: 테스트: web module performs exactly two pinned HEAD requests with separate User-Agents, no credentials and redacted evidence 주요 호출: method·runAssessment·assessmentInput. */ async t=>{
 t.mock.method(dns,'lookup',/** method 콜백: method에서 전달한 값을 처리하는 콜백입니다 */ async()=>[{address:'8.8.8.8',family:4}]);const agents:string[]=[];
 const transport=t.mock.method(https,'request',/** method 콜백: method에서 전달한 값을 처리하는 콜백입니다 주요 호출: equal·push. */ (_url:URL,options:any,callback:Function)=>{assert.equal(options.method,'HEAD');assert.equal(options.rejectUnauthorized,true);assert.equal(options.headers.Cookie,undefined);assert.equal(options.headers.Authorization,undefined);agents.push(options.headers['User-Agent']);const req=new EventEmitter() as any;req.end=/** method 콜백: method에서 전달한 값을 처리하는 콜백입니다 주요 호출: callback·emit. */ ()=>{callback({statusCode:200,headers:{'set-cookie':['private=SECRET; Secure; SameSite=Lax']},socket:{authorized:true,getProtocol:/** callback 콜백: callback에서 전달한 값을 처리하는 콜백입니다 */ ()=> 'TLSv1.3',getPeerCertificate:/** callback 콜백: callback에서 전달한 값을 처리하는 콜백입니다 */ ()=>({valid_to:'Jan 1 00:00:00 2030 GMT'})},/** destroy: 검증 시나리오에서 destroy에 필요한 입력·호출·기대 결과 처리를 제공합니다 */ destroy(){}});req.emit('close');};req.destroy=/** method 콜백: method에서 전달한 값을 처리하는 콜백입니다 주요 호출: emit. */ (e:Error)=>{req.emit('error',e);req.emit('close');};return req;});
 const before=process.env.SCAN_TARGET_POLICY;process.env.SCAN_TARGET_POLICY='public';try{const r=await runAssessment(assessmentInput({moduleId:'web.compare',label:'web',url:'https://owned.example',authorized:true}),context());assert.equal(transport.mock.callCount(),2);assert.equal(agents.filter(/** filter 콜백: 조건에 맞는 항목만 고릅니다 주요 호출: includes. */ a=>a.includes('Mobile')).length,1);assert(!JSON.stringify(r).includes('SECRET'));assert(r.findings.some(/** some 콜백: 조건을 만족하는 항목이 있는지 확인합니다 */ f=>f.id==='profile-comparison'));}finally{if(before===undefined)delete process.env.SCAN_TARGET_POLICY;else process.env.SCAN_TARGET_POLICY=before;}
});
