import {scan,scanFailureReason} from '../scanner';
import {scanTarget,approvedHosts,targetPolicy} from '../scan-policy';
import {assessmentText} from '../assessment-copy';
import {technologyFindings} from '../web-technology';
import {scanFailureCode,scanFailureText,isScanFailureCode} from '../scan-failure';
import {checkpoint,pick,report,type SecurityScanner,type Finding} from './types';
export const webCompare:SecurityScanner={id:'web.compare',version:'1.1.1',targetKind:'public-https',maxBytes:300,/** validate: 값의 형식이나 처리 조건을 확인합니다 주요 호출: scanTarget·targetPolicy·approvedHosts. */ validate(input){if(typeof input.url!=='string')throw new Error('INPUT_INVALID');scanTarget(input.url,targetPolicy()==='approved'?approvedHosts():undefined);},/** scan: 해당 자료의 관찰·검토 결과를 계산합니다 주요 호출: checkpoint·targetPolicy·approvedHosts. */ async scan(input,ctx){
 checkpoint(ctx);const allowed=targetPolicy()==='approved'?approvedHosts():undefined;
 const profiles=['desktop','mobile'] as const;
 const results=await Promise.allSettled(profiles.map(/** map 콜백: 각 항목을 필요한 값으로 변환합니다 주요 호출: scan. */ profile=>scan(input.url!,allowed,/** scan 콜백: scan에서 전달한 값을 처리하는 콜백입니다 */ ()=>{},ctx.signal,profile)));
 checkpoint(ctx);for(let i=0;i<results.length;i++){const result=results[i];if(result.status==='rejected')console.warn('[WebGuard web profile unavailable]',{profile:profiles[i],reason:scanFailureReason(result.reason,ctx.signal)});}
 if(results.every(/** every 콜백: 모든 항목이 조건을 만족하는지 확인합니다 */ r=>r.status==='rejected')){const codes=results.map(/** map: 실패한 프로필의 안전한 원인 코드만 비교합니다. */ r=>scanFailureCode(r.status==='rejected'?r.reason:undefined,ctx.signal));throw new Error(codes.every(/** every: 프로필별 원인이 같을 때만 하나의 원인으로 안내합니다. */ code=>code===codes[0])?codes[0]:'TARGET_REJECTED');}
 const findings:Finding[]=[];
 for(let n=0;n<profiles.length;n++){
  const r=results[n],profile=profiles[n];
  if(r.status==='rejected'){const code=scanFailureCode(r.reason,ctx.signal);findings.push({id:profile+':connection',title:profile+' '+pick(ctx,'연결','connection'),status:'not_assessed',severity:'info',evidence:['connectionUnavailable=true',`failureCode=${code}`],remediation:isScanFailureCode(code)?scanFailureText(ctx.locale,code):pick(ctx,'공개 DNS·인증서·HTTPS 응답 상태를 확인하고 다시 검사하세요.','Check public DNS, certificate and HTTPS response, then retest.')});continue;}
  findings.push({id:profile+':response',title:profile+' HTTP',status:'info',severity:'info',evidence:[`status=${r.value.status}`],remediation:pick(ctx,'HEAD 결과이며 실제 브라우저 페이지 실행과 리디렉션 목적지는 검사하지 않습니다.','This is a HEAD response; browser execution and redirect destinations are not assessed.')});
  if(r.value.technology)for(const f of technologyFindings(r.value.technology,ctx.locale))findings.push({...f,id:profile+':'+f.id,title:profile+' · '+f.title});
  for(const f of r.value.assessment??[])findings.push({id:profile+':'+f.id,title:profile+' · '+assessmentText(ctx.locale,f.group==='headers'?f.id:f.group),status:f.status,severity:f.severity,evidence:[...f.evidence,...f.issues.map(/** map 콜백: 각 항목을 필요한 값으로 변환합니다 주요 호출: assessmentText. */ issue=>assessmentText(ctx.locale,issue))],remediation:assessmentText(ctx.locale,`${f.group==='headers'?f.id:f.group}_fix`),reference:'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers'});
 }
 const [d,m]=results;
 const comparable=d.status==='fulfilled'&&m.status==='fulfilled';
 const differences=comparable?['status','technology',...(d.value.assessment??[]).map(/** map 콜백: 각 항목을 필요한 값으로 변환합니다 */ f=>f.id)].filter(/** filter 콜백: 조건에 맞는 항목만 고릅니다 주요 호출: stringify·find. */ id=>id==='status'?d.value.status!==m.value.status:id==='technology'?JSON.stringify(d.value.technology)!==JSON.stringify(m.value.technology):JSON.stringify(d.value.assessment?.find(/** find 콜백: 조건에 맞는 첫 항목을 찾습니다 */ f=>f.id===id))!==JSON.stringify(m.value.assessment?.find(/** find 콜백: 조건에 맞는 첫 항목을 찾습니다 */ f=>f.id===id))):[];
 findings.push({id:'profile-comparison',title:pick(ctx,'PC·모바일 응답 차이','Desktop / mobile response differences'),status:comparable?'info':'not_assessed',severity:'info',evidence:comparable?[`differentChecks=${differences.length}`,...differences.map(/** map 콜백: 각 항목을 필요한 값으로 변환합니다 */ id=>`check=${id}`)]:['bothProfilesAvailable=false'],remediation:pick(ctx,'차이가 의도된 것인지 확인하세요. User-Agent 변경은 실제 모바일 브라우저·PWA 실행을 재현하지 않으며 차이 자체가 취약점은 아닙니다.','Review whether differences are intentional. User-Agent variation does not reproduce a real mobile browser or PWA; differences alone are not vulnerabilities.')});
 return {...report(this,findings,[pick(ctx,'PC·모바일 User-Agent별 공개 루트 HEAD 각 1회 및 TLS 검사','One public-root HEAD and TLS check per desktop/mobile User-Agent')],[pick(ctx,'실제 브라우저·PWA·인증 세션·GET·리디렉션 추적·전체 TLS 등급은 미검사입니다.','No real browser, PWA, authenticated session, GET, redirect following or full TLS grading.')]),ruleVersion:'2026-11-03.1'};
}};
