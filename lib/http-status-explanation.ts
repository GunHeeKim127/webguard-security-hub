import type {AssessmentReport} from './assessment/types';
const descriptions:Record<number,[string,string,string,string,string,string]>={
 200:['정상 응답','서버가 이번 HEAD 요청을 정상 처리했습니다. 보안이 안전하다는 뜻은 아닙니다.','아래 보안 헤더·TLS 항목을 따로 확인하세요.','OK','The server processed this HEAD request. This does not establish security.','Review the header and TLS findings separately.'],
 204:['본문 없는 정상 응답','서버가 요청을 처리했지만 본문을 제공하지 않는 응답입니다.','현재 응답의 헤더만 판단할 수 있으며 실제 페이지 동작은 별도 확인하세요.','No Content','The request succeeded without a response body.','Review these headers; page behavior requires a separate check.'],
 400:['요청을 처리할 수 없음','대상 서버가 요청을 잘못된 요청으로 처리했습니다.','해당 도메인의 공개 HEAD 요청 허용 여부를 담당자에게 확인하세요.','Bad Request','The target treated this request as invalid.','Ask the owner whether public HEAD requests are supported.'],
 401:['인증 필요','대상 서버가 인증을 요구하거나 인증 정보를 받아들이지 않았습니다. 이 검사는 대상 사이트에 로그인하지 않습니다.','공개 페이지인지 확인하세요. 비밀번호나 로그인 쿠키를 검사 도구에 넣지 마세요.','Authentication required','The target requires authentication or rejected credentials. This inspector does not sign into the target.','Verify public access; do not submit passwords or login cookies to this inspector.'],
 403:['접근 거절','대상 서버가 요청을 이해했지만 접근을 거절했습니다. 권한·자동 요청 제한 등이 원인일 수 있으며 정확한 사유는 미확인입니다.','사이트 담당자에게 공개 HEAD 요청과 접근 정책을 확인해 달라고 요청하세요.','Access refused','The target understood but refused access. Permissions or automated-request restrictions may be involved; the exact reason is unknown.','Ask the owner to check public HEAD access and policy.'],
 404:['페이지를 찾지 못함','대상 서버가 이 주소를 찾지 못했거나 존재 여부를 공개하지 않았습니다. 기본 도메인의 404가 하위 프로젝트의 취약점을 의미하지는 않습니다.','GitHub Pages처럼 /프로젝트/ 아래에 배포했다면 루트 응답이 실제 프로젝트를 대표하지 않을 수 있습니다. 현재 상세 경로 검사는 지원하지 않습니다.','Not Found','The target did not find this address or did not disclose its existence. A root 404 is not a vulnerability verdict for a subpath project.','A GitHub Pages project under /repository/ may differ from the root. Detailed-path inspection is not currently supported.'],
 405:['검사 요청 방식 미지원','대상 서버가 이 주소에서 HEAD 요청을 허용하지 않습니다. 브라우저의 GET 접속과 결과가 다를 수 있습니다.','HEAD 지원을 담당자에게 확인하세요. 이 도구는 GET으로 자동 전환하지 않습니다.','Method Not Allowed','The target does not allow HEAD here; a browser GET may behave differently.','Check HEAD support with the owner. This tool does not switch to GET automatically.'],
 408:['대상 서버의 요청 시간 초과','대상 서버가 요청 처리 시간 초과 상태를 응답했습니다.','잠시 후 다시 시도하고 반복되면 담당자에게 요청 처리 상태를 확인해 달라고 요청하세요.','Request Timeout','The target returned a request-timeout response.','Retry later and ask the owner to inspect request handling if it persists.'],
 429:['요청 횟수 제한','대상 서버가 너무 많은 요청으로 판단해 제한했습니다.','검사를 반복하지 말고 대상의 제한이 해제된 후 다시 시도하세요.','Too Many Requests','The target applied a request-frequency limit.','Stop repeating checks and retry after the target’s limit resets.'],
 500:['대상 서버 내부 오류','대상 서버가 내부 처리 오류를 응답했습니다.','사이트 담당자가 서버 로그와 상태를 확인해야 합니다. 이 코드만으로 침해를 확정하지 않습니다.','Internal Server Error','The target reported an internal processing error.','The owner should inspect server health and logs. This code alone does not establish compromise.'],
 502:['대상 중계 서버 오류','대상 프록시·게이트웨이가 뒤쪽 서버에서 적절한 응답을 받지 못했습니다.','대상 서비스의 프록시와 원본 서버 상태를 확인하세요.','Bad Gateway','The target gateway received an invalid upstream response.','Check the target proxy and origin server.'],
 503:['대상 서비스 일시 사용 불가','대상 서버가 현재 요청을 처리할 수 없다고 응답했습니다. 점검·과부하 등 여러 원인이 가능합니다.','잠시 후 재시도하고 계속되면 대상 사이트 담당자에게 문의하세요.','Service Unavailable','The target cannot currently handle the request; maintenance or overload may be involved.','Retry later and contact the target owner if it persists.'],
 504:['대상 중계 서버 시간 초과','대상 게이트웨이가 뒤쪽 서버의 응답을 제때 받지 못했습니다.','대상 프록시와 원본 서버의 응답 시간을 확인하세요.','Gateway Timeout','The target gateway did not receive an upstream response in time.','Check response times at the target proxy and origin.']
};
export const commonHttpStatuses=[200,301,400,401,403,404,405,429,500,502,503,504] as const;
/** httpStatusExplanation: 대상 서버 응답 코드의 뜻과 조치를 보안 판정과 구분합니다. */
export function httpStatusExplanation(status:number,locale:string){
 const ko=locale==='ko',entry=descriptions[status],eligible=status>=200&&status<300;
 if(entry)return {title:entry[ko?0:3],meaning:entry[ko?1:4],action:entry[ko?2:5],eligible};
 if(status>=300&&status<400)return {title:ko?'다른 주소로 이동 안내':'Redirection',meaning:ko?'대상 서버가 다른 위치로 이동하도록 응답했습니다. 이동 목적지는 따라가지 않았습니다.':'The target returned a redirect. Its destination was not followed.',action:ko?'현재 도구는 공개 기본 도메인 응답만 확인합니다. 실제 이동 경로는 별도로 확인하세요.':'This tool checks only the public root-domain response. Verify the redirect separately.',eligible:false};
 return {title:eligible?(ko?'정상 처리 범위 응답':'Successful response'):(ko?'추가 확인이 필요한 응답':'Response requiring review'),meaning:ko?'대상 서버에서 관찰한 HTTP 응답입니다. 숫자만으로 보안 수준이나 침해 여부를 판정하지 않습니다.':'This is an observed target HTTP response, not a security or compromise verdict.',action:ko?'사이트 담당자에게 해당 코드의 처리 조건을 확인하세요.':'Ask the owner to verify the conditions for this status.',eligible};
}
/** webResponseStatuses: 저장된 보고서의 충돌 없는 PC·모바일 HTTP 관찰만 읽습니다. */
export function webResponseStatuses(report:AssessmentReport){
 if(report.moduleId!=='web.compare'||report.targetKind==='supplied-source')return [];
 const results:Array<{profile:'desktop'|'mobile',status:number}>=[];
 for(const profile of ['desktop','mobile'] as const){const findings=report.findings.filter(/** filter: 동일 프로필의 HTTP 결과가 하나일 때만 사용합니다. */ f=>f.id===profile+':response');if(findings.length!==1)continue;const values=findings[0].evidence.filter(/** filter: 허용 범위의 HTTP 상태 코드만 읽습니다. */ v=>/^status=[1-5]\d\d$/.test(v));if(values.length===1)results.push({profile,status:Number(values[0].slice(7))});}
 return results;
}
