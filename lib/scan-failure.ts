const copy={
 TARGET_DNS_FAILED:{ko:['DNS에서 대상 도메인의 주소를 확인하지 못했습니다.','도메인 철자와 공개 DNS 설정을 확인하세요. 이 결과만으로 도메인이 존재하지 않는다고 확정하지는 않습니다.'],en:['DNS could not resolve the target domain.','Check the spelling and public DNS configuration. This alone does not prove the domain does not exist.']},
 TARGET_DNS_TIMEOUT:{ko:['DNS 주소 조회가 제한 시간 안에 끝나지 않았습니다.','잠시 후 다시 시도하고 반복되면 대상 도메인의 DNS 응답 상태를 확인하세요.'],en:['The DNS lookup timed out.','Retry later and check the domain’s DNS response if this repeats.']},
 TARGET_TLS_FAILED:{ko:['대상 사이트의 HTTPS 인증서 또는 TLS 연결 검증에 실패했습니다.','사이트 담당자에게 인증서 유효기간·도메인 일치·인증서 체인과 TLS 설정 확인을 요청하세요. 검증을 끄고 연결하지 않습니다.'],en:['HTTPS certificate or TLS verification failed.','Ask the owner to check expiry, hostname, certificate chain and TLS configuration. Verification is not disabled.']},
 TARGET_TIMEOUT:{ko:['대상 사이트의 연결 또는 응답이 제한 시간 안에 완료되지 않았습니다.','잠시 후 재시도하고 반복되면 서버 응답 속도·방화벽·네트워크 상태를 확인하세요.'],en:['The target connection or response timed out.','Retry later; if it persists, check server response time, firewall and network availability.']},
 TARGET_CONNECTION_REFUSED:{ko:['대상 사이트가 HTTPS 연결을 거절했습니다.','서버가 HTTPS로 서비스 중인지 담당자에게 확인하세요. 원인은 서비스 중지나 접속 제한 등일 수 있습니다.'],en:['The target refused the HTTPS connection.','Ask the owner whether HTTPS is running. A stopped service or access restriction may be involved.']},
 TARGET_CONNECTION_FAILED:{ko:['대상 사이트와의 연결이 끊기거나 도달하지 못했습니다.','공개 HTTPS 접속 상태를 확인하고 잠시 후 다시 시도하세요. 세부 원인은 이 결과만으로 확정하지 않습니다.'],en:['The target connection was interrupted or unreachable.','Check public HTTPS availability and retry later. This result does not establish the precise cause.']},
 TARGET_ADDRESS_REJECTED:{ko:['대상 주소가 허용된 공개 네트워크 검사 범위에 포함되지 않아 연결하지 않았습니다.','내부망·로컬 주소 대신 본인 소유 또는 허가받은 공개 HTTPS 도메인을 사용하세요.'],en:['The address was outside the permitted public-network scope, so no connection was made.','Use an owned or authorized public HTTPS domain, not a private or local address.']},
 TARGET_HEADERS_TOO_LARGE:{ko:['대상 응답 헤더가 검사 도구의 크기 한도를 넘었습니다.','대상 서버의 과도한 헤더·쿠키 설정을 담당자에게 확인해 달라고 요청하세요. 사이트가 취약하다는 확정 판정은 아닙니다.'],en:['The response headers exceeded the inspector’s size limit.','Ask the owner to review excessive headers or cookies. This is not a confirmed vulnerability.']},
 TARGET_POLICY_REJECTED:{ko:['주소가 현재 허용된 HTTPS 기본 주소 검사 조건에 맞지 않습니다.','상세 경로·IP·계정 정보·별도 포트를 제외하고 도메인을 입력하세요. 승인된 대상만 검사하는 환경이면 담당자에게 대상 등록을 요청하세요.'],en:['The address did not meet the current HTTPS-root inspection policy.','Use a domain without paths, IP literals, credentials or custom ports. In approved-target mode, ask the owner to register it.']},
 TARGET_CANCELLED:{ko:['검사가 취소되어 새 결과를 만들지 않았습니다.','입력과 동의를 확인한 뒤 필요할 때 다시 검사하세요.'],en:['Inspection was cancelled; no new result was produced.','Review the input and consent, then restart if needed.']}
} as const;
export type ScanFailureCode=keyof typeof copy;
export const scanFailureCodes=Object.keys(copy) as ScanFailureCode[];
/** isScanFailureCode: 외부에 보낼 수 있는 고정된 검사 실패 코드인지 확인합니다. */
export function isScanFailureCode(code:string):code is ScanFailureCode{return Object.hasOwn(copy,code);}
/** scanFailureDetails: 원인과 해결책을 분리하고 내부 오류 원문·주소·자격증명을 포함하지 않습니다. */
export function scanFailureDetails(locale:string,code:ScanFailureCode){const [reason,action]=copy[code][locale==='ko'?'ko':'en'];return {reason,action};}
/** scanFailureText: 고정된 실패 분류의 사용자 안내만 반환합니다. */
export function scanFailureText(locale:string,code:ScanFailureCode){const value=scanFailureDetails(locale,code);return value.reason+' '+value.action;}
/** scanFailureCode: 실제 오류 신호가 있는 경우에만 DNS·TLS·연결 실패를 구분합니다. */
export function scanFailureCode(error:unknown,signal?:AbortSignal):ScanFailureCode|'TARGET_REJECTED'{
 const message=error instanceof Error?error.message:'',code=error&&typeof error==='object'&&'code' in error?error.code:undefined;
 if(isScanFailureCode(message))return message;
 if(signal?.aborted)return signal.reason?.name==='TimeoutError'?'TARGET_TIMEOUT':'TARGET_CANCELLED';
 if(message==='DNS timeout')return 'TARGET_DNS_TIMEOUT';
 if(code==='ENOTFOUND'||code==='EAI_AGAIN'||code==='EAI_NODATA')return 'TARGET_DNS_FAILED';
 if(message==='Non-public DNS rejected')return 'TARGET_ADDRESS_REJECTED';
 if(message==='Scan deadline exceeded'||code==='ETIMEDOUT')return 'TARGET_TIMEOUT';
 if(message==='Scan cancelled')return 'TARGET_CANCELLED';
 if(message==='TLS verification failed'||typeof code==='string'&&(/^(?:ERR_TLS_|ERR_SSL_|CERT_)/.test(code)||['DEPTH_ZERO_SELF_SIGNED_CERT','SELF_SIGNED_CERT_IN_CHAIN','UNABLE_TO_VERIFY_LEAF_SIGNATURE'].includes(code)))return 'TARGET_TLS_FAILED';
 if(code==='ECONNREFUSED')return 'TARGET_CONNECTION_REFUSED';
 if(['ECONNRESET','EHOSTUNREACH','ENETUNREACH'].includes(code as string))return 'TARGET_CONNECTION_FAILED';
 if(code==='HPE_HEADER_OVERFLOW')return 'TARGET_HEADERS_TOO_LARGE';
 if(['Only HTTPS origin on port 443 is allowed','Hostname is not allowed'].includes(message))return 'TARGET_POLICY_REJECTED';
 return 'TARGET_REJECTED';
}
