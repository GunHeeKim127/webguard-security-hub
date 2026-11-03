import {scanTarget} from './scan-policy';
export type WebTargetIssue='empty'|'https'|'invalid'|'detail';
/** webTargetInput: 도메인 입력을 검증하며 상세 경로를 자동으로 검사 대상으로 바꾸지 않습니다. */
export function webTargetInput(raw:string):{normalized:string,issue:WebTargetIssue|null,domain?:string}{
 const text=raw.trim(),normalized=text.includes('://')?text:'https://'+text;
 if(!text)return {normalized,issue:'empty'};
 if(text.length>300)return {normalized,issue:'invalid'};
 let url:URL;try{url=new URL(normalized);}catch{return {normalized,issue:'invalid'};}
 if(url.username||url.password||url.port&&url.port!=='443')return {normalized,issue:'invalid'};
 if(url.protocol!=='https:')return {normalized,issue:'https'};
 try{scanTarget(url.origin);}catch{return {normalized,issue:'invalid'};}
 if(url.pathname!=='/'||url.search||url.hash)return {normalized,issue:'detail',domain:url.origin};
 return {normalized:url.origin,issue:null};
}
/** webTargetReason: 확인한 주소 문제와 사용자가 취할 수 있는 조치를 함께 설명합니다. */
export function webTargetReason(issue:WebTargetIssue,locale:string){
 const ko=locale==='ko';
 if(issue==='empty')return ko?'도메인 주소를 입력해 주세요. 예: https://example.com':'Enter a domain address, for example https://example.com.';
 if(issue==='detail')return ko?'도메인까지만 지원합니다. /login 같은 상세 경로, ?검색조건, #위치는 제외하고 입력해 주세요.':'Only the domain is supported. Remove page paths such as /login, query parameters and fragments.';
 if(issue==='https')return ko?'HTTPS 도메인만 지원합니다. 예: https://example.com. 해당 사이트가 HTTPS를 제공하는지 확인해 주세요.':'Only HTTPS domains are supported. Use https://example.com and confirm the site supports HTTPS.';
 return ko?'주소 형식을 확인해 주세요. 공개 도메인만 지원하며 IP 주소·계정 정보·별도 포트는 사용할 수 없습니다. 예: https://example.com':'Check the address format. Use a public domain without an IP address, credentials or a custom port, for example https://example.com.';
}
