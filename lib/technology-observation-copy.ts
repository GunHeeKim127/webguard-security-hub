import type {Finding} from './assessment/types';
/** technologyCoverageCopy: 기술 미식별과 관찰 범위 미확인을 구분해 설명합니다. */
export function technologyCoverageCopy(eligible:boolean|undefined,products:number|undefined,locale:string){
 const ko=locale==='ko';
 if(eligible===true&&products!==undefined)return {label:products===0?(ko?'헤더 관찰 완료 · 기술 미식별':'Headers checked · no technology identified'):(ko?'헤더 기술 단서 관찰 완료':'Header technology hints observed'),observed:ko?`공개 응답 헤더를 확인했고 식별된 기술 단서는 ${products}개입니다.`:`Public response headers were checked; ${products} technology hints were identified.`,reason:products===0?(ko?'검사를 건너뛴 것이 아닙니다. 헤더에 식별할 단서가 없었으며, 특정 기술을 사용하지 않는다는 뜻이나 안전 판정은 아닙니다.':'The check was not skipped. Headers contained no identifiable hints; this proves neither absence of a technology nor safety.'):(ko?'헤더에 나타난 제품 단서이며 실제 설치 제품·버전의 증명은 아닙니다.':'These are header hints, not proof of installed products or versions.')};
 return {label:ko?'응답 범위상 기술 판단 보류':'Technology unresolved for this response',observed:ko?'정상 서비스 응답을 대표하는 기술 관찰 자료가 부족합니다.':'There is insufficient technology evidence representative of the normal application.',reason:ko?'오류·이동 응답이거나 과거 기록에 관찰 정보가 없어 실제 서비스의 기술을 확정하지 않습니다.':'An error/redirect response or missing historical observation cannot establish the application’s technology.'};
}
/** technologyCoverageEvidence: 충돌하지 않는 고정 헤더 관찰 메타데이터만 해석합니다. */
export function technologyCoverageEvidence(f:Finding){
 if(!/(?:^|:)technology:coverage$/.test(f.id))return null;
 const eligibility=f.evidence.filter(/** filter: 중복된 응답 범위 값은 확정하지 않습니다. */ v=>v.startsWith('responseEligible=')),counts=f.evidence.filter(/** filter: 식별 단서 개수는 고정된 정수만 읽습니다. */ v=>/^observedProducts=\d{1,5}$/.test(v));
 return {eligible:eligibility.length===1?(eligibility[0]==='responseEligible=true'?true:eligibility[0]==='responseEligible=false'?false:undefined):undefined,products:counts.length===1?Number(counts[0].split('=')[1]):undefined};
}
/** displayedFinding: 기존 저장 기록도 헤더 관찰 완료를 검사 생략으로 오해하지 않게 표현만 보완합니다. */
export function displayedFinding(f:Finding):Finding{const value=technologyCoverageEvidence(f);return value?.eligible===true&&value.products!==undefined&&f.status==='not_assessed'?{...f,status:'info'}:f;}
