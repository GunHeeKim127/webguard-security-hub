// Existing self-service accounts retain their DB role and data. Membership
// allows personal assessments; administrative capabilities remain separate.
export const canAssess=/** canAssess: 사용자 역할의 진단 실행 가능 여부를 반환합니다 주요 호출: includes. */ (role:string)=>['admin','analyst','viewer'].includes(role);
