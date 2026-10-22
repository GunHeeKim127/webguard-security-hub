// Existing self-service accounts retain their DB role and data. Membership
// allows personal assessments; administrative capabilities remain separate.
export const canAssess=(role:string)=>['admin','analyst','viewer'].includes(role);
