/** registrationInput: 회원가입 입력의 형식과 허용 필드를 검증합니다 주요 호출: some·keys·toLowerCase. */ export function registrationInput(data:Record<string,unknown>){
 if(Object.keys(data).some(/** some 콜백: 조건을 만족하는 항목이 있는지 확인합니다 주요 호출: includes. */ key=>!['email','password'].includes(key))||typeof data.email!=='string'||typeof data.password!=='string')return null;
 const email=data.email.trim().toLowerCase(),password=data.password;
 if(email.length>254||!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||password.length<14||password.length>128)return null;
 return {email,password};
}
