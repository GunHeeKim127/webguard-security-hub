export function registrationInput(data:Record<string,unknown>){
 if(Object.keys(data).some(key=>!['email','password'].includes(key))||typeof data.email!=='string'||typeof data.password!=='string')return null;
 const email=data.email.trim().toLowerCase(),password=data.password;
 if(email.length>254||!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)||password.length<14||password.length>128)return null;
 return {email,password};
}
