import { randomBytes, scryptSync, timingSafeEqual, createHash } from 'node:crypto';
export function hashPassword(password:string) {
 if(password.length < 14 || password.length > 128) throw new Error('Password must be 14–128 characters');
 const salt=randomBytes(16).toString('hex');
 return salt+':'+scryptSync(password,salt,64).toString('hex');
}
export function verifyPassword(password:string,stored:string) {
 const [salt,hash]=stored.split(':');
 if(!salt || !hash || password.length>128) return false;
 const expected=Buffer.from(hash,'hex'), actual=scryptSync(password,salt,64);
 return expected.length===actual.length && timingSafeEqual(expected,actual);
}
export const tokenHash=(token:string)=>createHash('sha256').update(token).digest('hex');
export const canScan=(role:string)=>['admin','analyst'].includes(role);
