import { randomBytes, scryptSync, timingSafeEqual, createHash } from 'node:crypto';
/** hashPassword: 비밀번호를 저장용 해시로 변환합니다 주요 호출: toString·randomBytes·scryptSync. */ export function hashPassword(password:string) {
 if(password.length < 14 || password.length > 128) throw new Error('Password must be 14–128 characters');
 const salt=randomBytes(16).toString('hex');
 return salt+':'+scryptSync(password,salt,64).toString('hex');
}
/** verifyPassword: 제공한 비밀번호와 저장된 해시를 비교합니다 주요 호출: split·from·scryptSync. */ export function verifyPassword(password:string,stored:string) {
 if(!/^[0-9a-f]{32}:[0-9a-f]{128}$/.test(stored)||password.length>128)return false;
 const [salt,hash]=stored.split(':');
 const expected=Buffer.from(hash,'hex'), actual=scryptSync(password,salt,64);
 return expected.length===actual.length && timingSafeEqual(expected,actual);
}
export const tokenHash=/** tokenHash: 토큰 원문 대신 비교할 해시를 계산합니다 주요 호출: digest·update·createHash. */ (token:string)=>createHash('sha256').update(token).digest('hex');
export {canAssess as canScan} from './assessment-permission';
