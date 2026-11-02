import {createHash} from 'node:crypto';
/** migrationChecksums: 마이그레이션 파일의 검증용 체크섬 목록을 계산합니다 주요 호출: replace·hash. */ export function migrationChecksums(sql:string){
 const lf=sql.replace(/\r\n/g,'\n');
 const hash=/** hash: 입력 바이트 또는 텍스트의 해시를 계산합니다 주요 호출: digest·update·createHash. */ (value:string)=>createHash('sha256').update(value).digest('hex');
 return {canonical:hash(lf),accepted:new Set([hash(sql),hash(lf),hash(lf.replace(/\n/g,'\r\n'))])};
}
