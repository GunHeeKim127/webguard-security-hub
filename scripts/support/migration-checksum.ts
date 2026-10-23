import {createHash} from 'node:crypto';
export function migrationChecksums(sql:string){
 const lf=sql.replace(/\r\n/g,'\n');
 const hash=(value:string)=>createHash('sha256').update(value).digest('hex');
 return {canonical:hash(lf),accepted:new Set([hash(sql),hash(lf),hash(lf.replace(/\n/g,'\r\n'))])};
}
