export function singleFileSelection<T>(files:ArrayLike<T>|null|undefined):{file:T|null;tooMany:boolean}{
 if((files?.length??0)>1)return {file:null,tooMany:true};
 return {file:files?.[0]??null,tooMany:false};
}
export const singleFileMessage=(locale:'ko'|'en')=>locale==='ko'?'한 번에 파일 1개만 선택할 수 있습니다.':'Select only one file at a time.';
