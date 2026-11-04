/** coalescedReadiness: 같은 인스턴스의 동시 상태 조회만 합치며 완료 결과는 캐시하지 않습니다. */
export function coalescedReadiness<T>(probe:()=>Promise<T>){
 let pending:Promise<T>|undefined;
 return /** read: 진행 중인 읽기는 공유하고 성공·실패 후 다음 요청은 다시 검사합니다. */ ()=>pending??(pending=Promise.resolve().then(probe).finally(/** finally: 실패도 성공으로 보존하지 않고 다음 실제 검사를 허용합니다. */ ()=>{pending=undefined;}));
}
