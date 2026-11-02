/** GET: 서비스 생존 상태를 응답합니다。 */ export async function GET(){return Response.json({status:'up',service:'WebGuard',database:'not checked'},{headers:{'Cache-Control':'no-store'}});}
