type Client={query:(sql:string,values?:unknown[])=>Promise<{rows:any[];rowCount:number|null}>};
export async function resetAccountPassword(client:Client,email:string,passwordHash:string,emailHash:string){
 await client.query('BEGIN');
 try{
  const row=await client.query('SELECT id FROM public.users WHERE email=$1 FOR UPDATE',[email]);
  if(row.rowCount!==1)throw new Error('ACCOUNT_NOT_FOUND');
  const id=row.rows[0].id;
  await client.query('UPDATE public.users SET password_hash=$1 WHERE id=$2',[passwordHash,id]);
  await client.query('DELETE FROM public.sessions WHERE user_id=$1',[id]);
  await client.query('DELETE FROM public.rate_limits WHERE bucket=$1',['login:'+emailHash]);
  await client.query("INSERT INTO public.events(category,user_id) VALUES('password_reset_admin',$1)",[id]);
  await client.query('COMMIT');
 }catch(error){await client.query('ROLLBACK');throw error;}
}
