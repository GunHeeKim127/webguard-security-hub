import {NextResponse,type NextRequest} from 'next/server';
import {database} from './lib/database-pool';
import {vercelProtection} from './lib/vercel-protection';

export async function proxy(req:NextRequest){
 const rejected=await vercelProtection(req,(sql,values)=>database.protectionQuery(sql,values));
 if(rejected)return rejected;
 return NextResponse.next();
}
export const config={matcher:['/((?!_next/static|_next/image|favicon.ico).*)']};
