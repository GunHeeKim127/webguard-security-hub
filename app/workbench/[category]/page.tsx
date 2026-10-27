import {publicUser} from '../../../lib/public-identity';
import {headers} from 'next/headers';
import {notFound,redirect} from 'next/navigation';
import {currentUser} from '../../../lib/security';
import {requestLocale} from '../../../lib/request-locale';
import Workbench from '../workbench-client';
export const dynamic='force-dynamic';
export default async function Page({params}:{params:Promise<{category:string}>}){
 const {category}=await params;
 if(category!=='web'&&category!=='mobile'&&category!=='endpoint'&&category!=='virtualization'&&category!=='network'&&category!=='results')notFound();
 const user=await currentUser();if(!user)redirect('/');
 return <Workbench key={category} view={category} initialUser={publicUser(user)} initialLocale={requestLocale(await headers()).locale==='ko'?'ko':'en'}/>;
}
