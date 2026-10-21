import {headers} from 'next/headers';
import {requestLocale} from '../lib/request-locale';
import {redirect} from 'next/navigation';
import {currentUser} from '../lib/security';
import Home from './home-client';
export default async function Page({searchParams}:{searchParams:Promise<{view?:string|string[]}>}){
 if((await searchParams).view!=='web'&&await currentUser())redirect('/workbench');
 return <Home initialLocale={requestLocale(await headers()).locale}/>;
}
