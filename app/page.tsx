import {headers} from 'next/headers';
import {requestLocale} from '../lib/request-locale';
import {redirect} from 'next/navigation';
import {currentUser} from '../lib/security';
import Home from './home-client';
/** Page: 해당 경로의 서버 페이지를 구성합니다 주요 호출: currentUser·redirect·requestLocale. */ export default async function Page({searchParams}:{searchParams:Promise<{view?:string|string[]}>}){
 if((await searchParams).view!=='web'&&await currentUser())redirect('/workbench');
 return <Home initialLocale={requestLocale(await headers()).locale}/>;
}
