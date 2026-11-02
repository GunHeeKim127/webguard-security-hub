import type {Metadata} from 'next';
import {headers} from 'next/headers';
import {requestLocale} from '../lib/request-locale';
import {messages} from '../lib/messages';
import {AppRouterCacheProvider} from '@mui/material-nextjs/v16-appRouter';
/** generateMetadata: 페이지의 제목·아이콘 등 문서 메타데이터를 만듭니다 주요 호출: requestLocale·headers. */ export async function generateMetadata():Promise<Metadata>{const {locale}=requestLocale(await headers());return {title:`WebGuard · ${messages[locale].title}`,description:messages[locale].intro,robots:{index:false,follow:false}};}
/** Layout: 페이지의 공통 문서와 화면 틀을 구성합니다 주요 호출: headers·requestLocale·get. */ export default async function Layout({children}:{children:React.ReactNode}){const incoming=await headers(),{locale}=requestLocale(incoming),nonce=incoming.get('x-nonce')??undefined;return <html lang={locale}><body style={{margin:0,background:'#091321'}}><AppRouterCacheProvider options={{nonce}}>{children}</AppRouterCacheProvider></body></html>;}
