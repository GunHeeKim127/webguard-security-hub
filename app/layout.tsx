import type {Metadata} from 'next';
import {headers} from 'next/headers';
import {requestLocale} from '../lib/request-locale';
import {messages} from '../lib/messages';
import {AppRouterCacheProvider} from '@mui/material-nextjs/v16-appRouter';
export async function generateMetadata():Promise<Metadata>{const {locale}=requestLocale(await headers());return {title:`VELTHARA · ${messages[locale].title}`,description:'Unified Asset Security Assessment Platform · '+messages[locale].intro,robots:{index:false,follow:false}};}
export default async function Layout({children}:{children:React.ReactNode}){const {locale}=requestLocale(await headers());return <html lang={locale}><body style={{margin:0,background:'#ffffff'}}><AppRouterCacheProvider>{children}</AppRouterCacheProvider></body></html>;}
