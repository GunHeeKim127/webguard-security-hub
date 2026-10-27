import type {Metadata} from 'next';
import {headers} from 'next/headers';
import {requestLocale} from '../lib/request-locale';
import {messages} from '../lib/messages';
import {AppRouterCacheProvider} from '@mui/material-nextjs/v16-appRouter';
export async function generateMetadata():Promise<Metadata>{const {locale}=requestLocale(await headers());return {title:`WebGuard · ${messages[locale].title}`,description:messages[locale].intro,robots:{index:false,follow:false}};}
export default async function Layout({children}:{children:React.ReactNode}){const incoming=await headers(),{locale}=requestLocale(incoming),nonce=incoming.get('x-nonce')??undefined;return <html lang={locale}><body style={{margin:0,background:'#091321'}}><AppRouterCacheProvider options={{nonce}}>{children}</AppRouterCacheProvider></body></html>;}
