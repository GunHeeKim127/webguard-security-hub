import {headers} from 'next/headers';
import {requestLocale} from '../lib/request-locale';
import {messages} from '../lib/messages';
export default async function NotFound(){const t=messages[requestLocale(await headers()).locale];return <main style={{color:'white',padding:48,fontFamily:'Arial,sans-serif'}}><h1>{t.notFound}</h1><a href="/" style={{color:'#66e6c3'}}>{t.back}</a></main>;}
