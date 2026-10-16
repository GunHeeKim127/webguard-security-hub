import {headers} from 'next/headers';
import {requestLocale} from '../lib/request-locale';
import Home from './home-client';
export default async function Page(){return <Home initialLocale={requestLocale(await headers()).locale}/>;}
