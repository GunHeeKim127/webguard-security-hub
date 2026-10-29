import {headers} from 'next/headers';
import {requestLocale} from '../../lib/request-locale';
import Help from './help-client';
export default async function Page(){return <Help initialLocale={requestLocale(await headers()).locale==='ko'?'ko':'en'}/>;}
