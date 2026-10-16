import {headers} from 'next/headers';
import {requestLocale} from '../../lib/request-locale';
import {registrationCopy} from '../../lib/registration-copy';
import Signup from './signup-client';
export async function generateMetadata(){const {locale}=requestLocale(await headers());return {title:'WebGuard · '+registrationCopy[locale].title};}
export default async function Page(){const {locale}=requestLocale(await headers());return <Signup locale={locale}/>;}
