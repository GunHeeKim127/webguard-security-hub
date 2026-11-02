import {headers} from 'next/headers';
import {requestLocale} from '../../lib/request-locale';
import {registrationCopy} from '../../lib/registration-copy';
import Signup from './signup-client';
/** generateMetadata: 페이지의 제목·아이콘 등 문서 메타데이터를 만듭니다 주요 호출: requestLocale·headers. */ export async function generateMetadata(){const {locale}=requestLocale(await headers());return {title:'VELTHARA · '+registrationCopy[locale].title};}
/** Page: 해당 경로의 서버 페이지를 구성합니다 주요 호출: requestLocale·headers. */ export default async function Page(){const {locale}=requestLocale(await headers());return <Signup locale={locale}/>;}
