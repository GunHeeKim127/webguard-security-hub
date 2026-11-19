import {currentUser} from '../../lib/security';
import {publicUser} from '../../lib/public-identity';
import {headers} from 'next/headers';
import {requestLocale} from '../../lib/request-locale';
import Help from './help-client';
/** Page: 해당 경로의 서버 페이지를 구성합니다 주요 호출: requestLocale·headers. */ export default async function Page(){const user=await currentUser().catch(()=>null);return <Help user={user?publicUser(user):undefined} initialLocale={requestLocale(await headers()).locale==='ko'?'ko':'en'}/>;}
