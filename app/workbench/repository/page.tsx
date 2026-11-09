import {headers} from 'next/headers';
import {redirect} from 'next/navigation';
import {currentUser} from '../../../lib/security';
import {requestLocale} from '../../../lib/request-locale';
import RepositoryReview from './repository-client';
export const dynamic='force-dynamic';
export default async function Page(){if(!await currentUser())redirect('/');return <RepositoryReview locale={requestLocale(await headers()).locale==='ko'?'ko':'en'}/>;}
