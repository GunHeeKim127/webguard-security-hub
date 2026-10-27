import {publicUser} from '../../lib/public-identity';
import {headers} from 'next/headers';
import {redirect} from 'next/navigation';
import {currentUser} from '../../lib/security';
import {requestLocale} from '../../lib/request-locale';
import Workbench from './workbench-client';
export const dynamic='force-dynamic';
export default async function Page(){const user=await currentUser();if(!user)redirect('/');return <Workbench initialUser={publicUser(user)} initialLocale={requestLocale(await headers()).locale==='ko'?'ko':'en'}/>;}
