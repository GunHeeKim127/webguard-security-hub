import {resolveLocale} from './locale';
import {trustedCountry} from './geo-country';
/** requestLocale: 요청 헤더에서 사용할 언어를 결정합니다 주요 호출: resolveLocale·get·trustedCountry. */ export function requestLocale(headers:Pick<Headers,'get'>){return resolveLocale({cookie:headers.get('cookie'),acceptLanguage:headers.get('accept-language'),trustedCountry:trustedCountry(headers),defaultLocale:process.env.DEFAULT_LOCALE});}
