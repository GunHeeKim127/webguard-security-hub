import {resolveLocale} from './locale';
import {trustedCountry} from './geo-country';
export function requestLocale(headers:Pick<Headers,'get'>){return resolveLocale({cookie:headers.get('cookie'),acceptLanguage:headers.get('accept-language'),trustedCountry:trustedCountry(headers),defaultLocale:process.env.DEFAULT_LOCALE});}
