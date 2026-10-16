import {createHash,timingSafeEqual} from 'node:crypto';
// Only the configured gateway may supply an IP-derived country. Never trust XFF/client headers alone.
export function trustedCountry(headers:Pick<Headers,'get'>,secret=process.env.GEOIP_PROXY_SECRET,countryHeader=process.env.GEOIP_COUNTRY_HEADER??'cf-ipcountry'){
 if(!secret||secret.length<32||secret.length>256||!/^[a-z0-9-]{1,64}$/i.test(countryHeader))return undefined;
 const token=headers.get('x-webguard-geo-token');if(!token||token.length>256)return undefined;
 if(!timingSafeEqual(createHash('sha256').update(secret).digest(),createHash('sha256').update(token).digest()))return undefined;
 const country=headers.get(countryHeader)?.toUpperCase();return country&&/^[A-Z]{2}$/.test(country)&&!['XX','T1'].includes(country)?country:undefined;
}
