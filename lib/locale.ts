export const locales=['ko','en','ja','zh','es','fr'] as const;
export type Locale=typeof locales[number];
export const localeNames:Record<Locale,string>={ko:'한국어',en:'English',ja:'日本語',zh:'简体中文',es:'Español',fr:'Français'};
export const languageNames:Record<Locale,string>={ko:'Korean',en:'English',ja:'Japanese',zh:'Simplified Chinese',es:'Spanish',fr:'French'};
export function isLocale(value:unknown):value is Locale{return typeof value==='string'&&(locales as readonly string[]).includes(value);}
export function preferredLanguage(header:string|null):Locale|undefined{
 const candidates=(header??'').slice(0,2048).split(',').slice(0,30).map((part,index)=>{
  const [tag,...params]=part.trim().split(';');const qText=params.find(p=>p.trim().startsWith('q='))?.trim().slice(2);
  const q=qText===undefined?1:/^(?:0(?:\.\d{1,3})?|1(?:\.0{1,3})?)$/.test(qText)?Number(qText):0;
  return {locale:tag.toLowerCase().split('-')[0],q,index};
 }).filter(item=>item.q>0).sort((a,b)=>b.q-a.q||a.index-b.index);
 return candidates.find(item=>isLocale(item.locale))?.locale as Locale|undefined;
}
export function localeCookie(header:string|null):Locale|undefined{
 const raw=(header??'').slice(0,8192).split(';').map(c=>c.trim()).find(c=>c.startsWith('wg_locale='))?.slice(10);
 try{const value=decodeURIComponent(raw??'');return isLocale(value)?value:undefined;}catch{return undefined;}
}
const countryLocales:Record<string,Locale>={KR:'ko',JP:'ja',CN:'zh',SG:'zh',US:'en',GB:'en',AU:'en',NZ:'en',IE:'en',ES:'es',MX:'es',AR:'es',CL:'es',CO:'es',PE:'es',UY:'es',EC:'es',BO:'es',PY:'es',VE:'es',CR:'es',PA:'es',GT:'es',HN:'es',SV:'es',NI:'es',DO:'es',CU:'es',FR:'fr',MC:'fr',SN:'fr',CI:'fr'};
export function resolveLocale(input:{cookie?:string|null,acceptLanguage?:string|null,trustedCountry?:string|null,defaultLocale?:string}){
 const manual=localeCookie(input.cookie??null);if(manual)return {locale:manual,source:'manual' as const};
 const browser=preferredLanguage(input.acceptLanguage??null);if(browser)return {locale:browser,source:'browser' as const};
 const country=input.trustedCountry?.toUpperCase();if(country&&Object.hasOwn(countryLocales,country))return {locale:countryLocales[country],source:'country' as const};
 return {locale:isLocale(input.defaultLocale)?input.defaultLocale:'en' as Locale,source:'default' as const};
}
