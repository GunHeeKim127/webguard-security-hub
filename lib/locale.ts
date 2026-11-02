export const locales=['ko','en','ja','zh','es','fr'] as const;
export type Locale=typeof locales[number];
export const localeNames:Record<Locale,string>={ko:'한국어',en:'English',ja:'日本語',zh:'简体中文',es:'Español',fr:'Français'};
export const languageNames:Record<Locale,string>={ko:'Korean',en:'English',ja:'Japanese',zh:'Simplified Chinese',es:'Spanish',fr:'French'};
/** isLocale: 지원 언어 값인지 확인합니다 주요 호출: includes. */ export function isLocale(value:unknown):value is Locale{return typeof value==='string'&&(locales as readonly string[]).includes(value);}
/** preferredLanguage: 사용자 언어 우선순위를 해석합니다 주요 호출: sort·filter·map. */ export function preferredLanguage(header:string|null):Locale|undefined{
 const candidates=(header??'').slice(0,2048).split(',').slice(0,30).map(/** map 콜백: 각 항목을 필요한 값으로 변환합니다 주요 호출: split·trim·slice. */ (part,index)=>{
  const [tag,...params]=part.trim().split(';');const qText=params.find(/** find 콜백: 조건에 맞는 첫 항목을 찾습니다 주요 호출: startsWith·trim. */ p=>p.trim().startsWith('q='))?.trim().slice(2);
  const q=qText===undefined?1:/^(?:0(?:\.\d{1,3})?|1(?:\.0{1,3})?)$/.test(qText)?Number(qText):0;
  return {locale:tag.toLowerCase().split('-')[0],q,index};
 }).filter(/** filter 콜백: 조건에 맞는 항목만 고릅니다 */ item=>item.q>0).sort(/** sort 콜백: 비교 기준에 따라 항목 순서를 정합니다 */ (a,b)=>b.q-a.q||a.index-b.index);
 return candidates.find(/** find 콜백: 조건에 맞는 첫 항목을 찾습니다 주요 호출: isLocale. */ item=>isLocale(item.locale))?.locale as Locale|undefined;
}
/** localeCookie: 선택 언어를 보관할 쿠키 표현을 만듭니다 주요 호출: slice·find·map. */ export function localeCookie(header:string|null):Locale|undefined{
 const raw=(header??'').slice(0,8192).split(';').map(/** map 콜백: 각 항목을 필요한 값으로 변환합니다 주요 호출: trim. */ c=>c.trim()).find(/** find 콜백: 조건에 맞는 첫 항목을 찾습니다 주요 호출: startsWith. */ c=>c.startsWith('wg_locale='))?.slice(10);
 try{const value=decodeURIComponent(raw??'');return isLocale(value)?value:undefined;}catch{return undefined;}
}
const countryLocales:Record<string,Locale>={KR:'ko',JP:'ja',CN:'zh',SG:'zh',US:'en',GB:'en',AU:'en',NZ:'en',IE:'en',ES:'es',MX:'es',AR:'es',CL:'es',CO:'es',PE:'es',UY:'es',EC:'es',BO:'es',PY:'es',VE:'es',CR:'es',PA:'es',GT:'es',HN:'es',SV:'es',NI:'es',DO:'es',CU:'es',FR:'fr',MC:'fr',SN:'fr',CI:'fr'};
/** resolveLocale: 쿠키·헤더 등 언어 입력을 지원 언어로 결정합니다 주요 호출: localeCookie·preferredLanguage·toUpperCase. */ export function resolveLocale(input:{cookie?:string|null,acceptLanguage?:string|null,trustedCountry?:string|null,defaultLocale?:string}){
 const manual=localeCookie(input.cookie??null);if(manual)return {locale:manual,source:'manual' as const};
 const browser=preferredLanguage(input.acceptLanguage??null);if(browser)return {locale:browser,source:'browser' as const};
 const country=input.trustedCountry?.toUpperCase();if(country&&Object.hasOwn(countryLocales,country))return {locale:countryLocales[country],source:'country' as const};
 return {locale:isLocale(input.defaultLocale)?input.defaultLocale:'en' as Locale,source:'default' as const};
}
