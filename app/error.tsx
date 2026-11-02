'use client';
import {useEffect,useState} from 'react';
import {isLocale,type Locale} from '../lib/locale';
import {messages} from '../lib/messages';
/** ErrorPage: 오류 안내와 재시도 동작을 표시합니다 주요 호출: useState·useEffect. */ export default function ErrorPage({reset}:{error:Error&{digest?:string},reset:()=>void}){
 const [locale,setLocale]=useState<Locale>('en');useEffect(/** useEffect 콜백: 의존값에 따른 부수 작업과 정리를 실행합니다 주요 호출: isLocale·setLocale. */ ()=>{const l=document.documentElement.lang;if(isLocale(l))setLocale(l);},[]);
 return <main style={{color:'white',padding:48,fontFamily:'Arial,sans-serif'}}><h1>{messages[locale].unexpected}</h1><button onClick={reset}>{messages[locale].retry}</button></main>;
}
