'use client';
import {useEffect,useState} from 'react';
import {isLocale,type Locale} from '../lib/locale';
import {messages} from '../lib/messages';
export default function ErrorPage({reset}:{error:Error&{digest?:string},reset:()=>void}){
 const [locale,setLocale]=useState<Locale>('en');useEffect(()=>{const l=document.documentElement.lang;if(isLocale(l))setLocale(l);},[]);
 return <main style={{color:'white',padding:48,fontFamily:'Arial,sans-serif'}}><h1>{messages[locale].unexpected}</h1><button onClick={reset}>{messages[locale].retry}</button></main>;
}
