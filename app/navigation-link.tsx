'use client';
import NextLink,{useLinkStatus} from 'next/link';
import {forwardRef,useEffect,useState,type ComponentPropsWithoutRef} from 'react';

function PendingNavigation(){
 const {pending}=useLinkStatus(),[slow,setSlow]=useState(false);
 useEffect(()=>{if(!pending){setSlow(false);return;}const timer=setTimeout(()=>setSlow(true),8000);return()=>clearTimeout(timer);},[pending]);
 if(!pending)return null;
 const ko=document.documentElement.lang==='ko';
 return <span role="status" aria-live="polite" data-navigation-pending="true" style={{position:'fixed',inset:'0 0 auto',zIndex:2000,padding:'12px 18px',background:'#102735',color:'#e6fff7',boxShadow:'0 2px 12px #0006',fontFamily:'Arial, sans-serif',fontSize:14,pointerEvents:'none',textTransform:'none'}}><progress aria-label={ko?'화면 이동 중':'Opening page'} style={{display:'block',width:'100%',height:4,marginBottom:8}}/>{slow?(ko?'응답이 지연되고 있습니다. 잠시 기다려 주세요.':'The response is taking longer. Please wait.'):(ko?'화면 이동 중…':'Opening page…')}</span>;
}
const NavigationLink=forwardRef<HTMLAnchorElement,ComponentPropsWithoutRef<typeof NextLink>>(function NavigationLink({children,prefetch,onMouseEnter,onFocus,...props},ref){
 const [intent,setIntent]=useState(false);
 return <NextLink {...props} ref={ref} prefetch={prefetch===undefined?(intent?null:false):prefetch} onMouseEnter={event=>{setIntent(true);onMouseEnter?.(event);}} onFocus={event=>{setIntent(true);onFocus?.(event);}}>{children}<PendingNavigation/></NextLink>;
});
export default NavigationLink;
