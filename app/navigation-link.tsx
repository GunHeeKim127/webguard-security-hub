'use client';
import NextLink,{useLinkStatus} from 'next/link';
import {forwardRef,useEffect,useState,type ComponentPropsWithoutRef} from 'react';

/** PendingNavigation: 진행 중인 화면 이동 상태를 표시하고 지연 안내를 관리합니다 주요 호출: useLinkStatus·useState·useEffect. */ function PendingNavigation(){
 const {pending}=useLinkStatus(),[slow,setSlow]=useState(false);
 useEffect(/** useEffect 콜백: 의존값에 따른 부수 작업과 정리를 실행합니다 주요 호출: setSlow·setTimeout. */ ()=>{if(!pending){setSlow(false);return;}const timer=setTimeout(/** setTimeout 콜백: setTimeout의 이전 상태로부터 다음 상태를 계산합니다 주요 호출: setSlow. */ ()=>setSlow(true),8000);return/** useEffect 콜백: 의존값에 따른 부수 작업과 정리를 실행합니다 주요 호출: clearTimeout. */ ()=>clearTimeout(timer);},[pending]);
 if(!pending)return null;
 const ko=document.documentElement.lang==='ko';
 return <span role="status" aria-live="polite" data-navigation-pending="true" style={{position:'fixed',inset:'0 0 auto',zIndex:2000,padding:'12px 18px',background:'#102735',color:'#e6fff7',boxShadow:'0 2px 12px #0006',fontFamily:'Arial, sans-serif',fontSize:14,pointerEvents:'none',textTransform:'none'}}><progress aria-label={ko?'화면 이동 중':'Opening page'} style={{display:'block',width:'100%',height:4,marginBottom:8}}/>{slow?(ko?'응답이 지연되고 있습니다. 잠시 기다려 주세요.':'The response is taking longer. Please wait.'):(ko?'화면 이동 중…':'Opening page…')}</span>;
}
const NavigationLink=forwardRef<HTMLAnchorElement,ComponentPropsWithoutRef<typeof NextLink>>(/** NavigationLink: 이동 의도가 있는 링크의 준비와 진행 상태 표시를 연결합니다 주요 호출: useState. */ function NavigationLink({children,prefetch,onMouseEnter,onFocus,...props},ref){
 const [intent,setIntent]=useState(false);
 return <NextLink {...props} ref={ref} prefetch={prefetch===undefined?(intent?null:false):prefetch} onMouseEnter={/** onMouseEnter 콜백: onMouseEnter 이벤트의 입력·상태 처리를 실행합니다 주요 호출: setIntent·onMouseEnter. */ event=>{setIntent(true);onMouseEnter?.(event);}} onFocus={/** onFocus 콜백: onFocus 이벤트의 입력·상태 처리를 실행합니다 주요 호출: setIntent·onFocus. */ event=>{setIntent(true);onFocus?.(event);}}>{children}<PendingNavigation/></NextLink>;
});
export default NavigationLink;
