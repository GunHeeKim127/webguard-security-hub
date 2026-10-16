import type { Metadata } from 'next';
export const metadata:Metadata={title:'WebGuard Security Hub',description:'Authorized web security checks and traffic signals',robots:{index:false,follow:false}};
export default function Layout({children}:{children:React.ReactNode}){return <html lang="ko"><body style={{margin:0,background:'#091321'}}>{children}</body></html>;}
