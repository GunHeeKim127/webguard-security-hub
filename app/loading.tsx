export default function Loading(){
 return <main aria-busy="true" style={{maxWidth:900,margin:'auto',padding:'32px 20px',fontFamily:'Arial, sans-serif',color:'#e6fff7',minHeight:'60vh'}}><p role="status">화면을 준비하고 있습니다… / Loading…</p><progress aria-label="Loading" style={{width:'100%',height:4}}/><div aria-hidden="true" style={{height:140,marginTop:24,borderRadius:14,background:'#111f31'}}/><div aria-hidden="true" style={{height:240,marginTop:20,borderRadius:14,background:'#111f31'}}/></main>;
}
