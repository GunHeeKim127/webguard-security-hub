/** PageLoading: 페이지 준비·이동 중 안내와 진행 막대를 화면 중앙에 표시합니다. */
export default function PageLoading({message,overlay=false}:{message:string,overlay?:boolean}){
 return <span role="status" aria-live="polite" aria-busy="true" data-page-loading="true" style={{position:'fixed',inset:0,zIndex:2000,display:'grid',placeItems:'center',padding:24,boxSizing:'border-box',background:overlay?'rgba(9,19,33,.88)':'#091321',color:'#e6fff7',fontFamily:'Arial, sans-serif',textTransform:'none',pointerEvents:'none'}}>
  <span style={{display:'block',width:320,maxWidth:'100%',textAlign:'center',padding:24,boxSizing:'border-box',border:'1px solid #294451',borderRadius:16,background:'#111f31',boxShadow:'0 12px 40px #0005'}}>
   <span style={{display:'block',marginBottom:18,fontSize:15,lineHeight:1.6}}>{message}</span>
   <progress aria-label={message} style={{display:'block',width:'100%',height:6,accentColor:'#66e6c3'}}/>
  </span>
 </span>;
}
