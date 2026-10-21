import {createTheme} from '@mui/material/styles';
export const platformTheme=createTheme({
 palette:{mode:'light',primary:{main:'#276b59'},background:{default:'#ffffff',paper:'#f6f7f8'},text:{primary:'#252a2d',secondary:'#737b80'},divider:'#e5e8e9'},
 typography:{fontFamily:'Inter, "Segoe UI", "Malgun Gothic", Arial, sans-serif',h5:{fontWeight:700},h6:{fontWeight:650,fontSize:'1.05rem'},button:{textTransform:'none',fontWeight:600}},
 shape:{borderRadius:16},
 components:{
  MuiPaper:{defaultProps:{elevation:0},styleOverrides:{root:{backgroundImage:'none'}}},
  MuiButton:{defaultProps:{disableElevation:true},styleOverrides:{root:{borderRadius:10,padding:'9px 16px'}}},
  MuiOutlinedInput:{styleOverrides:{root:{backgroundColor:'#fff',borderRadius:11},notchedOutline:{borderColor:'#dce1e3'}}},
  MuiChip:{styleOverrides:{root:{fontSize:12,height:26}}},
  MuiAlert:{styleOverrides:{root:{borderRadius:12,fontSize:13,lineHeight:1.7}}},
 },
});
