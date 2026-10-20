// Bounded ZIP inventory + explicit APK AXML / IPA plist observations. No extraction/execution.
const fail=()=>{throw new Error('INVALID_PACKAGE');},MAX=1048576;
export function androidSettings(bytes){
 const empty={decoded:false,debuggable:null,allowBackup:null,cleartext:null,arbitraryLoads:null,permissionCount:null};
 try{
  const v=new DataView(bytes.buffer,bytes.byteOffset,bytes.byteLength);if(v.byteLength<8||v.getUint16(0,true)!==3||v.getUint16(2,true)!==8||v.getUint32(4,true)!==v.byteLength)return empty;
  let strings=[],p=8,application=false,permissions=0,result={...empty,decoded:true,permissionCount:0};
  const string=index=>index===0xffffffff?'':strings[index]??fail();
  while(p<v.byteLength){if(p+8>v.byteLength)fail();const type=v.getUint16(p,true),header=v.getUint16(p+2,true),size=v.getUint32(p+4,true);if(header<8||size<header||p+size>v.byteLength)fail();
   if(type===1){if(header<28)fail();const count=v.getUint32(p+8,true),styleCount=v.getUint32(p+12,true),utf8=!!(v.getUint32(p+16,true)&0x100),start=v.getUint32(p+20,true);if(count>20000||styleCount>20000||header+(count+styleCount)*4>size||start<header+(count+styleCount)*4||start>size)fail();strings=[];
    for(let i=0;i<count;i++){let at=p+start+v.getUint32(p+header+i*4,true);const end=p+size;if(at>=end)fail();
     const length=()=>{if(at>=end)fail();if(utf8){let n=v.getUint8(at++);if(n&128){if(at>=end)fail();n=((n&127)<<8)|v.getUint8(at++);}return n;}if(at+2>end)fail();let n=v.getUint16(at,true);at+=2;if(n&0x8000){if(at+2>end)fail();n=((n&0x7fff)*65536)+v.getUint16(at,true);at+=2;}return n;};
     let n=length();if(utf8)n=length();const amount=utf8?n:n*2;if(n>65536||at+amount+(utf8?1:2)>end)fail();if(utf8?v.getUint8(at+amount)!==0:v.getUint16(at+amount,true)!==0)fail();strings.push(new TextDecoder(utf8?'utf-8':'utf-16le',{fatal:true}).decode(bytes.subarray(at,at+amount)));
    }
   }else if(type===0x102){if(header<16||size<header+20)fail();const ext=p+header,tag=string(v.getUint32(ext+4,true)),offset=v.getUint16(ext+8,true),width=v.getUint16(ext+10,true),count=v.getUint16(ext+12,true);if(offset<20||width<20||count>1000||header+offset+width*count>size)fail();if(tag==='uses-permission'||tag==='uses-permission-sdk-23')permissions++;
    if(tag==='application'){if(application)fail();application=true;const seen=new Set();for(let i=0;i<count;i++){const a=ext+offset+i*width,namespace=string(v.getUint32(a,true)),name=string(v.getUint32(a+4,true)),key=({debuggable:'debuggable',allowBackup:'allowBackup',usesCleartextTraffic:'cleartext'})[name];if(namespace!=='http://schemas.android.com/apk/res/android'||!key)continue;if(seen.has(key))fail();seen.add(key);const dataType=v.getUint8(a+15);result[key]=dataType===0x12? v.getUint32(a+16,true)!==0:null;}}
   }
   p+=size;
  }
  if(!application||permissions>10000)return empty;result.permissionCount=permissions;return result;
 }catch{return empty;}
}
export function plistValue(bytes){
 if(new TextDecoder().decode(bytes.subarray(0,8))==='bplist00'){
  const v=new DataView(bytes.buffer,bytes.byteOffset,bytes.byteLength),tail=v.byteLength-32;if(tail<8)fail();const offsetWidth=v.getUint8(tail+6),refWidth=v.getUint8(tail+7);
  const number=(p,n)=>{if(![1,2,4,8].includes(n)||p<0||p+n>v.byteLength)fail();let x=0;for(let i=0;i<n;i++)x=x*256+v.getUint8(p+i);if(!Number.isSafeInteger(x))fail();return x;};
  const count=number(tail+8,8),top=number(tail+16,8),table=number(tail+24,8);if(!count||count>20000||top>=count||table<8||table+count*offsetWidth>tail)fail();let budget=50000;const visiting=new Set();
  const parse=(id,depth=0)=>{if(id>=count||depth>30||--budget<0||visiting.has(id))fail();visiting.add(id);try{let p=number(table+id*offsetWidth,offsetWidth);if(p<8||p>=table)fail();const marker=v.getUint8(p++),type=marker>>4;let n=marker&15;if(n===15&&[4,5,6,10,13].includes(type)){if(p>=table||(v.getUint8(p)>>4)!==1)fail();const width=2**(v.getUint8(p++)&15);n=number(p,width);p+=width;}if(n>MAX)fail();const bound=n*(type===6?2:type===13?2*refWidth:type===10?refWidth:1);if([4,5,6,10,13].includes(type)&&p+bound>table)fail();
   if(type===0)return marker===8?false:marker===9?true:null;if(type===1)return number(p,2**n);
   if(type===5)return new TextDecoder('utf-8',{fatal:true}).decode(bytes.subarray(p,p+n));if(type===6)return new TextDecoder('utf-16be',{fatal:true}).decode(bytes.subarray(p,p+2*n));
   if(type===10)return Array.from({length:n},(_,i)=>parse(number(p+i*refWidth,refWidth),depth+1));
   if(type===13){const result=Object.create(null);for(let i=0;i<n;i++){const key=parse(number(p+i*refWidth,refWidth),depth+1);if(typeof key!=='string'||Object.hasOwn(result,key))fail();result[key]=parse(number(p+(n+i)*refWidth,refWidth),depth+1);}return result;}return null;
  }finally{visiting.delete(id);}};return parse(top);
 }
 // Tiny non-networking plist XML parser. DTD entities/internal subsets are rejected.
 let xml=new TextDecoder('utf-8',{fatal:true}).decode(bytes).replace(/^\uFEFF/,'').replace(/<\?xml[^?]*\?>/,'').replace(/<!DOCTYPE\s+plist\s+PUBLIC\s+"[^"]*"\s+"[^"]*"\s*>/,'');if(/<!/.test(xml))fail();
 const tokens=xml.match(/<[^>]*>|[^<]+/g)??[];let p=0,budget=50000;const skip=()=>{while(p<tokens.length&&!tokens[p].trim())p++;},take=()=>{skip();return tokens[p++];};
 const decode=s=>s.replace(/&(amp|lt|gt|quot|apos);/g,(_,e)=>({amp:'&',lt:'<',gt:'>',quot:'"',apos:"'"})[e]);
 const parse=(depth=0)=>{if(depth>30||--budget<0)fail();const tag=take();if(tag==='<true/>'||tag==='<true />')return true;if(tag==='<false/>'||tag==='<false />')return false;
  if(tag==='<dict>'){const result=Object.create(null);while(true){skip();if(tokens[p]==='</dict>'){p++;return result;}if(take()!=='<key>')fail();const key=decode(tokens[p++]??'');if(take()!=='</key>'||Object.hasOwn(result,key))fail();result[key]=parse(depth+1);}}
  if(tag==='<array>'){const result=[];while(true){skip();if(tokens[p]==='</array>'){p++;return result;}result.push(parse(depth+1));}}
  if(tag==='<dict/>'||tag==='<dict />')return Object.create(null);if(tag==='<array/>'||tag==='<array />')return [];
  if(/^<(string|integer|real|date|data)>$/.test(tag??'')){const name=tag.slice(1,-1);let text='';if(tokens[p]!==`</${name}>`)text=tokens[p++]??'';if(take()!==`</${name}>`)fail();return name==='string'?decode(text):null;}if(/^<(string|data)\s*\/>$/.test(tag??''))return '';fail();};
 if(!/^<plist(?:\s+version="1\.0")?>$/.test(take()??''))fail();const result=parse();if(take()!=='</plist>'){fail();}skip();if(p!==tokens.length)fail();return result;
}
export async function inspectPackage(source){
 if(!Number.isSafeInteger(source.size)||source.size<22||source.size>8*1024**3)fail();let used=0;
 const read=async(o,n)=>{if(!Number.isSafeInteger(o)||!Number.isSafeInteger(n)||o<0||n<0||o+n>source.size||(used+=n)>8*MAX)fail();const b=await source.read(o,n);if(b.byteLength!==n)fail();return b;};
 const tail=await read(Math.max(0,source.size-65557),Math.min(source.size,65557)),tv=new DataView(tail.buffer,tail.byteOffset,tail.byteLength);let end=-1;
 for(let p=tail.length-22;p>=0;p--)if(tv.getUint32(p,true)===0x06054b50&&p+22+tv.getUint16(p+20,true)===tail.length){end=p;break;}
 if(end<0||tv.getUint16(end+4,true)||tv.getUint16(end+6,true))fail();const count=tv.getUint16(end+10,true),size=tv.getUint32(end+12,true),start=tv.getUint32(end+16,true),endAbsolute=source.size-tail.length+end;
 if(!count||count>50000||tv.getUint16(end+8,true)!==count||size>4*MAX||start+size!==endAbsolute)fail();
 const central=await read(start,size),v=new DataView(central.buffer,central.byteOffset,central.byteLength);let p=0;const entries=[],names=new Set();
 for(let i=0;i<count;i++){if(p+46>size||v.getUint32(p,true)!==0x02014b50)fail();const flags=v.getUint16(p+8,true),method=v.getUint16(p+10,true),packed=v.getUint32(p+20,true),unpacked=v.getUint32(p+24,true),nl=v.getUint16(p+28,true),extra=v.getUint16(p+30,true),comment=v.getUint16(p+32,true),offset=v.getUint32(p+42,true),next=p+46+nl+extra+comment;
  if(flags&1||![0,8].includes(method)||v.getUint16(p+34,true)||unpacked===0xffffffff||packed===0xffffffff||!nl||next>size||offset+30+packed>start)fail();
  const name=new TextDecoder('utf-8',{fatal:true}).decode(central.subarray(p+46,p+46+nl));if(names.has(name)||/[\\\0]/.test(name)||name.startsWith('/')||name.split('/').includes('..'))fail();names.add(name);entries.push({name,flags,method,packed,unpacked,offset});p=next;
 }if(p!==size)fail();
 const infos=entries.filter(e=>/^Payload\/[^/]+\.app\/Info\.plist$/.test(e.name)),apks=entries.filter(e=>e.name.endsWith('.apk'));let format;
 if(infos.length===1)format='ipa';else if(names.has('AndroidManifest.xml'))format='apk';else if(names.has('base/manifest/AndroidManifest.xml'))format='aab';else if(names.has('toc.pb')&&apks.length)format='apks';else if(names.has('manifest.json')&&apks.length)format='xapk';else fail();
 const settings={decoded:false,debuggable:null,allowBackup:null,cleartext:null,arbitraryLoads:null,permissionCount:null};
 const selected=format==='ipa'?infos[0]:format==='apk'?entries.find(e=>e.name==='AndroidManifest.xml'):null;
 if(selected&&selected.unpacked<=MAX&&selected.packed<=MAX&&selected.unpacked<=Math.max(selected.packed*100,1024)){
  try{
   const local=await read(selected.offset,30),lv=new DataView(local.buffer,local.byteOffset,local.byteLength),nl=lv.getUint16(26,true),extra=lv.getUint16(28,true),at=selected.offset+30+nl+extra;
   if(lv.getUint32(0,true)!==0x04034b50||lv.getUint16(6,true)!==selected.flags||lv.getUint16(8,true)!==selected.method||at+selected.packed>start)fail();
   if(new TextDecoder('utf-8',{fatal:true}).decode(await read(selected.offset+30,nl))!==selected.name)fail();let bytes=await read(at,selected.packed);
   if(selected.method===8){const reader=new Blob([bytes]).stream().pipeThrough(new DecompressionStream('deflate-raw')).getReader(),chunks=[];let length=0;try{while(true){const r=await reader.read();if(r.done)break;length+=r.value.length;if(length>MAX||length>selected.unpacked)fail();chunks.push(r.value);}}finally{await reader.cancel();}bytes=new Uint8Array(length);let cursor=0;for(const chunk of chunks){bytes.set(chunk,cursor);cursor+=chunk.length;}}
   if(bytes.length!==selected.unpacked)fail();
   if(format==='apk')Object.assign(settings,androidSettings(bytes));else{const plist=plistValue(bytes);if(!plist||typeof plist!=='object'||Array.isArray(plist))fail();settings.decoded=true;const value=plist.NSAppTransportSecurity?.NSAllowsArbitraryLoads;settings.arbitraryLoads=typeof value==='boolean'?value:null;}
  }catch{/* Unsafe/unsupported manifest remains unassessed; never infer defaults. */}
 }
 return {schemaVersion:1,source:'browser',format,size:source.size,entries:count,nestedPackages:apks.length,settings};
}
if(typeof self!=='undefined'&&typeof self.postMessage==='function'&&typeof document==='undefined')self.onmessage=async e=>{try{const file=e.data.file,result=await inspectPackage({size:file.size,read:async(o,n)=>new Uint8Array(await file.slice(o,o+n).arrayBuffer())});self.postMessage({ok:true,result});}catch{self.postMessage({ok:false});}};
