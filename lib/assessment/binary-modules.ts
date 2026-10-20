import {createHash} from 'node:crypto';
import {binaryInput,checkpoint,pick,report,type SecurityScanner,type Finding} from './types';
const peRef='https://learn.microsoft.com/en-us/windows/win32/debug/pe-format';
export function peMetadata(b:Buffer){
 if(b.length<64||b.toString('ascii',0,2)!=='MZ')throw new Error('INPUT_INVALID');
 const pe=b.readUInt32LE(60);if(pe<64||pe+24>b.length||b.readUInt32LE(pe)!==0x4550)throw new Error('INPUT_INVALID');
 const count=b.readUInt16LE(pe+6),size=b.readUInt16LE(pe+20),o=pe+24;if(count<1||count>96||o+size+count*40>b.length||size<96)throw new Error('INPUT_INVALID');
 const magic=b.readUInt16LE(o);if(![0x10b,0x20b].includes(magic)||size<(magic===0x20b?112:96))throw new Error('INPUT_INVALID');
 let writableExecutable=0;
 for(let n=0;n<count;n++){const s=o+size+n*40,raw=b.readUInt32LE(s+20),bytes=b.readUInt32LE(s+16),flags=b.readUInt32LE(s+36);if(bytes&&(raw+bytes>b.length||raw<o+size+count*40))throw new Error('INPUT_INVALID');if((flags&0xa0000000)>>>0===0xa0000000)writableExecutable++;}
 const directories=b.readUInt32LE(o+(magic===0x20b?108:92)),base=o+(magic===0x20b?112:96);let certificate=false;
 if(directories>4&&base+40<=o+size){const off=b.readUInt32LE(base+32),len=b.readUInt32LE(base+36);if(off&&len){if(off+len>b.length||len<8)throw new Error('INPUT_INVALID');certificate=true;}}
 return {flags:b.readUInt16LE(o+70),writableExecutable,certificate,sha256:createHash('sha256').update(b).digest('hex')};
}
export const peScanner:SecurityScanner={id:'application.pe',version:'1.0.0',targetKind:'windows-pe-file',maxBytes:2097152,validate(input){peMetadata(binaryInput(input));},async scan(input,ctx){
 checkpoint(ctx);const meta=peMetadata(binaryInput(input));
 const findings:Finding[]=[
  ...([['aslr',0x40,'ASLR 선언 플래그','ASLR declaration flag'],['nx',0x100,'DEP/NX 선언 플래그','DEP/NX declaration flag']] as const).map(([id,flag,ko,en])=>({id,title:pick(ctx,ko,en),status:meta.flags&flag?'pass' as const:'warning' as const,severity:meta.flags&flag?'info' as const:'medium' as const,evidence:[`declared=${!!(meta.flags&flag)}`],remediation:pick(ctx,'빌드 설정과 실제 로더 적용 여부를 검토하세요. 플래그만으로 런타임 보호를 증명하지 않습니다.','Review build options and effective loader behavior. A flag alone does not establish runtime protection.'),reference:peRef})),
  {id:'writable-executable',title:pick(ctx,'쓰기·실행 동시 선언 섹션','Sections declared writable and executable'),status:meta.writableExecutable?'warning':'pass',severity:meta.writableExecutable?'medium':'info',evidence:[`sectionCount=${meta.writableExecutable}`],remediation:pick(ctx,'섹션 권한과 패커/JIT 사용을 검토하고 필요한 경우 빌드를 수정하세요.','Review section permissions and packer/JIT requirements before changing the build.'),reference:peRef},
  {id:'authenticode',title:pick(ctx,'서명 신뢰 검증','Signature trust validation'),status:'not_assessed',severity:'info',evidence:[`certificateTableObserved=${meta.certificate}`],remediation:pick(ctx,'승인된 Windows 환경에서 Authenticode 체인·유효기간·파일 해시를 검증하세요. 테이블 존재는 서명 유효성을 뜻하지 않습니다.','Verify the Authenticode chain, validity and file hash on an approved Windows host. A certificate table is not a valid-signature verdict.'),reference:peRef},
  {id:'file-fingerprint',title:pick(ctx,'파일 지문','File fingerprint'),status:'info',severity:'info',evidence:[`sha256=${meta.sha256}`],remediation:pick(ctx,'배포자가 제공한 신뢰 가능한 해시와 별도로 대조하세요.','Compare with a trusted publisher-provided hash.')},
 ];
 return report(this,findings,['PE32 / PE32+ header baseline, max 2 MiB'],[pick(ctx,'파일 실행·악성코드 판정·의존성 CVE·런타임 분석·MSI는 미지원입니다.','No execution, malware verdict, dependency CVEs, runtime analysis or MSI support.')]);
}};
export function apkMetadata(b:Buffer){
 let end=-1;for(let i=b.length-22;i>=Math.max(0,b.length-65557);i--)if(b.readUInt32LE(i)===0x06054b50&&i+22+b.readUInt16LE(i+20)===b.length){end=i;break;}
 if(end<0||b.readUInt16LE(end+4)||b.readUInt16LE(end+6))throw new Error('INPUT_INVALID');
 const count=b.readUInt16LE(end+10),size=b.readUInt32LE(end+12),start=b.readUInt32LE(end+16);
 if(!count||count>5000||count!==b.readUInt16LE(end+8)||size>1048576||start+size!==end)throw new Error('INPUT_INVALID');
 let p=start,manifest=false,dex=false,native=0;const names=new Set<string>();
 for(let i=0;i<count;i++){
  if(p+46>end||b.readUInt32LE(p)!==0x02014b50)throw new Error('INPUT_INVALID');
  const flags=b.readUInt16LE(p+8),method=b.readUInt16LE(p+10),packed=b.readUInt32LE(p+20),nameLen=b.readUInt16LE(p+28),extra=b.readUInt16LE(p+30),comment=b.readUInt16LE(p+32),local=b.readUInt32LE(p+42),next=p+46+nameLen+extra+comment;
  if(flags&1||![0,8].includes(method)||b.readUInt16LE(p+34)!==0||b.readUInt32LE(p+24)===0xffffffff||packed===0xffffffff||next>end||local+30>start||b.readUInt32LE(local)!==0x04034b50)throw new Error('INPUT_INVALID');
  const name=b.subarray(p+46,p+46+nameLen),text=name.toString('utf8'),ln=b.readUInt16LE(local+26),le=b.readUInt16LE(local+28);
  if(!nameLen||names.has(text)||text.includes('\0')||text.split(/[\\/]/).includes('..')||text.startsWith('/')||local+30+ln+le+packed>start||ln!==nameLen||!b.subarray(local+30,local+30+ln).equals(name)||b.readUInt16LE(local+6)!==flags||b.readUInt16LE(local+8)!==method)throw new Error('INPUT_INVALID');
  names.add(text);manifest ||=text==='AndroidManifest.xml';dex ||= /^classes(?:\d+)?\.dex$/.test(text);if(text.startsWith('lib/')&&text.endsWith('.so'))native++;p=next;
 }
 if(p!==end||!manifest)throw new Error('INPUT_INVALID');return {entries:count,dex,native,sha256:createHash('sha256').update(b).digest('hex')};
}
export const apkScanner:SecurityScanner={id:'application.apk',version:'1.0.0',targetKind:'android-apk-file',maxBytes:2097152,validate(input){apkMetadata(binaryInput(input));},async scan(input,ctx){
 checkpoint(ctx);const meta=apkMetadata(binaryInput(input));
 const findings:Finding[]=[{id:'package-structure',title:pick(ctx,'APK 컨테이너 구조','APK container structure'),status:'info',severity:'info',evidence:[`entries=${meta.entries}`,`dexObserved=${meta.dex}`,`nativeEntries=${meta.native}`,`sha256=${meta.sha256}`],remediation:pick(ctx,'이 결과는 패키지 목록 관찰입니다. 앱의 안전성이나 설치 가능성을 보장하지 않습니다.','This observes package inventory, not application safety or installability.')},
 ...(['permissions','debuggable','exported-components','signature-trust'] as const).map(id=>({id,title:pick(ctx,({permissions:'앱 권한',debuggable:'디버그 설정','exported-components':'외부 공개 컴포넌트','signature-trust':'앱 서명 신뢰'})[id],id),status:'not_assessed' as const,severity:'info' as const,evidence:['binaryManifestNotDecoded=true'],remediation:pick(ctx,'승인된 Android 분석 환경에서 바이너리 Manifest와 APK 서명을 검증하세요. 이 모듈은 압축 해제·코드 실행·AXML 분석을 하지 않습니다.','Use an approved Android analysis environment to inspect the binary manifest and APK signature. This module does not extract, execute or decode AXML.'),reference:'https://developer.android.com/studio/debug/apk-analyzer'}))];
 return report(this,findings,['ZIP central/local header consistency and inventory, max 2 MiB'],[pick(ctx,'APK 구조의 예비 점검만 지원합니다. 권한·서명·코드 취약점은 미검사이며 ZIP64·분할 ZIP은 거절합니다.','Preliminary container inspection only. Permissions, signatures and code vulnerabilities are unassessed; ZIP64 and split ZIP are rejected.')]);
}};
