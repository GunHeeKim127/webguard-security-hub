// Synthetic parser inputs only. Never execute, install or apply these files.
import {mkdir,writeFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {inspectExecutable} from '../public/tools/executable-inspector.mjs';
import {inspectPackage} from '../public/tools/package-inspector.mjs';
import {assessmentInput} from '../lib/assessment/input';
import {runAssessment} from '../lib/assessment/registry';
import {compareAssessments} from '../lib/assessment/compare';
import type {ModuleId} from '../lib/assessment/types';
const root='tests/fixtures/phase2',evidence='docs/assets/phase2-fixtures-2026-10-27';
await mkdir(root,{recursive:true});await mkdir(evidence,{recursive:true});
/** pe: 격리 검증용 최소 PE 입력을 만듭니다 주요 호출: alloc·write·writeUInt32LE. */ function pe(safe:boolean){const b=Buffer.alloc(1024);b.write('MZ');b.writeUInt32LE(64,60);b.writeUInt32LE(0x4550,64);b.writeUInt16LE(1,70);b.writeUInt16LE(240,84);b.writeUInt16LE(0x20b,88);b.writeUInt16LE(safe?0x140:0,158);b.writeUInt32LE(16,196);b.writeUInt32LE(512,344);b.writeUInt32LE(512,348);b.writeUInt32LE(safe?0x60000020:0xe0000020,364);return b;}
/** mac: 격리 검증용 최소 Mach-O 입력을 만듭니다 주요 호출: alloc·writeUInt32LE. */ function mac(safe:boolean){const b=Buffer.alloc(104);b.writeUInt32LE(0xfeedfacf);b.writeUInt32LE(2,12);b.writeUInt32LE(1,16);b.writeUInt32LE(72,20);b.writeUInt32LE(safe?0x200000:0x20000,24);b.writeUInt32LE(0x19,32);b.writeUInt32LE(72,36);b.writeUInt32LE(safe?5:7,92);return b;}
/** crc: 주어진 바이트의 CRC 검증 값을 계산합니다 */ function crc(bytes:Uint8Array){let x=0xffffffff;for(const byte of bytes){x^=byte;for(let i=0;i<8;i++)x=(x>>>1)^((x&1)?0xedb88320:0);}return (x^0xffffffff)>>>0;}
/** zip: 격리 검증에 사용할 최소 ZIP 컨테이너를 생성합니다 주요 호출: entries·from·alloc. */ function zip(files:Record<string,Uint8Array>){const locals:Buffer[]=[],central:Buffer[]=[];let offset=0;for(const [filename,bytes]of Object.entries(files)){const name=Buffer.from(filename),l=Buffer.alloc(30),c=Buffer.alloc(46),sum=crc(bytes);l.writeUInt32LE(0x04034b50);l.writeUInt16LE(20,4);l.writeUInt32LE(sum,14);l.writeUInt32LE(bytes.length,18);l.writeUInt32LE(bytes.length,22);l.writeUInt16LE(name.length,26);c.writeUInt32LE(0x02014b50);c.writeUInt16LE(20,6);c.writeUInt32LE(sum,16);c.writeUInt32LE(bytes.length,20);c.writeUInt32LE(bytes.length,24);c.writeUInt16LE(name.length,28);c.writeUInt32LE(offset,42);locals.push(l,name,Buffer.from(bytes));central.push(c,name);offset+=l.length+name.length+bytes.length;}const end=Buffer.alloc(22),c=Buffer.concat(central);end.writeUInt32LE(0x06054b50);end.writeUInt16LE(central.length/2,8);end.writeUInt16LE(central.length/2,10);end.writeUInt32LE(c.length,12);end.writeUInt32LE(offset,16);return Buffer.concat([...locals,c,end]);}
/** axml: 격리 검증용 Android XML 입력을 만듭니다 주요 호출: map·alloc·reduce. */ function axml(safe:boolean){
 const strings=['application','http://schemas.android.com/apk/res/android','debuggable','allowBackup','usesCleartextTraffic'];
 const data=strings.map(/** map 콜백: 각 항목을 필요한 값으로 변환합니다 주요 호출: concat·from. */ s=>Buffer.concat([Buffer.from([s.length,s.length]),Buffer.from(s),Buffer.from([0])]));
 const pool=Buffer.alloc(28+4*strings.length+data.reduce(/** reduce 콜백: 각 항목을 누적 결과에 합칩니다 */ (n,b)=>n+b.length,0));pool.writeUInt16LE(1);pool.writeUInt16LE(28,2);pool.writeUInt32LE(pool.length,4);pool.writeUInt32LE(strings.length,8);pool.writeUInt32LE(0x100,16);pool.writeUInt32LE(28+strings.length*4,20);let offset=0;data.forEach(/** forEach 콜백: 각 항목의 처리를 순서대로 실행합니다 주요 호출: writeUInt32LE·copy. */ (b,i)=>{pool.writeUInt32LE(offset,28+i*4);b.copy(pool,28+strings.length*4+offset);offset+=b.length;});
 const element=Buffer.alloc(96);element.writeUInt16LE(0x102);element.writeUInt16LE(16,2);element.writeUInt32LE(element.length,4);element.writeUInt32LE(0xffffffff,16);element.writeUInt32LE(0,20);element.writeUInt16LE(20,24);element.writeUInt16LE(20,26);element.writeUInt16LE(3,28);
 for(let i=0;i<3;i++){const p=36+20*i;element.writeUInt32LE(1,p);element.writeUInt32LE(2+i,p+4);element.writeUInt32LE(0xffffffff,p+8);element.writeUInt16LE(8,p+12);element[p+15]=0x12;element.writeUInt32LE(safe?0:1,p+16);}
 const body=Buffer.concat([pool,element]),h=Buffer.alloc(8);h.writeUInt16LE(3);h.writeUInt16LE(8,2);h.writeUInt32LE(body.length+8,4);return Buffer.concat([h,body]);
}
const specs:[string,ModuleId,string,(safe:boolean)=>Uint8Array|string][]=[
 ['linux','linux.ssh','sshd_config',/** 처리 콜백: 처리에서 전달한 값을 처리하는 콜백입니다 */ s=>`# SYNTHETIC REVIEW COPY - DO NOT APPLY\nPermitRootLogin ${s?'no':'yes'}\nPasswordAuthentication ${s?'no':'yes'}\nPermitEmptyPasswords ${s?'no':'yes'}\nPubkeyAuthentication ${s?'yes':'no'}\nMaxAuthTries ${s?'4':'10'}\n`],
 ['windows','windows.policy','json',/** 처리 콜백: 처리에서 전달한 값을 처리하는 콜백입니다 주요 호출: stringify. */ s=>JSON.stringify({schemaVersion:1,firewall:{domain:s,private:s,public:s},defender:{antivirus:s,realtime:s},rdp:{enabled:true,nla:s}},null,2)],
 ['vmware','virtualization.vmx','vmx',/** 처리 콜백: 처리에서 전달한 값을 처리하는 콜백입니다 주요 호출: join·map. */ s=>`config.version = "8"\nvirtualHW.version = "20"\n${['copy','paste','dnd','hgfs'].map(/** map 콜백: 각 항목을 필요한 값으로 변환합니다 */ k=>`isolation.tools.${k}.disable = "${s?'TRUE':'FALSE'}"`).join('\n')}\nRemoteDisplay.vnc.enabled = "${s?'FALSE':'TRUE'}"\nethernet0.present = "TRUE"\nethernet0.connectionType = "${s?'hostonly':'bridged'}"\n`],
 ['gns3','network.gns3','gns3',/** 처리 콜백: 처리에서 전달한 값을 처리하는 콜백입니다 주요 호출: stringify. */ s=>JSON.stringify({type:'topology',version:'2.2.61',topology:{nodes:[{node_id:'review-node',node_type:s?'vpcs':'cloud',console_host:s?'127.0.0.1':'0.0.0.0'}],links:[]}},null,2)],
 ['windows-pe','application.pe','exe',pe],['macos-macho','application.macho','macho',mac],
 ['android','application.package','apk',/** 처리 콜백: 처리에서 전달한 값을 처리하는 콜백입니다 주요 호출: zip·axml·from. */ s=>zip({'AndroidManifest.xml':axml(s),'classes.dex':Buffer.from('SYNTHETIC NON-INSTALLABLE TEST ONLY')})],
 ['ios','application.package','ipa',/** 처리 콜백: 처리에서 전달한 값을 처리하는 콜백입니다 주요 호출: zip·from. */ s=>zip({'Payload/Review.app/Info.plist':Buffer.from(`<?xml version="1.0"?><plist version="1.0"><dict><key>NSAppTransportSecurity</key><dict><key>NSAllowsArbitraryLoads</key><${s?'false':'true'}/></dict></dict></plist>`)})]
];
const pairs=[];
for(const [name,moduleId,extension,make]of specs){const runs=[];
 for(const safe of [false,true]){const bytes=Buffer.from(make(safe)),filename=`${name}-${safe?'remediated':'vulnerable'}.${extension}`;await writeFile(`${root}/${filename}`,bytes);
  const source={size:bytes.length,read:/** 처리 콜백: 처리에서 전달한 값을 처리하는 콜백입니다 주요 호출: subarray. */ async(o:number,n:number)=>bytes.subarray(o,o+n)};
  const payload=moduleId==='application.package'?{snapshot:await inspectPackage(source)}:moduleId==='application.pe'||moduleId==='application.macho'?{snapshot:await inspectExecutable(source,moduleId==='application.pe'?'pe':'macho')}:{text:bytes.toString('utf8')};
  const result=await runAssessment(assessmentInput({moduleId,label:`Review ${name}`,authorized:true,...payload}),{locale:'ko',signal:AbortSignal.timeout(5000)});
  runs.push({filename,sha256:createHash('sha256').update(bytes).digest('hex'),bytes:bytes.length,counts:Object.fromEntries(['warning','pass','info','not_assessed'].map(/** map 콜백: 각 항목을 필요한 값으로 변환합니다 주요 호출: filter. */ status=>[status,result.findings.filter(/** filter 콜백: 조건에 맞는 항목만 고릅니다 */ f=>f.status===status).length])),result});
 }
 pairs.push({name,moduleId,runs,comparison:compareAssessments(runs[0].result,runs[1].result)});
}
await writeFile(`${evidence}/fixture-results.json`,JSON.stringify({generatedAt:new Date().toISOString(),synthetic:true,originalsExecuted:false,pairs},null,2)+'\n');
await writeFile(`${root}/README.md`,`# 2단계 합성 검증 파일\n\n취약 선언(vulnerable)과 보완 선언(remediated)을 비교하는 **더미 입력**입니다. 악성코드 샘플이 아닙니다. 실행·설치·VM/GNS3 시작·실제 OS 설정 적용을 하지 마세요. EXE/Mach-O/APK/IPA는 최소 파서 입력이며 정상 프로그램이나 설치 가능한 앱이 아닙니다. 보완 파일도 안전 인증을 뜻하지 않습니다.\n\n작전실에서 해당 검사 종류를 선택하고 같은 자산 이름으로 두 파일을 차례로 검사한 뒤 실행 이력을 비교하세요. 실행 파일·모바일 패키지는 선택 파일 읽기에 별도 동의해야 검사합니다. Linux/Windows/VMX/GNS3는 설정 텍스트를 선택합니다.\n\n생성: node + tsx scripts/generate-review-fixtures.ts. 결과와 SHA-256: [검증 근거](../../../docs/PROGRESS_HANDOFF_2026-11-02.md). OS 서명·현재 장비·실제 통신·설치 여부는 미검사로 유지합니다. GNS3 2.x 구조만 지원하며 실제 GNS3 앱/장비 버전 호환성을 증명하지 않습니다.\n`);
console.log(pairs.map(/** map 콜백: 각 항목을 필요한 값으로 변환합니다 */ p=>({name:p.name,before:p.runs[0].counts,after:p.runs[1].counts})));
