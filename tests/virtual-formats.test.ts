import test from 'node:test';
import assert from 'node:assert/strict';
import {assessmentInput} from '../lib/assessment/input';
import {runAssessment} from '../lib/assessment/registry';
import {compareAssessments} from '../lib/assessment/compare';
import {infrastructureFileIssue} from '../lib/infrastructure-format';
import {findingContext} from '../lib/assessment/finding-context';
const input=/** input: 검증 시나리오에서 input에 필요한 입력·호출·기대 결과 처리를 제공합니다 주요 호출: assessmentInput. */ (text:string)=>assessmentInput({moduleId:'virtualization.vmx',label:'Local virtual format',authorized:true,text});
const scan=/** scan: 검증 시나리오에서 scan에 필요한 입력·호출·기대 결과 처리를 제공합니다 주요 호출: runAssessment·input·timeout. */ (text:string)=>runAssessment(input(text),{locale:'ko',signal:AbortSignal.timeout(5000)});
test('OVF validates namespace/structure without reading disk references or claiming isolation',/** test 콜백: 테스트: OVF validates namespace/structure without reading disk references or claiming isolation 주요 호출: scan·equal·filter. */ async()=>{
 const r=await scan('<Envelope xmlns="http://schemas.dmtf.org/ovf/envelope/1"><References><File href="https://never-fetch.invalid/SECRET"/></References><VirtualSystem id="PRIVATE_NAME"/></Envelope>');
 assert.equal(r.targetKind,'virtual-config:ovf');assert.equal(r.findings.filter(/** filter 콜백: 조건에 맞는 항목만 고릅니다 */ f=>f.status==='pass').length,0);assert(r.findings.some(/** some 콜백: 조건을 만족하는 항목이 있는지 확인합니다 */ f=>f.status==='not_assessed'));assert(!JSON.stringify(r).includes('PRIVATE_NAME'));assert(!JSON.stringify(r).includes('never-fetch'));
});
test('libvirt sharing/bridge/console declarations warn while sockets and unknowns are distinguished',/** test 콜백: 테스트: libvirt sharing/bridge/console declarations warn while sockets and unknowns are distinguished 주요 호출: scan·equal·filter. */ async()=>{
 const a=await scan('<domain type="kvm"><devices><filesystem><source dir="SECRET_PATH"/></filesystem><interface type="bridge"/><graphics type="vnc" listen="0.0.0.0" passwd="SECRET_PASSWORD"/></devices></domain>');
 assert.equal(a.findings.filter(/** filter 콜백: 조건에 맞는 항목만 고릅니다 */ f=>f.status==='warning').length,3);assert(!JSON.stringify(a).includes('SECRET'));
 const b=await scan('<domain type="kvm"><devices><interface type="network"/><graphics type="spice"><listen type="socket" socket="SECRET_PATH"/></graphics></devices></domain>');assert.equal(b.findings.filter(/** filter 콜백: 조건에 맞는 항목만 고릅니다 */ f=>f.status==='warning'||f.status==='pass').length,0);
 const c=await scan('<domain type="kvm"><devices><graphics type="vnc"/></devices></domain>');assert.equal(c.findings.find(/** find 콜백: 조건에 맞는 첫 항목을 찾습니다 */ f=>f.id==='virtual:console')?.status,'not_assessed');
});
test('VirtualBox declared sharing differs from omitted defaults and other formats cannot be compared',/** test 콜백: 테스트: VirtualBox declared sharing differs from omitted defaults and other formats cannot be compared 주요 호출: scan·equal·filter. */ async()=>{
 const vbox=await scan('<VirtualBox xmlns="http://www.virtualbox.org/"><Machine><Hardware><Clipboard mode="Bidirectional"/><DragAndDrop mode="Disabled"/><SharedFolders><SharedFolder hostPath="SECRET"/></SharedFolders><RemoteDisplay enabled="true"/></Hardware></Machine></VirtualBox>');
 assert.equal(vbox.findings.filter(/** filter 콜백: 조건에 맞는 항목만 고릅니다 */ f=>f.status==='warning').length,3);assert(!JSON.stringify(vbox).includes('SECRET'));
 const missing=await scan('<VirtualBox xmlns="http://www.virtualbox.org/"><Machine><Hardware/></Machine></VirtualBox>');assert(missing.findings.every(/** every 콜백: 모든 항목이 조건을 만족하는지 확인합니다 */ f=>f.status==='not_assessed'));
 const ovf=await scan('<Envelope xmlns="http://schemas.dmtf.org/ovf/envelope/2"><VirtualSystem/></Envelope>');assert.equal(compareAssessments(vbox,ovf).compatible,false);
});
test('malformed, external-entity, wrong namespace, deep and misleading XML fail closed',/** test 콜백: 테스트: malformed, external-entity, wrong namespace, deep and misleading XML fail closed 주요 호출: repeat·throws. */ ()=>{
 for(const xml of ['<!DOCTYPE domain [<!ENTITY x SYSTEM "file:///never-read">]><domain type="kvm"><devices/></domain>','<?xml-stylesheet href="https://never-fetch.invalid"?><domain type="kvm"><devices/></domain>','<domain type="kvm"><devices></domain>','<Envelope xmlns="fake"><VirtualSystem/></Envelope>','<domain type="kvm"><devices/><devices/></domain>','<domain type="kvm"><devices>'+ '<x>'.repeat(50)+'</x>'.repeat(50)+'</devices></domain>'])assert.throws(/** throws 콜백: throws에서 전달한 값을 처리하는 콜백입니다 주요 호출: input. */ ()=>input(xml));
});
test('unsupported disk/archive/capture formats have actionable messages without executing them',/** test 콜백: 테스트: unsupported disk/archive/capture formats have actionable messages without executing them 주요 호출: match·infrastructureFileIssue·equal. */ ()=>{
 for(const ext of ['ova','vmdk','qcow2','vhdx'])assert.match(infrastructureFileIssue('file.'+ext,'virtualization.vmx','ko')!,/확인 불가/);
 for(const ext of ['gns3project','pkt','pcapng'])assert.match(infrastructureFileIssue('file.'+ext,'network.gns3','en')!,/Unsupported/);
 for(const ext of ['ovf','xml','vbox','vmx'])assert.equal(infrastructureFileIssue('file.'+ext,'virtualization.vmx','en'),null);
});

test('virtual finding context explains explicit observations and missing effective evidence',/** 검증 콜백: OVF와 공유 선언의 사용자 설명이 실제 관찰 및 미확인을 구체적으로 구분하는지 확인합니다. */ async()=>{
 const ovf=await scan('<Envelope xmlns="http://schemas.dmtf.org/ovf/envelope/1"><VirtualSystem/></Envelope>');
 assert.match(findingContext(ovf.findings[0],ovf,'ko').observed,/1개/);
 const r=await scan('<domain type="kvm"><devices><filesystem/></devices></domain>');
 assert.match(findingContext(r.findings[0],r,'ko').observed,/1개/);
 assert.match(findingContext(r.findings.at(-1)!,r,'en').observed,/No live VM/);
});
