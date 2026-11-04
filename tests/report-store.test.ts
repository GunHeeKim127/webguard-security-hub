import test from 'node:test';
import assert from 'node:assert/strict';
import {loadReportSnapshot,REPORT_SNAPSHOT_SQL} from '../lib/assessment/report-store';
import {assertManagedRuntimeSql,assertRuntimeParameters} from '../lib/runtime-sql';

test('report snapshot binds ownership in one read and preserves empty actions',/** test: 보고서 조회의 단일 문장과 계정 바인딩 계약을 확인합니다. */ async()=>{
 let calls=0;
 const result=await loadReportSnapshot(/** query: 실제 전송 전 SQL 경계와 값을 대조합니다. */ async(sql,values)=>{
  calls++;assert.equal(sql,REPORT_SNAPSHOT_SQL);assert.deepEqual(values,['viewer','asset']);assertManagedRuntimeSql(sql);assertRuntimeParameters(sql,values);
  return {rows:[{runs:[{id:'run',report:{} as never,created_at:'2026-11-04T00:00:00Z'}],actions:[]}]};
 },'viewer','asset');
 assert.equal(calls,1);assert.equal(result?.runs[0].created_at,'2026-11-04T00:00:00.000Z');assert.deepEqual(result?.actions,[]);
});
test('report snapshot refuses missing ownership or missing runs',/** test: 소유 자산이나 유효 결과가 없으면 보고서를 생성하지 않습니다. */ async()=>{
 assert.equal(await loadReportSnapshot(/** query: 다른 계정 자산의 빈 조회를 재현합니다. */ async()=>({rows:[]}),'viewer','other'),null);
 assert.equal(await loadReportSnapshot(/** query: 결과가 없는 자산을 재현합니다. */ async()=>({rows:[{runs:[],actions:[]}]}),'viewer','asset'),null);
});
