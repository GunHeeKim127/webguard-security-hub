import {execFile, spawn} from 'node:child_process';
import {promisify} from 'node:util';
import {mkdir, writeFile} from 'node:fs/promises';
import {rootCertificates} from 'node:tls';
import {randomBytes} from 'node:crypto';
import {createServer} from 'node:net';
import path from 'node:path';
import assert from 'node:assert/strict';
import {Pool, type PoolClient} from 'pg';
import {projectDatabase} from '../lib/project-database';

const exec = promisify(execFile);

/** freePort: 별도 복원 서버에 사용할 loopback 포트를 운영 서비스 변경 없이 고릅니다. */
async function freePort(): Promise<number> {
 return new Promise(/** portPromise: 사용 가능한 임시 포트를 찾고 예약 소켓을 닫습니다. */ (resolve, reject) => {
  const server = createServer();
  server.once('error', reject);
  server.listen(0, '127.0.0.1', /** listening: OS가 선택한 포트를 반환합니다. */ () => {
   const address = server.address();
   if (!address || typeof address === 'string') { server.close(); reject(new Error('PORT_UNAVAILABLE')); return; }
   server.close(/** closed: 임시 포트 예약을 해제합니다. */ error => error ? reject(error) : resolve(address.port));
  });
 });
}

/** privateDirectory: 새 백업 폴더의 접근을 현재 OS 사용자로 제한한 후에만 데이터를 씁니다. */
async function privateDirectory(root: string) {
 await mkdir(root, {mode: 0o700});
 if (process.platform === 'win32') {
  const {stdout} = await exec('whoami.exe', ['/user', '/fo', 'csv', '/nh'], {windowsHide: true});
  const sid = stdout.match(/S-1-5-[0-9-]+/)?.[0];
  if (!sid) throw new Error('PRIVATE_DIRECTORY_IDENTITY_UNAVAILABLE');
  await exec('icacls.exe', [root, '/inheritance:r', '/grant:r', `*${sid}:(OI)(CI)F`], {windowsHide: true});
 }
}

/** signature: 동일 스냅샷의 테이블 행 수와 순서 독립 내용 지문을 비교용으로만 계산합니다. */
async function signature(client: PoolClient, table: string) {
 return JSON.stringify((await client.query(`SELECT count(*)::text AS n,md5(coalesce(string_agg(md5(row_to_json(t)::text),'' ORDER BY md5(row_to_json(t)::text)),'')) AS digest FROM ${table} t`)).rows[0]);
}

/** main: 운영은 읽기 전용으로 백업하고 독립 로컬 DB에만 복원한 후 내용과 접근 경계를 확인합니다. */
async function main() {
 if (process.argv.length !== 3 || process.argv[2] !== '--run') throw new Error('USE_EXPLICIT_RUN_FLAG');
 const bin = process.env.PG_BIN;
 if (!bin || !path.isAbsolute(bin)) throw new Error('ABSOLUTE_PG_BIN_REQUIRED');
 const binary = /** binary: 명시된 PostgreSQL 도구 폴더 안의 실행 파일만 선택합니다. */ (name: string) => path.join(bin, name + (process.platform === 'win32' ? '.exe' : ''));
 const settings = projectDatabase('migration'), url = new URL(settings.connectionString);
 const root = path.resolve('work', 'private-recovery-' + new Date().toISOString().replace(/[:.]/g, '-') + '-' + randomBytes(4).toString('hex'));
 await mkdir(path.dirname(root), {recursive: true});
 await privateDirectory(root);
 const dir = path.join(root, 'cluster'), dump = path.join(root, 'logical.dump'), ca = path.join(root, 'root-ca.pem'), pw = path.join(root, 'local-password');
 const password = randomBytes(32).toString('hex'), port = await freePort();
 await writeFile(ca, rootCertificates.join('\n'), {mode: 0o600});
 await writeFile(pw, password, {mode: 0o600});
 // Child processes receive only OS necessities and their specific connection, never the full app environment.
 const osEnv = {NODE_ENV: process.env.NODE_ENV || 'production', PATH: process.env.PATH, SystemRoot: process.env.SystemRoot, TEMP: process.env.TEMP, TMP: process.env.TMP, HOME: process.env.HOME};
 const sourceEnv = {...osEnv, PGHOST: url.hostname, PGPORT: url.port || '5432', PGDATABASE: decodeURIComponent(url.pathname.slice(1)), PGUSER: decodeURIComponent(url.username), PGPASSWORD: decodeURIComponent(url.password), PGSSLMODE: settings.ssl ? 'verify-full' : 'disable', PGSSLROOTCERT: ca, PGCONNECT_TIMEOUT: '15'};
 const localEnv = {...osEnv, PGHOST: '127.0.0.1', PGPORT: String(port), PGDATABASE: 'postgres', PGUSER: 'postgres', PGPASSWORD: password, PGSSLMODE: 'disable'};
 const source = new Pool({...settings, max: 1, connectionTimeoutMillis: 15000, query_timeout: 120000});
 let local: Pool | undefined, client: PoolClient | undefined, initialized = false;
 let verified: Record<string, unknown> | undefined;
 const control = /** control: 자체 임시 DB만 기동·중지하고 명령 출력의 비밀 노출을 막습니다. */ (args: string[]) => new Promise<void>(/** controlPromise: pg_ctl 종료 코드만 확인합니다. */ (resolve, reject) => {
  const child = spawn(binary('pg_ctl'), args, {windowsHide: true, stdio: 'ignore', env: osEnv});
  child.once('error', reject);
  child.once('exit', /** controlExit: 자체 서버 제어 실패만 고정 오류로 반환합니다. */ code => code === 0 ? resolve() : reject(new Error('LOCAL_CLUSTER_CONTROL_FAILED')));
 });
 const began = Date.now();
 try {
  client = await source.connect();
  await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
  await client.query("SET LOCAL TIME ZONE 'UTC'");
  assert((await client.query('SELECT current_database()=$1 AS expected', [process.env.PROJECT_DATABASE])).rows[0].expected);
  const snapshot = (await client.query('SELECT pg_export_snapshot() AS id')).rows[0].id;
  const tables = (await client.query("SELECT schemaname,tablename FROM pg_tables WHERE schemaname IN ('public','webguard_archive') ORDER BY schemaname,tablename")).rows;
  assert(tables.length > 0);
  const signatures = new Map<string, string>();
  for (const row of tables) {
   assert(/^[a-z_][a-z0-9_]*$/.test(row.schemaname) && /^[a-z_][a-z0-9_]*$/.test(row.tablename));
   const table = row.schemaname + '.' + row.tablename;
   signatures.set(table, await signature(client, table));
  }
  await exec(binary('pg_dump'), ['--format=custom', '--no-owner', '--no-privileges', '--schema=public', '--schema=webguard_archive', '--snapshot', snapshot, '--file', dump], {env: sourceEnv, windowsHide: true, timeout: 180000});
  await client.query('ROLLBACK'); client.release(); client = undefined;
  console.log('PASS read-only consistent snapshot backup');
  await exec(binary('initdb'), ['-D', dir, '-A', 'scram-sha-256', '--pwfile', pw, '-U', 'postgres', '--encoding=UTF8', '--locale=C'], {env: osEnv, windowsHide: true, timeout: 60000});
  initialized = true;
  await control(['-D', dir, '-l', path.join(root, 'server.log'), '-o', `-h 127.0.0.1 -p ${port}`, '-w', 'start']);
  const restoreStart = Date.now();
  await exec(binary('pg_restore'), ['--exit-on-error', '--clean', '--if-exists', '--no-owner', '--no-privileges', '--dbname=postgres', dump], {env: localEnv, windowsHide: true, timeout: 180000});
  local = new Pool({host: '127.0.0.1', port, database: 'postgres', user: 'postgres', password, max: 1, query_timeout: 120000});
  const check = await local.connect();
  try {
   await check.query("SET TIME ZONE 'UTC'");
   for (const [table, expected] of signatures) assert.equal(await signature(check, table), expected);
   assert((await check.query("SELECT NOT EXISTS(SELECT 1 FROM public.assessment_runs r LEFT JOIN public.assessment_assets a ON r.asset_id=a.id AND r.user_id=a.user_id WHERE a.id IS NULL) AS valid")).rows[0].valid);
   await check.query('CREATE ROLE restore_unprivileged NOLOGIN');
   const acl = (await check.query("SELECT has_table_privilege('restore_unprivileged','public.users','SELECT') AS users,has_schema_privilege('restore_unprivileged','webguard_archive','USAGE') AS archive")).rows[0];
   assert(!acl.users && !acl.archive);
   verified = {verifiedAt: new Date().toISOString(), fullLogicalData: true, consistentReadOnlySnapshot: true, verifiedTls: Boolean(settings.ssl), tableCount: signatures.size, allCountsAndDigestsMatch: true, ownerForeignKeysValid: true, unprivilegedReadDenied: true, localScramAuthentication: true, restoreDurationMs: Date.now() - restoreStart, productionWrites: false, providerRolesRestored: false, providerPitrTested: false, longTermStabilityProven: false};
  } finally { check.release(); }
 } finally {
  if (client) { await client.query('ROLLBACK').catch(/** rollback: 실패한 읽기 스냅샷의 정리 오류는 별도 데이터로 노출하지 않습니다. */ () => {}); client.release(); }
  await source.end(); await local?.end();
  if (initialized) await control(['-D', dir, '-m', 'fast', '-w', 'stop']);
 }
 assert(verified);
 const result = {...verified, totalDurationMs: Date.now() - began, cleanupComplete: true};
 await writeFile(path.join(root, 'verification.json'), JSON.stringify(result, null, 2));
 console.log(JSON.stringify(result));
}

main().catch(/** failure: 접속 문자열·데이터·도구 stderr 대신 고정 실패 안내만 출력합니다. */ () => {
 console.error('RECOVERY_VERIFICATION_INCOMPLETE: check tool availability, credentials and protected local recovery folder; production was not restored or modified.');
 process.exitCode = 1;
});
