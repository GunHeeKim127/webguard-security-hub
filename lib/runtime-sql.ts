// Defense against accidental use of the runtime client for DDL/admin work.
// This is an application boundary, NOT a replacement for DB ACLs or protection after key theft.
/** assertManagedRuntimeSql: 런타임에 허용된 SQL 경계를 검증합니다 주요 호출: replace. */ export function assertManagedRuntimeSql(sql:string){
 if(typeof sql!=='string'||sql.length>65536||sql.includes('\\')||sql.includes('\0'))throw new Error('Runtime SQL encoding rejected');
 if(/\bwebguard_archive\b/i.test(sql))throw new Error('Managed runtime archive access rejected');
 const structure=sql.replace(/'(?:''|[^'])*'/g,"''").replace(/"/g,'');
 // Runtime does not need credential catalogs or arbitrary privileged functions.
 // Keep the two fixed pg_* readiness helpers; this remains an application backstop, not DB ACLs.
 if(/\b(?:pg_authid|pg_auth_members|pg_shadow|pg_user_mapping|pg_user_mappings|pg_foreign_server|pg_stat_activity|pg_stat_statements|pg_settings|pg_file_settings)\b/i.test(structure))throw new Error('Runtime SQL catalog rejected');
 for(const call of structure.matchAll(/\b((?:pg_|lo_|dblink)[a-z0-9_]*)\s*\(/gi))if(!['pg_get_userbyid','pg_get_constraintdef'].includes(call[1].toLowerCase()))throw new Error('Runtime SQL privileged function rejected');
 for(const call of structure.matchAll(/\bpublic\s*\.\s*([a-z_][a-z0-9_]*)\s*\(/gi))if(!['register_viewer','archive_diagnostics_30d','sessions','scans','events','rate_limits','ip_blocks','account_blocks','ai_advice_cache','assessment_assets','assessment_runs','assessment_traffic','assessment_remediations','assessment_remediation_events'].includes(call[1].toLowerCase()))throw new Error('Runtime SQL public function rejected');
 // Reject alternate literal syntax and side-effectful SELECT helpers as well.
 // User values must remain bound parameters, never executable SQL fragments.
 if(/\$(?:[a-z_][a-z0-9_]*)?\$/i.test(structure)||/\b(?:pg_sleep(?:_for|_until)?|pg_stat_file|pg_notify|pg_terminate_backend|pg_cancel_backend|pg_reload_conf|pg_rotate_logfile|pg_advisory\w*|lo_get|lo_put|query_to_xml|database_to_xml|table_to_xml)\s*\(/i.test(structure)||/\bSELECT\b(?:(?!\b(?:SELECT|INSERT|UPDATE|DELETE|FROM)\b)[\s\S])*\bINTO\b/i.test(structure))throw new Error('Runtime SQL side effect rejected');
 if(!/^\s*(SELECT|INSERT|UPDATE|DELETE|WITH)\b/i.test(structure)||/[;]|--|\/\*|\*\//.test(structure)||/\b(CREATE|ALTER|DROP|TRUNCATE|GRANT|REVOKE|COPY|RESET|CALL|DISCARD|VACUUM|REINDEX)\b/i.test(structure)||/\b(schema_migrations|scan_duplicate_archive|pg_read_file|pg_read_binary_file|pg_ls_dir|pg_write_file|lo_import|lo_export|dblink|set_config)\b/i.test(structure)||/\b(?:INSERT\s+INTO|UPDATE|DELETE\s+FROM)\s+(?:public\.)?users\b/i.test(structure))throw new Error('Managed runtime SQL rejected');
}

/** assertRuntimeParameters: 값은 SQL 밖의 연속된 바인딩 자리와 정확하게 대응해야 합니다. */
export function assertRuntimeParameters(sql:string,values:unknown[]|undefined){
 if(values!==undefined&&!Array.isArray(values))throw new Error('Runtime SQL parameters rejected');
 const parameters=[...sql.replace(/'(?:''|[^'])*'/g,"''").matchAll(/\$(\d+)/g)],count=values?.length??0;
 if(count>128||parameters.some(/** some: 잘못된 자리 번호와 범위 밖 참조를 거절합니다. */ p=>!/^\$[1-9]\d{0,2}$/.test(p[0])||Number(p[1])>count))throw new Error('Runtime SQL parameters rejected');
 const used=new Set(parameters.map(/** map: SQL 구조에서 실제로 참조한 값 자리만 수집합니다. */ p=>Number(p[1])));
 if(used.size!==count)throw new Error('Runtime SQL parameters rejected');
}

/** assertReadinessSql: 함수 서명을 담은 상수와 실제 함수 호출을 구분해 준비 검사에 읽기만 허용합니다. */
export function assertReadinessSql(sql:string){
 assertManagedRuntimeSql(sql);assertRuntimeParameters(sql,undefined);
 const structure=sql.replace(/'(?:''|[^'])*'/g,"''");
 if(!/^\s*SELECT\b/i.test(structure)||/\b(?:register_viewer|archive_diagnostics_30d)\s*\(/i.test(structure))throw new Error('Readiness requires fixed read-only SQL');
}
