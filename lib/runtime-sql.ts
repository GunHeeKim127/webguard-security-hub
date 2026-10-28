// Defense against accidental use of the runtime client for DDL/admin work.
// This is an application boundary, NOT a replacement for DB ACLs or protection after key theft.
export function assertManagedRuntimeSql(sql:string){
 if(/\bwebguard_archive\b/i.test(sql))throw new Error('Managed runtime archive access rejected');
 const structure=sql.replace(/'(?:''|[^'])*'/g,"''").replace(/"/g,'');
 // Reject alternate literal syntax and side-effectful SELECT helpers as well.
 // User values must remain bound parameters, never executable SQL fragments.
 if(/\$(?:[a-z_][a-z0-9_]*)?\$/i.test(structure)||/\b(?:pg_sleep(?:_for|_until)?|pg_stat_file|pg_notify|pg_terminate_backend|pg_cancel_backend|pg_reload_conf|pg_rotate_logfile|pg_advisory\w*|lo_get|lo_put|query_to_xml|database_to_xml|table_to_xml)\s*\(/i.test(structure)||/\bSELECT\b(?:(?!\b(?:SELECT|INSERT|UPDATE|DELETE|FROM)\b)[\s\S])*\bINTO\b/i.test(structure))throw new Error('Runtime SQL side effect rejected');
 if(!/^\s*(SELECT|INSERT|UPDATE|DELETE|WITH)\b/i.test(structure)||/[;]|--|\/\*|\*\//.test(structure)||/\b(CREATE|ALTER|DROP|TRUNCATE|GRANT|REVOKE|COPY|RESET|CALL|DISCARD|VACUUM|REINDEX)\b/i.test(structure)||/\b(schema_migrations|scan_duplicate_archive|pg_read_file|pg_read_binary_file|pg_ls_dir|pg_write_file|lo_import|lo_export|dblink|set_config)\b/i.test(structure)||/\b(?:INSERT\s+INTO|UPDATE|DELETE\s+FROM)\s+(?:public\.)?users\b/i.test(structure))throw new Error('Managed runtime SQL rejected');
}
