// Defense against accidental use of the managed runtime client for DDL/admin work.
// This is an application boundary, NOT a replacement for DB ACLs or protection after key theft.
export function assertManagedRuntimeSql(sql:string){
 if(/\bwebguard_archive\b/i.test(sql))throw new Error('Managed runtime archive access rejected');
 const structure=sql.replace(/'(?:''|[^'])*'/g,"''").replace(/"/g,'');
 if(!/^\s*(SELECT|INSERT|UPDATE|DELETE|WITH)\b/i.test(structure)||/[;]|--|\/\*|\*\//.test(structure)||/\b(CREATE|ALTER|DROP|TRUNCATE|GRANT|REVOKE|COPY|RESET|CALL|DISCARD|VACUUM|REINDEX)\b/i.test(structure)||/\b(schema_migrations|scan_duplicate_archive|pg_read_file|pg_read_binary_file|pg_ls_dir|pg_write_file|lo_import|lo_export|dblink|set_config)\b/i.test(structure)||/\b(?:INSERT\s+INTO|UPDATE|DELETE\s+FROM)\s+(?:public\.)?users\b/i.test(structure))throw new Error('Managed runtime SQL rejected');
}
