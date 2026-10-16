import 'server-only';
// Validate on first DB operation so an unconfigured project can still build/show login.
export {database as db} from './database-pool';
