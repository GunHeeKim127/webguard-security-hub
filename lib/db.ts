import 'server-only';
import { Pool } from 'pg';
const globalDb = globalThis as unknown as { wgPool?: Pool };
export const db = globalDb.wgPool ?? new Pool({connectionString:process.env.DATABASE_URL,max:5,connectionTimeoutMillis:3000,statement_timeout:5000});
if (process.env.NODE_ENV !== 'production') globalDb.wgPool = db;
