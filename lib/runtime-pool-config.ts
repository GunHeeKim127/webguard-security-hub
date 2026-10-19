import {projectDatabase} from './project-database';
import {databaseProvider} from './database-provider';
import type {PoolConfig} from 'pg';

// Shared by the Next.js handlers and the local socket guard.
export function runtimePoolConfig():PoolConfig{
 const managed=databaseProvider()==='prisma-postgres';
 // Prisma rejects statement_timeout in startup parameters. Client timeout does
 // not guarantee cancellation of a query already executing at the provider.
 return {...projectDatabase('runtime'),...(managed?{query_timeout:5000}:{statement_timeout:5000}),
  max:process.env.VERCEL==='1'?2:5,connectionTimeoutMillis:managed?10000:5000,idleTimeoutMillis:5000,allowExitOnIdle:true};
}
