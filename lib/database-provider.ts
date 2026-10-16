export type DatabaseProvider='postgresql'|'prisma-postgres';
export function databaseProvider(env:Readonly<Record<string,string|undefined>>=process.env):DatabaseProvider{
 const value=env.DATABASE_PROVIDER??'postgresql';
 if(value!=='postgresql'&&value!=='prisma-postgres')throw new Error('Unsupported DATABASE_PROVIDER');
 return value;
}
