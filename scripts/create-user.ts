import { Pool } from 'pg';
import { randomUUID } from 'node:crypto';
import { hashPassword } from '../lib/password';
const email=process.env.BOOTSTRAP_EMAIL?.trim().toLowerCase(),password=process.env.BOOTSTRAP_PASSWORD??'',role=process.env.BOOTSTRAP_ROLE??'admin';
if(!email || !email.includes('@') || !['admin','analyst','viewer'].includes(role))throw new Error('Set valid BOOTSTRAP_EMAIL and BOOTSTRAP_ROLE');
const hash=hashPassword(password),pool=new Pool({connectionString:process.env.DATABASE_URL});
try{await pool.query('INSERT INTO users(id,email,password_hash,role) VALUES($1,$2,$3,$4)',[randomUUID(),email,hash,role]);console.log('User created; remove BOOTSTRAP_PASSWORD from local environment.');}finally{await pool.end();}
