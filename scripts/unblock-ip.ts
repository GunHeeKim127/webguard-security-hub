import {Pool} from 'pg';
import {projectDatabase} from '../lib/project-database';
import {normalizeIp} from '../lib/ingress-guard';
const address=normalizeIp(process.argv[2]);if(!address)throw new Error('Provide one IPv4 or IPv6 address');
const pool=new Pool(projectDatabase('migration'));
try{const result=await pool.query(`WITH reset AS (
 UPDATE public.ip_blocks SET strikes=0,blacklisted=false,blocked_until=NULL,last_reason='manual_reset',last_seen=now() WHERE address=$1::inet RETURNING address
), logged AS (INSERT INTO public.events(category) SELECT 'ip_unblocked' FROM reset RETURNING id)
SELECT count(*) FROM logged`,[address]);console.log(result.rows[0].count==='0'?'No matching block':'IP block reset; audit event recorded');}finally{await pool.end();}
