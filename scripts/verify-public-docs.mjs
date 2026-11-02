import {execFileSync} from 'node:child_process';
import {readFileSync,existsSync} from 'node:fs';
// Report locations only; never print a matched credential or private value.
const patterns=[/\b(?:ghp_|github_pat_)[A-Za-z0-9_]{30,}/,/\bAKIA[0-9A-Z]{16}\b/,/\bsk-(?:proj-)?[A-Za-z0-9_-]{40,}/,/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----\r?\n[A-Za-z0-9+/=\r\n]{40,}/,/(?:postgres(?:ql)?):\/\/[^\s\/@:]+:[^\s\/@]+@[^\s]+/,/[A-Z]:[\\/]Users[\\/][^\s/\\]+/i,/\b192\.168\.\d{1,3}\.\d{1,3}\b/,/\bCREATE\s+(?:OR\s+REPLACE\s+)?(?:TABLE|FUNCTION|ROLE)\b/i];
const files=[...new Set(execFileSync('git',['ls-files','--cached','--others','--exclude-standard'],{encoding:'utf8'}).split(/\r?\n/).filter(/** filter 콜백: 조건에 맞는 항목만 고릅니다 주요 호출: endsWith·existsSync. */ p=>p.endsWith('.md')&&existsSync(p)))];
const findings=[];for(const file of files){const text=readFileSync(file,'utf8');for(let rule=0;rule<patterns.length;rule++)if(patterns[rule].test(text))findings.push({file,rule});}
console.log(JSON.stringify({files:files.length,findings,scope:'Pattern review of current Markdown only; history and undisclosed secrets require separate review.'}));if(findings.length)process.exitCode=1;
