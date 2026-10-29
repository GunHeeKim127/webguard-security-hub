// Decode only the explicitly permitted, bounded file. Windows exports often
// use UTF-16; silently treating them as UTF-8 produces NULs or altered values.
export function configurationFileText(bytes:Uint8Array):string{
 if(bytes.length===0||bytes.length>65536)throw new Error('CONFIG_SIZE');
 const encoding=bytes[0]===0xff&&bytes[1]===0xfe?'utf-16le':bytes[0]===0xfe&&bytes[1]===0xff?'utf-16be':'utf-8';
 const text=new TextDecoder(encoding,{fatal:true}).decode(bytes).replace(/^\uFEFF/,'');
 if(!text.trim()||text.includes('\0'))throw new Error('CONFIG_ENCODING');
 return text;
}

export function configurationCompatibility(moduleId:string,text:string):'private-key'|'ssh-client'|'ssh-unrecognized'|'windows-json'|null{
 const value=text.replace(/^\uFEFF/,'');
 if(/-----BEGIN (?:OPENSSH |RSA |EC |DSA |ENCRYPTED )?PRIVATE KEY-----/.test(value))return 'private-key';
 if(moduleId==='linux.ssh'){
  if(/^\s*Host(?:\s|$)/im.test(value)&&!/^\s*(?:PermitRootLogin|PasswordAuthentication|PermitEmptyPasswords|PubkeyAuthentication|MaxAuthTries|Include|Match)\s/im.test(value))return 'ssh-client';
  if(!/^\s*(?:PermitRootLogin|PasswordAuthentication|PermitEmptyPasswords|PubkeyAuthentication|MaxAuthTries|Include|Match)\s/im.test(value))return 'ssh-unrecognized';
 }
 if(moduleId==='windows.policy'){
  try{const v=JSON.parse(value);if(!v||Array.isArray(v)||v.schemaVersion!==1||!['firewall','defender','rdp'].some(k=>v[k]&&typeof v[k]==='object'&&!Array.isArray(v[k])))return 'windows-json';}catch{return 'windows-json';}
 }
 return null;
}
export function configurationCompatibilityMessage(reason:ReturnType<typeof configurationCompatibility>,locale:'ko'|'en'){
 const messages={
  'private-key':['확인 불가 파일: SSH 개인키는 검사 대상이 아닙니다. 개인키를 업로드하지 말고 서버의 sshd_config 또는 비밀값을 제외한 실효 설정을 사용하세요.','Cannot assess file: SSH private keys are not supported. Do not upload private keys; use server sshd_config or redacted effective settings.'],
  'ssh-client':['확인 불가 파일: SSH 클라이언트 설정으로 보입니다. 서버용 sshd_config 또는 sshd -T의 설정 출력이 필요합니다.','Cannot assess file: this appears to be SSH client configuration. Supply server sshd_config or sshd -T settings output.'],
  'ssh-unrecognized':['확인 불가 파일: 지원하는 SSH 서버 설정을 찾지 못했습니다. 파일 경로를 가정하지 말고 실제 서비스가 사용하는 설정을 확인해 주세요.','Cannot assess file: no supported SSH server directives found. Check the configuration used by the actual service rather than assuming its path.'],
  'windows-json':['확인 불가 파일: 지원하는 Windows 정책 JSON이 아닙니다. 내보내기 도구로 생성한 schemaVersion 1 결과를 사용하세요. EXE·INF·REG·전체 GPO는 이 입력의 대상이 아닙니다.','Cannot assess file: unsupported Windows policy JSON. Use a schemaVersion 1 result from the exporter. EXE, INF, REG and full GPO exports are outside this input.'],
 };
 return reason?messages[reason][locale==='ko'?0:1]:'';
}
