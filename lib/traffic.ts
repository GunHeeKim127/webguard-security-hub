export function suspiciousPath(path:string){return /^\/(?:\.env(?:\.|$)|\.git(?:\/|$)|wp-admin(?:\/|$)|wp-login\.php$|phpmyadmin(?:\/|$))/i.test(path);}
