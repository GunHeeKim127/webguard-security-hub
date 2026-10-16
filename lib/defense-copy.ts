import type {Locale} from './locale';
const order=['ko','en','ja','zh','es','fr'] as const;
const rows:Record<string,string[]>={
 title:['위험 접근 탐지·IP 차단','Threat detection / IP blocks','危険アクセス検知・IP遮断','风险访问检测和IP封禁','Detección de amenazas / bloqueo IP','Détection des menaces / blocage IP'],
 scope:['이 허브로 들어오는 요청만 보호합니다. 외부 사이트 트래픽 수집·WAF 연동은 미구현입니다.','Protection applies to requests entering this Hub. External site traffic collection and WAF integration are not implemented.','このハブへの要求のみ保護。外部トラフィック収集・WAF連携は未実装。','仅保护进入此中心的请求。尚未实现外部网站流量收集或WAF集成。','Solo protege peticiones a este centro. Sin recopilación externa ni integración WAF.','Protège uniquement les requêtes vers ce centre. Collecte externe et intégration WAF non implémentées.'],
 temporary:['위험한 요청 패턴을 감지하여 접속 IP를 5분간 차단했습니다. 차단 중 요청은 위반 횟수에 추가되지 않습니다.','A dangerous request pattern was detected. This IP is blocked for five minutes. Requests during the block do not add strikes.','危険な要求を検知し接続IPを5分遮断しました。遮断中の要求は回数に加算しません。','检测到危险请求模式，此IP将被封禁5分钟。封禁期间的请求不增加违规次数。','Se detectó una petición peligrosa. IP bloqueada cinco minutos; las peticiones durante el bloqueo no suman infracciones.','Une requête dangereuse a été détectée. IP bloquée cinq minutes ; les requêtes pendant le blocage n’ajoutent pas d’infractions.'],
 permanent:['임시 차단 해제 후에도 위험 요청이 반복되어 IP를 블랙리스트에 등록했습니다. 관리자 검토 후 해제가 필요합니다.','Dangerous requests continued after temporary blocks. This IP is blacklisted until administrator review.','一時遮断後も危険要求が続いたためIPをブラックリストに登録。解除には管理者確認が必要です。','临时封禁结束后仍重复危险请求，此IP已加入黑名单，需管理员审核解除。','Las peticiones peligrosas continuaron tras los bloqueos. IP en lista negra hasta revisión del administrador.','Les requêtes dangereuses ont continué après les blocages. IP sur liste noire jusqu’à révision par un administrateur.'],
 policy:['실제 연결 IP 기준 · 5분 임시 차단 5회 후 6번째 위반에 블랙리스트. 요청 경로·쿼리의 정해진 패턴만 탐지하며, 모든 공격을 판별하거나 공격자 신원을 역추적하는 기능은 아닙니다.','Actual connection IP: five temporary five-minute blocks, blacklist on the sixth offense. Only defined URL/query patterns are detected; this is not universal attack detection or attribution.','実接続IPで5分遮断を5回、6回目にブラックリスト。定義済みURLパターンのみ検知し、全攻撃検知や身元追跡ではありません。','依据真实连接IP：5次5分钟封禁，第6次违规加入黑名单。仅检测指定URL模式，不能识别所有攻击或追溯身份。','IP real: cinco bloqueos de cinco minutos y lista negra en la sexta infracción. Solo patrones URL definidos; no detecta todo ataque ni atribuye identidad.','IP réelle : cinq blocages de cinq minutes, liste noire à la sixième infraction. Motifs URL définis uniquement, sans détection universelle ni attribution.'],
 empty:['기록된 위험 IP가 없습니다.','No threat IP records.','危険IPの記録はありません。','暂无风险IP记录。','No hay registros de IP peligrosas.','Aucune IP dangereuse enregistrée.'],
 strikes:['누적 위반','Strikes','累積回数','累计违规','Infracciones','Infractions'],
 blocked:['임시 차단','Temporarily blocked','一時遮断','临时封禁','Bloqueo temporal','Blocage temporaire'],
 blacklist:['블랙리스트','Blacklist','ブラックリスト','黑名单','Lista negra','Liste noire'],
 released:['임시 차단 만료 · 재발 관찰','Temporary block expired / observing','一時遮断終了・再発監視','临时封禁已结束：观察复发','Bloqueo vencido / observación','Blocage expiré / surveillance'],
 probe:['민감 경로 탐색','Sensitive-path probe','機密パス探索','敏感路径探测','Sondeo de rutas sensibles','Sondage de chemins sensibles'],
 injection:['URL 삽입 공격 패턴','URL injection pattern','URL挿入攻撃パターン','URL注入模式','Patrón de inyección URL','Motif d’injection URL'],
 traversal:['경로 이탈 패턴','Path traversal pattern','パストラバーサル','路径穿越模式','Patrón de recorrido de rutas','Motif de traversée de chemins'],
 manual_reset:['관리자 해제','Administrator reset','管理者による解除','管理员解除','Reinicio del administrador','Réinitialisation administrateur'],
 unavailable:['접속 보호 상태를 확인할 수 없습니다. 잠시 후 다시 시도하세요.','Access protection is unavailable. Try again later.','接続保護を確認できません。後で再試行してください。','无法确认访问保护状态，请稍后重试。','Protección no disponible. Inténtalo más tarde.','Protection indisponible. Réessayez plus tard.']
};
export function defenseText(locale:Locale,key:string){return rows[key]?.[order.indexOf(locale)]??key;}
