'use client';

import {Box,Button,Typography} from '@mui/material';
import Link from './navigation-link';
import type {Locale} from '../lib/locale';

const copy:Record<Locale,{title:string;body:string;link:string}>={
 ko:{title:'Java 기반 웹 서버 · Java4Shell 점검 안내',body:'Java 기반 웹 서비스도 Java4Shell의 영향을 받을 수 있습니다. URL·HTTP 헤더만으로 실제 JVM 버전·CPU·실행 설정을 확인할 수 없습니다. Endpoint의 Java/JVM 점검에서 실행 환경 자료를 확인하세요. 웹 진단 통과가 Java 취약점이 없다는 뜻은 아닙니다.',link:'Java/JVM 점검 열기 →'},
 en:{title:'Java web servers · Java4Shell review',body:'Java web services can also be affected by Java4Shell. A URL or HTTP headers cannot establish the actual JVM version, CPU or runtime settings. Review runtime evidence in Endpoint Java/JVM. Passing a web check does not rule out Java vulnerabilities.',link:'Open Java/JVM review →'},
 ja:{title:'Java Webサーバー · Java4Shellの確認',body:'JavaのWebサービスもJava4Shellの影響を受ける可能性があります。URLやHTTPヘッダーだけでは実際のJVMバージョン、CPU、実行設定を確認できません。EndpointのJava/JVM診断で実行環境の資料を確認してください。Web診断の通過はJavaの脆弱性がないことを意味しません。',link:'Java/JVM診断を開く →'},
 zh:{title:'Java Web 服务器 · Java4Shell 检查说明',body:'Java Web 服务也可能受到 Java4Shell 的影响。仅凭 URL 或 HTTP 标头无法确定实际 JVM 版本、CPU 和运行设置。请在 Endpoint 的 Java/JVM 检查中核对运行环境资料。通过 Web 检查不代表不存在 Java 漏洞。',link:'打开 Java/JVM 检查 →'},
 es:{title:'Servidores web Java · Revisión de Java4Shell',body:'Los servicios web Java también pueden verse afectados por Java4Shell. La URL y las cabeceras HTTP no permiten verificar la versión real de JVM, la CPU ni la configuración de ejecución. Revise las pruebas del entorno en Endpoint Java/JVM. Superar la revisión web no descarta vulnerabilidades de Java.',link:'Abrir revisión de Java/JVM →'},
 fr:{title:'Serveurs web Java · Vérification Java4Shell',body:'Les services web Java peuvent aussi être affectés par Java4Shell. Une URL ou des en-têtes HTTP ne permettent pas de vérifier la version réelle de la JVM, le processeur ni les paramètres d’exécution. Examinez les éléments de l’environnement dans Endpoint Java/JVM. Réussir le contrôle web n’exclut pas les vulnérabilités Java.',link:'Ouvrir la vérification Java/JVM →'},
};

export default function JavaWebGuidance({locale}:{locale:Locale}){
 const t=copy[locale];
 return <Box component="details" sx={{mt:3,color:'text.secondary'}}>
  <Typography component="summary" variant="body2" sx={{cursor:'pointer'}}>{t.title}</Typography>
  <Typography variant="body2" mt={1}>{t.body}</Typography>
  <Button component={Link} href="/workbench/java" size="small">{t.link}</Button>
 </Box>;
}
