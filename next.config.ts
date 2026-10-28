import type { NextConfig } from 'next';
import {accessOrigins} from './lib/access-origins';
const config: NextConfig = {
 allowedDevOrigins:accessOrigins().map(origin=>new URL(origin).hostname),
 poweredByHeader: false,
 // Client execution remains inspectable; never publish original production sources.
 productionBrowserSourceMaps: false,
 // Keep verification builds separate from the running development server.
 distDir: process.env.WEBGUARD_VERIFY==='true'?'.next-verify':'.next',
 async headers() { return [{source:'/:path*',headers:[
 {key:'X-Content-Type-Options',value:'nosniff'},
 {key:'X-Frame-Options',value:'DENY'},
 {key:'Referrer-Policy',value:'no-referrer'},
 {key:'Permissions-Policy',value:'camera=(), microphone=(), geolocation=()'}
 ]},{source:'/api/:path*',headers:[{key:'Cache-Control',value:'no-store, private'},{key:'X-Robots-Tag',value:'noindex, nofollow, nosnippet'}]}]; }
};
export default config;
