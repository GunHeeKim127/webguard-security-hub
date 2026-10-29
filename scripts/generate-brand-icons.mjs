// Deterministic raster/export variants of the existing login lock illustration.
import sharp from 'sharp';
import {readFile,writeFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
const source=await readFile(new URL('../public/brand/favicon.svg',import.meta.url));
await sharp(source).resize(256,256).png().toFile(fileURLToPath(new URL('../app/icon.png',import.meta.url)));
await sharp(source).resize(180,180).png().toFile(fileURLToPath(new URL('../app/apple-icon.png',import.meta.url)));
const sizes=[16,32,48],images=await Promise.all(sizes.map(size=>sharp(source).resize(size,size).png().toBuffer()));
const header=Buffer.alloc(6+16*sizes.length);header.writeUInt16LE(1,2);header.writeUInt16LE(sizes.length,4);let offset=header.length;
for(let i=0;i<sizes.length;i++){const p=6+i*16;header[p]=sizes[i];header[p+1]=sizes[i];header.writeUInt16LE(1,p+4);header.writeUInt16LE(32,p+6);header.writeUInt32LE(images[i].length,p+8);header.writeUInt32LE(offset,p+12);offset+=images[i].length;}
await writeFile(new URL('../app/favicon.ico',import.meta.url),Buffer.concat([header,...images]));
console.log('Login shield/lock favicon exported: ICO 16/32/48, PNG 256, Apple PNG 180.');
