import {readFileSync} from 'node:fs';

import {nodeResolve} from '@rollup/plugin-node-resolve';
import replace from '@rollup/plugin-replace';
import terser from '@rollup/plugin-terser';
import esbuild from 'rollup-plugin-esbuild';

const pkg = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8'));

const issuer = process.env.STUDIO_OAUTH_ISSUER ?? 'https://auth.bondage-studio.org';
const version = process.env.STUDIO_OAUTH_VERSION ?? pkg.version;

export default {
    input: 'src/oauth.ts',
    output: {
        file: 'dist/studio-oauth.js',
        format: 'iife',
        name: 'StudioOAuth',
    },
    plugins: [
        replace({
            preventAssignment: true,
            values: {
                __STUDIO_OAUTH_ISSUER__: JSON.stringify(issuer),
                __STUDIO_OAUTH_VERSION__: JSON.stringify(version),
            },
        }),
        nodeResolve({extensions: ['.ts', '.mjs', '.js']}),
        esbuild({target: 'es2022'}),
    ],
};
