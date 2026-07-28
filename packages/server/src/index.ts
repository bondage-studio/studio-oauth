import {AuthError, now, signToken, verifySelfSigned, verifyToken} from '@bc-studio/oauth-core';
import type {PrivateJwk} from '@bc-studio/oauth-core';

interface Env {
    bc_studio_oauth: KVNamespace;
    SERVER_KEY: string;
}

interface TokenClaims {
    issuer: string;
    user: string;
    resources: string[];
    issuedAt: number;
    expires: number;
    id: string;
    holderKey: string;
}

interface RouteContext {
    req: Request;
    env: Env;
    url: URL;
}

type RouteHandler = (ctx: RouteContext) => Response | Promise<Response>;

const CORS = {
    'access-control-allow-origin': '*',
    'access-control-allow-headers': 'Authorization, Content-Type',
    'access-control-allow-methods': 'GET, PUT, DELETE, OPTIONS',
};

const DEFAULT_TOKEN_TTL = 3600;
const MAX_TOKEN_TTL = 86400;
const MIN_REVOCATION_TTL = 60;

const kv = (env: Env): KVNamespace => env.bc_studio_oauth;
const serverKey = (env: Env): PrivateJwk => JSON.parse(env.SERVER_KEY);
const userKey = (sub: string): string => `user:${sub}`;
const revocationKey = (id: string): string => `rev:${id}`;

async function authenticateUser(env: Env, jws: string, typ: string) {
    const {payload, key} = await verifySelfSigned<{sub: unknown; token?: string; resources?: unknown; ttl?: number; client?: string}>(jws, typ);
    const sub = String(payload.sub);
    if ((await kv(env).get(userKey(sub))) !== key) throw new AuthError('unknown_user', 403);
    return {sub, key, payload};
}

const json = (body: unknown, status = 200): Response =>
    new Response(JSON.stringify(body), {status, headers: {'content-type': 'application/json', ...CORS}});

function jwks({env}: RouteContext): Response {
    return json({keys: [serverKey(env).x]});
}

async function register({req, env}: RouteContext): Promise<Response> {
    const {payload, key} = await verifySelfSigned<{sub: unknown}>(await req.text(), 'bcauth+register');
    const sub = String(payload.sub);
    const bound = await kv(env).get(userKey(sub));
    if (!bound) await kv(env).put(userKey(sub), key);
    else if (bound !== key) throw new AuthError('member_already_claimed', 409);
    return json({sub, key});
}

async function issueToken({req, env, url}: RouteContext): Promise<Response> {
    const {sub, key, payload} = await authenticateUser(env, await req.text(), 'bcauth+token');

    const resources = payload.resources;
    if (!Array.isArray(resources) || resources.length === 0 ||
        !resources.every((r) => typeof r === 'string' && r)) {
        throw new AuthError('bad_resource', 400);
    }

    const holder = payload.client ?? key;
    const serverJwk = serverKey(env);
    const issuedAt = now();
    const expires = issuedAt + Math.min(payload.ttl || DEFAULT_TOKEN_TTL, MAX_TOKEN_TTL);

    const token = await signToken({
        issuer: url.origin, user: sub, resources, issuedAt, expires,
        id: crypto.randomUUID(), holderKey: holder,
    }, serverJwk);
    return json({token});
}

async function introspect({req, env, url}: RouteContext): Promise<Response> {
    try {
        const claims = await verifyToken<TokenClaims>((await req.json() as {token: string}).token, serverKey(env));
        if (claims.issuer !== url.origin) throw new AuthError('bad_iss');
        if (await kv(env).get(revocationKey(claims.id))) throw new AuthError('revoked');
        return json({active: true, ...claims});
    } catch {
        return json({active: false});
    }
}

async function revoke({req, env}: RouteContext): Promise<Response> {
    const {sub, payload} = await authenticateUser(env, await req.text(), 'bcauth+revoke');
    if (!payload.token) throw new AuthError('missing_token', 400);
    const claims = await verifyToken<TokenClaims>(payload.token, serverKey(env));
    if (String(claims.user) !== sub) throw new AuthError('not_your_token', 403);
    await kv(env).put(revocationKey(claims.id), '1', {
        expirationTtl: Math.max(MIN_REVOCATION_TTL, claims.expires - now()),
    });
    return json({revoked: claims.id});
}

const ROUTES: Record<string, {method: string; handler: RouteHandler}> = {
    '/jwks': {method: 'GET', handler: jwks},
    '/register': {method: 'POST', handler: register},
    '/token': {method: 'POST', handler: issueToken},
    '/introspect': {method: 'POST', handler: introspect},
    '/revoke': {method: 'POST', handler: revoke},
};

export default {
    async fetch(req: Request, env: Env): Promise<Response> {
        if (req.method === 'OPTIONS') return new Response(null, {headers: CORS});

        const url = new URL(req.url);
        const route = ROUTES[url.pathname];
        if (!route) return json({error: 'not_found'}, 404);
        if (req.method !== route.method) return json({error: 'method_not_allowed'}, 405);

        try {
            return await route.handler({req, env, url});
        } catch (e) {
            if (e instanceof AuthError) return json({error: e.code}, e.status);
            console.error(e);
            return json({error: 'server_error'}, 500);
        }
    },
} satisfies ExportedHandler<Env>;
