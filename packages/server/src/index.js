import {AuthError, now, signToken, verifySelfSigned, verifyToken} from '@bc-studio/oauth-core';

const CORS = {
    'access-control-allow-origin': '*',
    'access-control-allow-headers': '*',
    'access-control-allow-methods': 'GET,POST,OPTIONS',
};

const DEFAULT_TOKEN_TTL = 3600;
const MAX_TOKEN_TTL = 86400;
const MIN_REVOCATION_TTL = 60;

const kv = (env) => env.bc_studio_oauth;
const serverKey = (env) => JSON.parse(env.SERVER_KEY);
const userKey = (sub) => `user:${sub}`;
const revocationKey = (id) => `rev:${id}`;

async function authenticateUser(env, jws, typ) {
    const {payload, key} = await verifySelfSigned(jws, typ);
    const sub = String(payload.sub);
    if ((await kv(env).get(userKey(sub))) !== key) throw new AuthError('unknown_user', 403);
    return {sub, key, payload};
}

const json = (body, status = 200) =>
    new Response(JSON.stringify(body), {status, headers: {'content-type': 'application/json', ...CORS}});

function jwks({env}) {
    // 返回公钥字符串数组（Ed25519 x 坐标），省略固定的 kty/crv
    return json({keys: [serverKey(env).x]});
}

async function register({req, env}) {
    const {payload, key} = await verifySelfSigned(await req.text(), 'bcauth+register');
    const sub = String(payload.sub);
    const bound = await kv(env).get(userKey(sub));
    if (!bound) await kv(env).put(userKey(sub), key);
    else if (bound !== key) throw new AuthError('member_already_claimed', 409);
    return json({sub, key});
}

async function issueToken({req, env, url}) {
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

async function introspect({req, env, url}) {
    try {
        const claims = await verifyToken((await req.json()).token, serverKey(env));
        if (claims.issuer !== url.origin) throw new AuthError('bad_iss');
        if (await kv(env).get(revocationKey(claims.id))) throw new AuthError('revoked');
        return json({active: true, ...claims});
    } catch {
        return json({active: false});
    }
}

async function revoke({req, env}) {
    const {sub, payload} = await authenticateUser(env, await req.text(), 'bcauth+revoke');
    const claims = await verifyToken(payload.token, serverKey(env));
    if (String(claims.user) !== sub) throw new AuthError('not_your_token', 403);
    await kv(env).put(revocationKey(claims.id), '1', {
        expirationTtl: Math.max(MIN_REVOCATION_TTL, claims.expires - now()),
    });
    return json({revoked: claims.id});
}

const ROUTES = {
    '/jwks': {method: 'GET', handler: jwks},
    '/register': {method: 'POST', handler: register},
    '/token': {method: 'POST', handler: issueToken},
    '/introspect': {method: 'POST', handler: introspect},
    '/revoke': {method: 'POST', handler: revoke},
};

export default {
    async fetch(req, env) {
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
};
