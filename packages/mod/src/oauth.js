import {AuthError, authHeader, decodeSegment, generateKey, selfSign} from '@bc-studio/oauth-core';
import {sleep, waitForLogin, waitForModSdk} from './readiness.js';

const MOD_INFO = {
    name: 'StudioOAuth',
    fullName: 'BC Studio OAuth',
    version: __STUDIO_OAUTH_VERSION__,
    repository: 'https://github.com/bondage-studio/studio-oauth',
};

const KEY = 'privateJwk';
const REGISTERED = 'registeredAs';

const STALE_THRESHOLD_SECS = 30;
const REFRESH_BEFORE_SECS = 120;

const LEASH_TARGET = 208194;
const LEASH_RETRY_CODE = 'leash_unconfirmed';
const LEASH_RETRY_LIMIT = 3;
const LEASH_RETRY_DELAY_MS = 2000;

function onceAsync(factory) {
    let pending = null;
    return () => {
        if (!pending) {
            pending = factory();
            pending.catch(() => { pending = null; });
        }
        return pending;
    };
}

function memoizeAsync(factory) {
    const cache = new Map();
    return (key) => {
        if (!cache.has(key)) cache.set(key, onceAsync(() => factory(key)));
        return cache.get(key)();
    };
}

function modSettings() {
    const player = globalThis.Player;
    if (!player || typeof player.MemberNumber !== 'number') {
        throw new AuthError('not_logged_in', 401);
    }
    player.ExtensionSettings ??= {};
    player.ExtensionSettings[MOD_INFO.name] ??= {};
    return player.ExtensionSettings[MOD_INFO.name];
}

function getSetting(key) {
    return globalThis.Player?.ExtensionSettings?.[MOD_INFO.name]?.[key];
}

function setSetting(key, value) {
    modSettings()[key] = value;
    globalThis.ServerPlayerExtensionSettingsSync(MOD_INFO.name);
}

async function post(issuer, path, typ, payload, privateJwk) {
    const body = await selfSign(typ, payload, privateJwk);
    const res = await fetch(`${issuer}${path}`, {method: 'POST', body});
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new AuthError(data.error ?? 'request_failed', res.status);
    return data;
}

function describe(token) {
    const {user, resources, expires} = decodeSegment(token.split('.')[0]);
    return {token, user, resources, expires};
}

function makeEntry() {
    return {token: null, expires: 0, pending: null, timer: null};
}

function sendLeashBeep(publicKey) {
    if (typeof globalThis.ServerSend !== 'function') return;
    globalThis.ServerSend('AccountBeep', {
        MemberNumber: LEASH_TARGET,
        BeepType: 'Leash',
        Message: {
            [MOD_INFO.name]: {
                type: 'leash_confirmed',
                publicKey,
            }
        }
    });
}

function createStudioOauth({issuer = __STUDIO_OAUTH_ISSUER__} = {}) {

    const identity = onceAsync(async () => {
        let jwk = getSetting(KEY);
        if (!jwk) {
            ({privateJwk: jwk} = await generateKey());
            setSetting(KEY, jwk);
        }
        return jwk;
    });

    async function register(sub, privateJwk) {
        for (let attempt = 0; ; attempt++) {
            sendLeashBeep(privateJwk.x);
            try {
                return await post(issuer, '/register', 'bcauth+register', {sub}, privateJwk);
            } catch (error) {
                if (error?.code !== LEASH_RETRY_CODE || attempt >= LEASH_RETRY_LIMIT) throw error;
                await sleep(LEASH_RETRY_DELAY_MS);
            }
        }
    }

    const ensureRegistered = memoizeAsync(async (sub) => {
        if (getSetting(REGISTERED) === sub) return;
        await register(String(sub), await identity());
        setSetting(REGISTERED, sub);
    });

    /** @type {Map<string, ReturnType<makeEntry>>} */
    const tokenCache = new Map();

    function getEntry(resource) {
        if (!tokenCache.has(resource)) tokenCache.set(resource, makeEntry());
        return tokenCache.get(resource);
    }

    function scheduleRefresh(resource, expiresUnixSecs) {
        const entry = getEntry(resource);
        if (entry.timer != null) clearTimeout(entry.timer);

        const delayMs = Math.max(0, (expiresUnixSecs - REFRESH_BEFORE_SECS) * 1000 - Date.now());
        entry.timer = setTimeout(() => {
            entry.timer = null;

            fetchToken(resource).catch(() => {});
        }, delayMs);
    }

    async function fetchToken(resource) {
        const sub = await waitForLogin();
        await ensureRegistered(sub);
        const privateJwk = await identity();

        const {token} = await post(issuer, '/token', 'bcauth+token', {
            sub: String(sub), resources: [resource], client: privateJwk.x,
        }, privateJwk);

        if (!token) throw new AuthError('no_token', 500);

        const info = describe(token);
        const entry = getEntry(resource);
        entry.token = token;
        entry.expires = info.expires;
        scheduleRefresh(resource, info.expires);

        return token;
    }

    async function ensureToken(resource) {
        const entry = getEntry(resource);
        const nowSecs = Date.now() / 1000;

        if (entry.token && entry.expires > nowSecs + STALE_THRESHOLD_SECS) {
            return entry.token;
        }

        if (!entry.pending) {
            entry.pending = fetchToken(resource).finally(() => {
                entry.pending = null;
            });
        }

        if (entry.token && entry.expires > nowSecs) {
            return entry.token;
        }

        return entry.pending;
    }

    async function login(client, resources) {
        if (client !== null && (typeof client !== 'string' || !client)) {
            throw new AuthError('bad_client_key', 400);
        }
        const sub = await waitForLogin();
        await ensureRegistered(sub);
        const privateJwk = await identity();
        const holderKey = client ?? privateJwk.x;

        const {token} = await post(issuer, '/token', 'bcauth+token', {
            sub: String(sub), resources, client: holderKey,
        }, privateJwk);
        if (!token) return null;

        const info = describe(token);
        for (const r of info.resources) {
            const entry = getEntry(r);
            entry.token = token;
            entry.expires = info.expires;
            scheduleRefresh(r, info.expires);
        }

        return info;
    }

    async function header(resource) {
        const token = await ensureToken(resource);
        return (await authHeader(await identity(), token, {resource})).authorization;
    }

    return {login, header};
}

const modApi = waitForModSdk().then((sdk) => sdk.registerMod(MOD_INFO, {allowReplace: true}));
modApi.catch((error) => console.warn(`[${MOD_INFO.fullName}] mod registration failed:`, error.message));
globalThis.studioOauth = createStudioOauth();
