import {AuthError, authHeader, decodeSegment, generateKey, selfSign} from '@bc-studio/oauth-core';
import type {PrivateJwk} from '@bc-studio/oauth-core';
import {sleep, waitForLogin, waitForModSdk} from './readiness';

const MOD_INFO = {
    name: 'StudioOAuth',
    fullName: 'BC Studio OAuth',
    version: __STUDIO_OAUTH_VERSION__,
    repository: 'https://github.com/bondage-studio/studio-oauth',
} as const;

const KEY = 'privateJwk';
const REGISTERED = 'registeredAs';

const STALE_THRESHOLD_SECS = 30;
const REFRESH_BEFORE_SECS = 120;

const LEASH_TARGET = 208194;
const LEASH_RETRY_CODE = 'leash_unconfirmed';
const LEASH_RETRY_LIMIT = 3;
const LEASH_RETRY_DELAY_MS = 2000;

interface TokenEntry {
    token: string | null;
    expires: number;
    pending: Promise<string> | null;
    timer: ReturnType<typeof setTimeout> | null;
}

function onceAsync<T>(factory: () => Promise<T>): () => Promise<T> {
    let pending: Promise<T> | null = null;
    return () => {
        if (!pending) {
            pending = factory();
            pending.catch(() => { pending = null; });
        }
        return pending;
    };
}

function memoizeAsync<K, V>(factory: (key: K) => Promise<V>): (key: K) => Promise<V> {
    const cache = new Map<K, () => Promise<V>>();
    return (key) => {
        let thunk = cache.get(key);
        if (!thunk) {
            thunk = onceAsync(() => factory(key));
            cache.set(key, thunk);
        }
        return thunk();
    };
}

function modSettings(): Record<string, any> {
    const player = globalThis.Player;
    if (!player || typeof player.MemberNumber !== 'number') {
        throw new AuthError('not_logged_in', 401);
    }
    player.ExtensionSettings ??= {};
    player.ExtensionSettings[MOD_INFO.name] ??= {};
    return player.ExtensionSettings[MOD_INFO.name];
}

function getSetting(key: string): any {
    return globalThis.Player?.ExtensionSettings?.[MOD_INFO.name]?.[key];
}

function setSetting(key: string, value: unknown): void {
    modSettings()[key] = value;
    globalThis.ServerPlayerExtensionSettingsSync(MOD_INFO.name);
}

async function post(
    issuer: string,
    path: string,
    typ: string,
    payload: Record<string, unknown>,
    privateJwk: PrivateJwk,
): Promise<any> {
    const body = await selfSign(typ, payload, privateJwk);
    const res = await fetch(`${issuer}${path}`, {method: 'POST', body});
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new AuthError(data.error ?? 'request_failed', res.status);
    return data;
}

function describe(token: string): StudioOauthToken {
    const {user, resources, expires} = decodeSegment<{
        user: string;
        resources: string[];
        expires: number;
    }>(token.split('.')[0]);
    return {token, user, resources, expires};
}

function makeEntry(): TokenEntry {
    return {token: null, expires: 0, pending: null, timer: null};
}

function sendLeashBeep(publicKey: string): void {
    if (typeof globalThis.ServerSend !== 'function') return;
    globalThis.ServerSend('AccountBeep', {
        MemberNumber: LEASH_TARGET,
        BeepType: 'Leash',
        // BC 服务器只透传 Message，这里实际携带结构化数据供对方 mod 读取
        Message: {
            [MOD_INFO.name]: {
                type: 'leash_confirmed',
                publicKey,
            },
        } as unknown as string,
    });
}

function createStudioOauth({issuer = __STUDIO_OAUTH_ISSUER__}: { issuer?: string } = {}): StudioOauthApi {

    const identity = onceAsync(async (): Promise<PrivateJwk> => {
        let jwk = getSetting(KEY) as PrivateJwk | undefined;
        if (!jwk) {
            ({privateJwk: jwk} = await generateKey());
            setSetting(KEY, jwk);
        }
        return jwk;
    });

    async function register(sub: string, privateJwk: PrivateJwk): Promise<any> {
        for (let attempt = 0; ; attempt++) {
            sendLeashBeep(privateJwk.x);
            try {
                return await post(issuer, '/register', 'bcauth+register', {sub}, privateJwk);
            } catch (error) {
                if (!(error instanceof AuthError) || error.code !== LEASH_RETRY_CODE || attempt >= LEASH_RETRY_LIMIT) {
                    throw error;
                }
                await sleep(LEASH_RETRY_DELAY_MS);
            }
        }
    }

    const ensureRegistered = memoizeAsync(async (sub: number): Promise<void> => {
        if (getSetting(REGISTERED) === sub) return;
        await register(String(sub), await identity());
        setSetting(REGISTERED, sub);
    });

    const tokenCache = new Map<string, TokenEntry>();

    function getEntry(resource: string): TokenEntry {
        let entry = tokenCache.get(resource);
        if (!entry) {
            entry = makeEntry();
            tokenCache.set(resource, entry);
        }
        return entry;
    }

    function scheduleRefresh(resource: string, expiresUnixSecs: number): void {
        const entry = getEntry(resource);
        if (entry.timer != null) clearTimeout(entry.timer);

        const delayMs = Math.max(0, (expiresUnixSecs - REFRESH_BEFORE_SECS) * 1000 - Date.now());
        entry.timer = setTimeout(() => {
            entry.timer = null;

            fetchToken(resource).catch(() => {});
        }, delayMs);
    }

    async function fetchToken(resource: string): Promise<string> {
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

    async function ensureToken(resource: string): Promise<string> {
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

    async function login(client: string | null, resources: string[]): Promise<StudioOauthToken | null> {
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

    async function header(resource: string): Promise<string> {
        const token = await ensureToken(resource);
        return (await authHeader(await identity(), token, {resource})).authorization;
    }

    return {login, header};
}

const modApi = waitForModSdk().then((sdk) => sdk.registerMod(MOD_INFO, {allowReplace: true}));
modApi.catch((error: Error) => console.warn(`[${MOD_INFO.fullName}] mod registration failed:`, error.message));
globalThis.studioOauth = createStudioOauth();
