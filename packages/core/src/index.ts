const ED25519: AlgorithmIdentifier = {name: 'Ed25519'};

export const REQUEST_TTL = 60;
export const PROOF_TTL = 120;

export class AuthError extends Error {
    readonly code: string;
    readonly status: number;

    constructor(code: string, status = 401) {
        super(code);
        this.name = 'AuthError';
        this.code = code;
        this.status = status;
    }
}

export interface PublicJwk extends JsonWebKey {
    kty: 'OKP';
    crv: 'Ed25519';
    x: string;
}

export interface PrivateJwk extends PublicJwk {
    d: string;
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export const base64url = (bytes: ArrayBuffer | Uint8Array): string =>
    btoa(String.fromCharCode(...new Uint8Array(bytes)))
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
export const base64urlToBytes = (s: string): Uint8Array<ArrayBuffer> =>
    Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));
export const encodeSegment = (obj: unknown): string => base64url(encoder.encode(JSON.stringify(obj)));
export const decodeSegment = <T = any>(s: string): T => JSON.parse(decoder.decode(base64urlToBytes(s)));

export const now = (): number => Math.floor(Date.now() / 1000);

export const decodePublicKey = (x: string): PublicJwk => ({kty: 'OKP', crv: 'Ed25519', x});

const publicJwkOf = ({kty, crv, x}: JsonWebKey): JsonWebKey => ({kty, crv, x});

const importKey = (jwk: JsonWebKey, usage: KeyUsage): Promise<CryptoKey> =>
    crypto.subtle.importKey('jwk', {...jwk, key_ops: [usage], ext: true}, ED25519, false, [usage]);

export async function generateKey(): Promise<{ privateJwk: PrivateJwk; publicKey: string }> {
    const keyPair = await crypto.subtle.generateKey(ED25519, true, ['sign', 'verify']) as CryptoKeyPair;
    const {x, d} = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
    if (!x || !d) throw new AuthError('key_export_failed', 500);
    return {privateJwk: {kty: 'OKP', crv: 'Ed25519', x, d}, publicKey: x};
}


export async function sign(
    typ: string,
    payload: Record<string, unknown>,
    privateJwk: JsonWebKey,
    header: Record<string, unknown> = {},
): Promise<string> {
    const key = await importKey(privateJwk, 'sign');
    const signingInput = `${encodeSegment({alg: 'EdDSA', typ, ...header})}.${encodeSegment(payload)}`;
    const signature = await crypto.subtle.sign(ED25519, key, encoder.encode(signingInput));
    return `${signingInput}.${base64url(signature)}`;
}

// header.jwk 存放公钥字符串（x 坐标），省略固定的 kty/crv
export function selfSign(
    typ: string,
    payload: Record<string, unknown>,
    privateJwk: PrivateJwk,
    ttl = REQUEST_TTL,
): Promise<string> {
    return sign(typ, {...payload, exp: now() + ttl}, privateJwk, {jwk: privateJwk.x});
}

export async function verify<T = any>(jws: string, publicJwk: JsonWebKey): Promise<T> {
    const [header, payload, signature] = String(jws).split('.');
    if (!signature) throw new AuthError('malformed_jws', 400);
    const key = await importKey(publicJwkOf(publicJwk), 'verify');
    const signed = encoder.encode(`${header}.${payload}`);
    if (!(await crypto.subtle.verify(ED25519, key, base64urlToBytes(signature), signed))) {
        throw new AuthError('bad_signature');
    }
    const claims = decodeSegment<T>(payload);
    if (!((claims as any).exp > now())) throw new AuthError('expired');
    return claims;
}

// access token：自定义两段式 `payload.signature`，无 header（算法固定 Ed25519，无需声明）
export async function signToken(payload: Record<string, unknown>, privateJwk: JsonWebKey): Promise<string> {
    const key = await importKey(privateJwk, 'sign');
    const segment = encodeSegment(payload);
    const signature = await crypto.subtle.sign(ED25519, key, encoder.encode(segment));
    return `${segment}.${base64url(signature)}`;
}

export async function verifyToken<T = any>(token: string, publicJwk: JsonWebKey): Promise<T> {
    const [payload, signature] = String(token).split('.');
    if (!signature) throw new AuthError('malformed_token', 400);
    const key = await importKey(publicJwkOf(publicJwk), 'verify');
    if (!(await crypto.subtle.verify(ED25519, key, base64urlToBytes(signature), encoder.encode(payload)))) {
        throw new AuthError('bad_signature');
    }
    const claims = decodeSegment<T>(payload);
    if (!((claims as any).expires > now())) throw new AuthError('expired');
    return claims;
}

export interface SelfSigned<T = any> {
    payload: T;
    jwk: PublicJwk;
    key: string;
    typ: string;
}

export async function verifySelfSigned<T = any>(
    jws: string,
    acceptedType: string | string[],
): Promise<SelfSigned<T>> {
    let header: {typ?: string; jwk?: string};
    try {
        header = decodeSegment(String(jws).split('.')[0]);
    } catch {
        throw new AuthError('malformed_jws', 400);
    }
    const accepted = [acceptedType].flat();
    if (!header.typ || !accepted.includes(header.typ)) throw new AuthError('bad_typ', 400);
    if (!header.jwk) throw new AuthError('missing_jwk', 400);
    const jwk = decodePublicKey(header.jwk);
    return {payload: await verify<T>(jws, jwk), jwk, key: header.jwk, typ: header.typ};
}

export async function authHeader(
    privateJwk: PrivateJwk,
    token: string,
    {resource = null, ttl = PROOF_TTL}: { resource?: string | null; ttl?: number } = {},
): Promise<{ authorization: string }> {
    const typ = resource != null ? 'bcauth+narrow' : 'bcauth+proof';
    const payload = resource != null ? {tok: token, resource} : {tok: token};
    return {authorization: `BCAuth ${await selfSign(typ, payload, privateJwk, ttl)}`};
}
