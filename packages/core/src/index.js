const ED25519 = {name: 'Ed25519'};

export const REQUEST_TTL = 60;
export const PROOF_TTL = 120;

export class AuthError extends Error {
    constructor(code, status = 401) {
        super(code);
        this.name = 'AuthError';
        this.code = code;
        this.status = status;
    }
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export const base64url = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
export const base64urlToBytes = (s) =>
    Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));
export const encodeSegment = (obj) => base64url(encoder.encode(JSON.stringify(obj)));
export const decodeSegment = (s) => JSON.parse(decoder.decode(base64urlToBytes(s)));

export const now = () => Math.floor(Date.now() / 1000);

// 公钥格式：直接使用 JWK 中的 x 坐标（Ed25519 只有一个坐标，32 字节 → 43 字符 base64url）
export const decodePublicKey = (x) => ({kty: 'OKP', crv: 'Ed25519', x});

// 内部用：从任意密钥 JWK 中提取公钥部分（去除私钥字段 d）
const publicJwkOf = ({kty, crv, x}) => ({kty, crv, x});

const importKey = (jwk, usage) =>
    crypto.subtle.importKey('jwk', {...jwk, key_ops: [usage], ext: true}, ED25519, false, [usage]);

export async function generateKey() {
    const keyPair = await crypto.subtle.generateKey(ED25519, true, ['sign', 'verify']);
    const {x, d} = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
    return {privateJwk: {kty: 'OKP', crv: 'Ed25519', x, d}, publicKey: x};
}


export async function sign(typ, payload, privateJwk, header = {}) {
    const key = await importKey(privateJwk, 'sign');
    const signingInput = `${encodeSegment({alg: 'EdDSA', typ, ...header})}.${encodeSegment(payload)}`;
    const signature = await crypto.subtle.sign(ED25519, key, encoder.encode(signingInput));
    return `${signingInput}.${base64url(signature)}`;
}

// header.jwk 存放公钥字符串（x 坐标），省略固定的 kty/crv
export function selfSign(typ, payload, privateJwk, ttl = REQUEST_TTL) {
    return sign(typ, {...payload, exp: now() + ttl}, privateJwk, {jwk: privateJwk.x});
}

export async function verify(jws, publicJwk) {
    const [header, payload, signature] = String(jws).split('.');
    if (!signature) throw new AuthError('malformed_jws', 400);
    const key = await importKey(publicJwkOf(publicJwk), 'verify');
    const signed = encoder.encode(`${header}.${payload}`);
    if (!(await crypto.subtle.verify(ED25519, key, base64urlToBytes(signature), signed))) {
        throw new AuthError('bad_signature');
    }
    const claims = decodeSegment(payload);
    if (!(claims.exp > now())) throw new AuthError('expired');
    return claims;
}

// access token：自定义两段式 `payload.signature`，无 header（算法固定 Ed25519，无需声明）
export async function signToken(payload, privateJwk) {
    const key = await importKey(privateJwk, 'sign');
    const segment = encodeSegment(payload);
    const signature = await crypto.subtle.sign(ED25519, key, encoder.encode(segment));
    return `${segment}.${base64url(signature)}`;
}

export async function verifyToken(token, publicJwk) {
    const [payload, signature] = String(token).split('.');
    if (!signature) throw new AuthError('malformed_token', 400);
    const key = await importKey(publicJwkOf(publicJwk), 'verify');
    if (!(await crypto.subtle.verify(ED25519, key, base64urlToBytes(signature), encoder.encode(payload)))) {
        throw new AuthError('bad_signature');
    }
    const claims = decodeSegment(payload);
    if (!(claims.expires > now())) throw new AuthError('expired');
    return claims;
}

// acceptedType 可以是字符串或字符串数组；返回值包含实际类型 typ，供调用方区分
export async function verifySelfSigned(jws, acceptedType) {
    let header;
    try {
        header = decodeSegment(String(jws).split('.')[0]);
    } catch {
        throw new AuthError('malformed_jws', 400);
    }
    const accepted = [acceptedType].flat();
    if (!accepted.includes(header?.typ)) throw new AuthError('bad_typ', 400);
    if (!header.jwk) throw new AuthError('missing_jwk', 400);
    // header.jwk 是公钥字符串（x 坐标），直接作为持有者绑定值
    const jwk = decodePublicKey(header.jwk);
    return {payload: await verify(jws, jwk), jwk, key: header.jwk, typ: header.typ};
}

// resource 不为 null 时产生"收窄证明"（bcauth+narrow），
// 将宽 token 的使用范围锁定到单个 resource，无需再向服务器请求。
// resource 为 null/省略时产生普通证明（bcauth+proof）。
export async function authHeader(privateJwk, token, {resource = null, ttl = PROOF_TTL} = {}) {
    const typ = resource != null ? 'bcauth+narrow' : 'bcauth+proof';
    const payload = resource != null ? {tok: token, resource} : {tok: token};
    return {authorization: `BCAuth ${await selfSign(typ, payload, privateJwk, ttl)}`};
}