import {AuthError, authHeader, decodePublicKey, now, verifySelfSigned, verifyToken} from '@bc-studio/oauth-core';

export {AuthError, authHeader};

const DEFAULT_MAX_PROOF_AGE = 300;

export function createVerifier({
    issuer,
    resource,
    mode = 'offline',
    maxProofAge = DEFAULT_MAX_PROOF_AGE,
    fetch = (...args) => globalThis.fetch(...args),
}) {
    const audiences = new Set([resource].flat());
    let keys;

    function jwks() {
        keys ??= fetch(`${issuer}/jwks`)
            .then((res) => res.json())
            // keys 是公钥字符串数组（Ed25519 x 坐标），解码为 JWK 对象
            .then((body) => body.keys.map(decodePublicKey))
            .catch((e) => {
                keys = undefined;
                throw e;
            });
        return keys;
    }

    async function offlineClaims(token) {
        for (const key of await jwks()) {
            try {
                return await verifyToken(token, key);
            } catch (e) {
                if (e.code !== 'bad_signature') throw e;
            }
        }
        throw new AuthError('bad_token');
    }

    async function onlineClaims(token) {
        const res = await fetch(`${issuer}/introspect`, {
            method: 'POST',
            headers: {'content-type': 'application/json'},
            body: JSON.stringify({token}),
        });
        const claims = await res.json();
        if (!claims.active) throw new AuthError('inactive_token');
        return claims;
    }

    return async function verifyAuthorization(authorization) {
        const proof = /^BCAuth\s+(\S+)$/.exec(authorization ?? '')?.[1];
        if (!proof) throw new AuthError('missing_authorization', 400);

        // 同时接受普通证明和收窄证明两种类型
        const {payload, key, typ} = await verifySelfSigned(
            proof, ['bcauth+proof', 'bcauth+narrow'],
        );
        if (payload.exp - now() > maxProofAge) throw new AuthError('proof_ttl_too_long');
        if (!payload.tok) throw new AuthError('missing_token', 400);

        const claims = mode === 'online' ? await onlineClaims(payload.tok) : await offlineClaims(payload.tok);
        if (claims.issuer !== issuer) throw new AuthError('bad_iss');

        let resource;
        if (typ === 'bcauth+narrow') {
            // 收窄证明：holder 在证明中声明本次只使用宽 token 里的某一个资源
            resource = payload.resource;
            if (!resource) throw new AuthError('missing_narrow_resource', 400);
            if (!Array.isArray(claims.resources) || !claims.resources.includes(resource)) {
                throw new AuthError('bad_aud', 403);
            }
        } else {
            // 旧式单资源证明
            resource = claims.resource;
        }
        if (!audiences.has(resource)) throw new AuthError('bad_aud', 403);

        // 直接比较公钥字符串，无需指纹
        if (claims.holderKey !== key) throw new AuthError('bad_proof_binding');
        // 将本次实际匹配的 resource 一并返回，方便调用方知道用的是哪个
        return {...claims, resource};
    };
}