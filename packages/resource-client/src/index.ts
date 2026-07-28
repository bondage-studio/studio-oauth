import {AuthError, authHeader, decodePublicKey, now, verifySelfSigned, verifyToken} from '@bc-studio/oauth-core';

export {AuthError, authHeader};

const DEFAULT_MAX_PROOF_AGE = 300;

export interface TokenClaims {
    issuer: string;
    user: string;
    resources?: string[];
    resource?: string;
    issuedAt?: number;
    expires?: number;
    id?: string;
    holderKey?: string;
    active?: boolean;
    [key: string]: unknown;
}

export interface VerifierOptions {
    issuer: string;
    resource: string | string[];
    mode?: 'offline' | 'online';
    maxProofAge?: number;
    fetch?: typeof globalThis.fetch;
}

export type VerifiedAuth = TokenClaims & { resource: string };

export function createVerifier({
    issuer,
    resource,
    mode = 'offline',
    maxProofAge = DEFAULT_MAX_PROOF_AGE,
    fetch = (...args) => globalThis.fetch(...args),
}: VerifierOptions): (authorization: string | null | undefined) => Promise<VerifiedAuth> {
    const audiences = new Set([resource].flat());
    let keys: Promise<JsonWebKey[]> | undefined;

    function jwks(): Promise<JsonWebKey[]> {
        keys ??= fetch(`${issuer}/jwks`)
            .then((res) => res.json())
            .then((body) => (body.keys as string[]).map(decodePublicKey))
            .catch((e) => {
                keys = undefined;
                throw e;
            });
        return keys;
    }

    async function offlineClaims(token: string): Promise<TokenClaims> {
        for (const key of await jwks()) {
            try {
                return await verifyToken<TokenClaims>(token, key);
            } catch (e) {
                if (!(e instanceof AuthError) || e.code !== 'bad_signature') throw e;
            }
        }
        throw new AuthError('bad_token');
    }

    async function onlineClaims(token: string): Promise<TokenClaims> {
        const res = await fetch(`${issuer}/introspect`, {
            method: 'POST',
            headers: {'content-type': 'application/json'},
            body: JSON.stringify({token}),
        });
        const claims = await res.json() as TokenClaims;
        if (!claims.active) throw new AuthError('inactive_token');
        return claims;
    }

    return async function verifyAuthorization(authorization) {
        const proof = /^BCAuth\s+(\S+)$/.exec(authorization ?? '')?.[1];
        if (!proof) throw new AuthError('missing_authorization', 400);

        const {payload, key, typ} = await verifySelfSigned<{
            exp: number;
            tok?: string;
            resource?: string;
        }>(proof, ['bcauth+proof', 'bcauth+narrow']);
        if (payload.exp - now() > maxProofAge) throw new AuthError('proof_ttl_too_long');
        if (!payload.tok) throw new AuthError('missing_token', 400);

        const claims = mode === 'online' ? await onlineClaims(payload.tok) : await offlineClaims(payload.tok);
        if (claims.issuer !== issuer) throw new AuthError('bad_iss');

        let resource: string | undefined;
        if (typ === 'bcauth+narrow') {
            resource = payload.resource;
            if (!resource) throw new AuthError('missing_narrow_resource', 400);
            if (!Array.isArray(claims.resources) || !claims.resources.includes(resource)) {
                throw new AuthError('bad_aud', 403);
            }
        } else {
            resource = claims.resource;
        }
        if (!resource || !audiences.has(resource)) throw new AuthError('bad_aud', 403);

        if (claims.holderKey !== key) throw new AuthError('bad_proof_binding');
        return {...claims, resource};
    };
}
