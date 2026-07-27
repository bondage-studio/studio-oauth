# @bc-studio/oauth-core

协议实现：Ed25519 密钥、签名令牌与持有者证明。mod、resource-client、server 三方共用；想理解或重新实现协议，看这里。

## 概念

- **密钥**：Ed25519。公钥直接用 JWK 的 `x` 坐标（43 字符的 base64url 字符串）表示，`generateKey()` 生成密钥对。
- **自证 JWS**：三段式 `header.payload.signature`，header 的 `jwk` 字段携带签名者公钥，payload 附带 `exp` 过期时间。`typ` 区分用途（`bcauth+register`、`bcauth+token`、`bcauth+proof` 等）。
- **访问令牌**：两段式 `payload.signature`，由授权服务器签发并绑定持有者（`holderKey`），claims 含 `issuer`、`user`、`resources`、`expires`、`id`。
- **持有者证明**：`authHeader()` 把令牌签进一个短期自证 JWS，作为 `Authorization: BCAuth ...` 头。传入 `resource` 时生成收窄证明（`bcauth+narrow`），把多资源令牌锁定到单个资源使用，无需再请求服务器。

## API

| 导出 | 说明 |
| --- | --- |
| `generateKey()` | 生成密钥对，返回 `{privateJwk, publicKey}` |
| `selfSign(typ, payload, privateJwk, ttl?)` | 签发自证 JWS，自动附带 `exp` |
| `verifySelfSigned(jws, acceptedType)` | 验签并校验 `typ`，返回 `{payload, jwk, key, typ}` |
| `signToken(payload, privateJwk)` / `verifyToken(token, publicJwk)` | 签发 / 验证访问令牌 |
| `authHeader(privateJwk, token, {resource?, ttl?})` | 生成 `{authorization}` 请求头 |
| `sign()` / `verify()` | 底层 JWS 签名与验签 |
| `AuthError` | 统一错误类型，含 `code` 与 HTTP `status` |
| `REQUEST_TTL` / `PROOF_TTL` | 默认有效期（秒）：请求 60，证明 120 |
| `base64url()`、`decodeSegment()`、`decodePublicKey()`、`now()` 等 | 编解码与工具函数 |

所有验签失败、过期、类型不符的情况都会抛出 `AuthError`。
