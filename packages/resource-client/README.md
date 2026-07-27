# @bc-studio/oauth-resource-client

资源服务器用它验证 `Authorization: BCAuth ...` 请求头，确认请求者的身份与授权范围。

## 验证请求

```js
import {createVerifier} from '@bc-studio/oauth-resource-client';

const verifyAuthorization = createVerifier({
    issuer: 'https://auth.bondage-studio.org',
    resource: 'https://api.example.com',
});

// 在请求处理函数中：
const claims = await verifyAuthorization(req.headers.get('authorization'));
// claims.user       玩家 MemberNumber
// claims.resource   本次命中的资源标识
// claims.resources  令牌覆盖的全部资源
// claims.expires    令牌过期时间（Unix 秒）
```

验证失败抛出 `AuthError`，用 `err.code`（如 `bad_signature`、`expired`、`bad_aud`）和 `err.status` 回应客户端。

## 选项

- `mode: 'offline'`（默认）：从 issuer 拉取公钥后本地验签，不产生额外请求；
- `mode: 'online'`：每次请求 issuer 的 `/introspect`，能识别已吊销的令牌；
- `resource` 可传数组以接受多个资源标识，实际命中的那个放在返回值的 `resource` 字段；
- `maxProofAge`：持有者证明允许的最大有效期（秒），默认 300。

## 作为客户端调用

没有浏览器的机器客户端可以自行持有密钥、签出请求头：

```js
import {authHeader} from '@bc-studio/oauth-resource-client';

const {authorization} = await authHeader(privateJwk, token, {resource: 'https://api.example.com'});
```

运行 `bcauth-keygen` 生成密钥对：`privateJwk` 自己保管，`publicKey` 交给令牌的签发方注册。
