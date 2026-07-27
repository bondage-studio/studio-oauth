# @bc-studio/oauth-mod

装入游戏后在全局暴露 `studioOauth`，其他 mod 通过它调用需要身份验证的接口。令牌的获取、缓存、刷新全部自动完成，调用方只需要一个方法。

## 获取请求头

```js
const authorization = await studioOauth.header('https://api.example.com');
const res = await fetch('https://api.example.com/data', {headers: {authorization}});
```

`header(resource)` 返回 `BCAuth ...` 字符串，直接作为 `Authorization` 头发给资源服务器。`resource` 填对方声明的资源标识（通常是其 origin），必须与资源服务器的配置一致。失败时抛出 `AuthError`。

## 显式登录

```js
const info = await studioOauth.login('the_public_key_with_client_have_private_key', ['https://api.example.com']);
// {token, user, resources, expires}
```

不同于 `header()`，`login(client, resources)` 用于把令牌授权给另一个持有者：`client` 传对方的公钥。

## 构建

`pnpm build` 产出 `dist/studio-oauth.user.js`。
