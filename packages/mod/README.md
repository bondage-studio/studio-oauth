# @bc-studio/oauth-mod

装入游戏后在全局暴露 `studioOauth`，其他 mod 通过它调用需要身份验证的接口。令牌的获取、缓存、刷新全部自动完成，调用方只需要一个方法。

## 集成

从 [GitHub Releases](https://github.com/bondage-studio/studio-oauth/releases) 下载 `studio-oauth.js`，直接内联进你的 mod 代码。

```
https://github.com/bondage-studio/studio-oauth/releases/latest/download/studio-oauth.js
```

打包时以副作用引入，或直接把文件拼在 bundle 顶部：

```js
import './vendor/studio-oauth.js';
```

加载后它会向 bcModSdk 注册自己，并在全局暴露 `studioOauth`。

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