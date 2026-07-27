# BC Studio OAuth

为 Bondage Club 模组生态提供的授权体系：玩家在浏览器中通过 mod 持有身份，第三方资源服务器验证签名令牌。没有账号密码，身份就是一把 Ed25519 密钥。

## 工作方式

1. mod 在浏览器内生成密钥对，向授权服务器注册并绑定玩家的 MemberNumber；
2. mod 用私钥换取访问令牌，并自动缓存、刷新；
3. 请求资源服务器时，mod 用私钥把令牌签成一次性持有者证明（`Authorization: BCAuth ...`）；
4. 资源服务器验证证明与令牌，确认玩家身份和授权范围。

## 子项目

| 目录 | 说明 |
| --- | --- |
| [packages/mod](packages/mod) | 浏览器端 mod，向其他 mod 提供 `studioOauth` 调用接口 |
| [packages/resource-client](packages/resource-client) | 资源服务器端的验证库 |
| [packages/core](packages/core) | 协议实现：密钥、签名、令牌与证明 |
| [packages/server](packages/server) | 授权服务器 |
