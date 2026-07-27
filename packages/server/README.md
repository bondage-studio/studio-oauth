# bc-studio-oauth-server

授权服务器，部署在 Cloudflare Workers 上。路由：`/register`、`/token`、`/jwks`、`/introspect`、`/revoke`。

## 部署

1. `pnpm genkey` 生成服务器私钥（JSON）；
2. `pnpm exec wrangler secret put SERVER_KEY`，粘贴该 JSON；
3. `pnpm deploy`。

本地调试用 `pnpm dev`。
