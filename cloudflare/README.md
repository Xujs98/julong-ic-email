# Cloudflare 转发邮箱 Worker

本目录把 Cloudflare Email Routing 收到的原始 MIME 邮件投递到矩龙邮箱的
`POST /api/v1/forwarding/inbound` 接口。矩龙应用会按 `to` 地址匹配已有域名邮箱，
复用现有 MIME 解析和 HTML 接码页面，因此邮件会直接出现在“全部邮箱”和“转发邮箱”。

## 部署步骤

1. 在矩龙后台的“转发邮箱”页面启用转发收件，填写接收域名并复制接收 API 与签名密钥。
2. 把 `wrangler.toml.example` 复制为 `wrangler.toml`，将 `APP_ENDPOINT` 改为后台显示的接收 API。
3. 安装 Wrangler 后登录 Cloudflare：`npx wrangler login`。
4. 写入密钥：`npx wrangler secret put FORWARDING_SECRET`，粘贴后台生成的密钥。
5. 如需同时投递到 Gmail/Outlook 等外部邮箱，再执行 `npx wrangler secret put FORWARD_TO`；不需要外部副本时留空。
6. 执行 `npx wrangler deploy`，在 Cloudflare Email Routing 中把 Catch-all 或指定地址的 Action 设置为 **Send to a Worker**，选择本 Worker。
7. 从外部邮箱发送测试邮件到矩龙后台“可收件域名邮箱”列表中的地址。

## 请求安全

Worker 使用 `timestamp + "\\n" + JSON` 的 HMAC-SHA256 签名，并通过
`X-Julong-Forwarding-Timestamp` 与 `X-Julong-Forwarding-Signature` 头发送。
矩龙应用会校验时间窗口、签名、接收域名、收件邮箱状态和原始邮件大小。

## 重要说明

- Cloudflare 普通橙云代理不负责 SMTP 收件；必须使用 Email Routing + Email Worker。
- 域名需要托管在 Cloudflare，并按 Cloudflare 控制台提示完成 MX/Nameserver 配置。
- Worker 不会把完整邮件写入日志；矩龙应用只记录发件人、收件人、Message-ID 和重复状态。
- 服务器公网 TCP 25 被上游拦截时，Worker 仍可通过 HTTPS 把邮件送入矩龙应用。
