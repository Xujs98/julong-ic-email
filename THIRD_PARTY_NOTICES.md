# 第三方声明

矩龙邮箱保留其基于 `q1953258942/iCloud-Privacy-Mail` 二次开发的署名与许可说明，详见仓库 README。


## maildotcom-sdk MAIL 别名与收件流程参考

MAIL 别名的登录、可用域名查询、创建与删除，以及移动端 PKCE OAuth、会话刷新、文件夹遍历和邮件正文读取协议流程参考了 [tanu360/maildotcom-sdk](https://github.com/tanu360/maildotcom-sdk) 的公开实现。本项目未直接引入其 TypeScript/npm 运行时，而是以 Go 重新实现相关 HTTP 流程并接入矩龙邮箱现有权限、存储和接码能力。

上游仓库许可证与版权信息以其仓库 `LICENSE` 文件为准。

## CloakMail 域名邮件能力参考

本版本的域名邮箱产品能力参考并以 Go 重新实现了 [DreamsHive/CloakMail](https://github.com/DreamsHive/cloakmail) 中的自建域名收件、收件箱生命周期和 DNS 引导思路；本仓库未引入其 Svelte UI 或 Bun 服务端源码。

CloakMail 使用 MIT License：

```text
MIT License

Copyright (c) 2025 DreamsHive

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
