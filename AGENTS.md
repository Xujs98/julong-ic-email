# 矩龙邮箱开发约定

## 项目标识

- 中文项目名：矩龙邮箱
- 英文仓库名：`julong-ic-email`
- GitHub 仓库：`https://github.com/Xujs98/julong-ic-email.git`
- 本项目属于基于 `q1953258942/iCloud-Privacy-Mail` 的二次开发，README 和发布资料必须保留二开说明与原项目署名。

## 完成代码后的强制流程

每次完成代码、模板、配置或公开文档修改后，必须在同一任务内依次执行：

1. 格式化修改过的代码。
2. 执行 `git diff --check`。
3. 执行与改动相关的定向测试。
4. 执行 `go test ./...`。
5. 提升 `internal/app/version.go` 中的 `AppVersion`，并更新 `更新日志.md` 与必要的发布说明。
6. 检查提交内容，排除 `config.json`、`data/`、Cookie、密码、API Key、验证码、`.codex-artifacts/` 和其他运行数据。
7. 提交本次全部预期代码改动。
8. 推送到 `origin` 的当前分支；默认分支使用 `main`。

## GitHub 推送重试

- 优先执行 `scripts/push-with-retry.sh origin <branch>`。
- 首次 `git push` 失败后必须再重试三次，即最多执行四次推送。
- 每次重试前输出当前尝试次数并短暂等待。
- 四次均失败时，保留本地提交，并在任务结果中记录四次失败原因和当前 commit。
- 推送成功后必须返回远端仓库、分支和 commit SHA。

## 提交边界

- 不重置或丢弃工作区已有修改。
- 不提交本地构建产物、验证日志和临时目录。
- 不提交任何真实账号、会话、Cookie、密码、验证码或密钥。
