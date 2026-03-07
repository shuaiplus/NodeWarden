<p align="center">
  <img src="./NodeWarden.png" alt="NodeWarden Logo" />
</p>

<p align="center">
  运行在 Cloudflare Workers 的 Bitwarden 第三方服务端，兼容官方客户端
</p>

[![Powered by Cloudflare](https://img.shields.io/badge/Powered%20by-Cloudflare-F38020?logo=cloudflare&logoColor=white)](https://workers.cloudflare.com/)
[![License: LGPL-3.0](https://img.shields.io/badge/License-LGPL--3.0-2ea44f)](./LICENSE)
[![Latest Release](https://img.shields.io/github/v/release/shuaiplus/NodeWarden?display_name=tag)](https://github.com/shuaiplus/NodeWarden/releases/latest)
[![Sync Upstream](https://github.com/shuaiplus/NodeWarden/actions/workflows/sync-upstream.yml/badge.svg)](https://github.com/shuaiplus/NodeWarden/actions/workflows/sync-upstream.yml)

[更新日志](./RELEASE_NOTES.md) • [提交问题](https://github.com/shuaiplus/NodeWarden/issues/new/choose) • [最新发布](https://github.com/shuaiplus/NodeWarden/releases/latest)

English：[`README_EN.md`](./README_EN.md)


> **免责声明**  
> 本项目仅供学习交流使用。我们不对任何数据丢失负责，强烈建议定期备份您的密码库。  
> 本项目与 Bitwarden 官方无关，请勿向 Bitwarden 官方反馈问题。

---
## 与 Bitwarden 官方服务端能力对比

| 能力项 | Bitwarden | NodeWarden | 说明 |
|---|---|---|---|
| Web Vault（登录/笔记/卡片/身份） | ✅ | ✅ | 网页端密码库管理页面 |
| 文件夹 / 收藏 | ✅ | ✅ | 常用管理能力可用 |
| 全量同步 `/api/sync` | ✅ | ✅ | 已做兼容与性能优化 |
| 附件上传/下载 | ✅ | ✅ | Cloudflare R2 和 KV 二选一 |
| 导入导出功能 | ✅ | ✅ | 完整实现，含 Bitwarden 密码库+附件 ZIP 导入 |
| 网站图标代理 | ✅ | ✅ | 通过 `/icons/{hostname}/icon.png` |
| passkey、TOTP 字段 | ✅ | ✅ | 完全支持，无需高级版 |
| Send | ✅ | ✅ | Cloudflare R2 和 KV 二选一 |
| 多用户 | ✅ | ✅ | 完整的用户管理，邀请机制 |
| 组织/集合/成员权限 | ✅ | ❌ | 没必要实现 |
| 登录 2FA（TOTP/WebAuthn/Duo/Email） | ✅ | ⚠️ 部分支持 | 仅支持用户级 TOTP |
| SSO / SCIM / 企业目录 | ✅ | ❌ | 没必要实现 |
| 紧急访问 | ✅ | ❌ | 没必要实现 |
| 管理后台 / 计费订阅 | ✅ | ❌ | 纯免费 |
| 推送通知完整链路 | ✅ | ❌ | 没必要实现 |

## 测试情况：

- ✅ Windows 客户端（v2026.1.0）
- ✅ 手机 App（v2026.1.0）
- ✅ 浏览器扩展（v2026.1.0）
- ✅ Linux 客户端（v2026.1.0）
- ⬜ macOS 客户端（未测试）
---


## 网页部署


1. Fork 本仓库。若本项目对你有帮助，欢迎点个 Star。
2. 打开 [Workers](https://dash.cloudflare.com/?to=/:account/workers-and-pages/create) ➜ `Continue with GitHub` ➜ 选择你 Fork 后的仓库（`NodeWarden`）➜ 下一步 ➜ （默认使用 R2 存储；若未开通，可切换为 KV，并将部署命令改为 `npm run deploy:kv`）➜ 部署 ➜ 打开生成的链接

   | 储存 | 是否需绑卡 | 单个附件/Send文件上限 | 免费额度 |
   |---|---|---|---|
   | R2 | 需要 | 100 MB（软限制可更改） | 10 GB |
   | KV | 不需要 | 25 MiB（Cloudflare限制） | 1 GB |

> [!TIP] 
> 同步方法（更新仓库）：
>- 手动：打开你 Fork 的 GitHub 仓库，看到顶部同步提示后，点击 `Sync fork` ➜ `Update branch`
>- 自动：进入你的 Fork 仓库 ➜ `Actions` ➜ `Sync upstream` ➜ `Enable workflow`，会在每天凌晨 3 点自动同步上游。



## CLI 部署

```powershell
# 先把仓库拉到本地
git clone https://github.com/shuaiplus/NodeWarden.git
cd NodeWarden

# 安装依赖
npm install

# Cloudflare CLI 登录
npx wrangler login

# 部署到 Cloudflare
npm run deploy 

# （可选）KV 模式（无 R2 / 无信用卡）
npm run deploy:kv

# 本地开发
npm run dev
npm run dev:kv

# 后续更新时重新拉取仓库并重新部署即可，无需重复创建云资源
git clone https://github.com/shuaiplus/NodeWarden.git
cd NodeWarden
npm run deploy 
```


---
## 常见问题

**Q: 如何备份数据？**  
A: 在客户端中选择「导出密码库」，保存 JSON 文件。

**Q: 导入导出支持哪些格式？**  
A: 支持 Bitwarden `json/csv/密码库+附件 zip` 和 NodeWarden `密码库+附件 json`（均含加密模式），且导入下拉中看到的格式都可直接导入。  
A: 另外还支持直接导入 Bitwarden `密码库+附件 zip`，这条路径官方 Bitwarden Web 暂不支持。

**Q: 忘记主密码怎么办？**  
A: 无法恢复，这是端到端加密的特性。建议妥善保管主密码。

**Q: 可以多人使用吗？**  
A: 支持。第一个注册的用户会自动成为管理员；管理员可在管理页面生成邀请码，其他用户凭邀请码注册。

---

## 开源协议

LGPL-3.0 License

---

## 致谢

- [Bitwarden](https://bitwarden.com/) - 原始设计和客户端
- [Vaultwarden](https://github.com/dani-garcia/vaultwarden) - 服务器实现参考
- [Cloudflare Workers](https://workers.cloudflare.com/) - 无服务器平台

---
## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=shuaiplus/NodeWarden&type=timeline&legend=top-left)](https://www.star-history.com/#shuaiplus/NodeWarden&type=timeline&legend=top-left)
