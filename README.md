<p align="center">
  <img src="./NodeWarden.png" alt="NodeWarden Logo" />
</p>

<p align="center">
  运行在 Cloudflare Workers 上的第三方 Bitwarden 兼容服务端。
</p>

[![Powered by Cloudflare](https://img.shields.io/badge/Powered%20by-Cloudflare-F38020?logo=cloudflare&logoColor=white)](https://workers.cloudflare.com/)
[![License: LGPL-3.0](https://img.shields.io/badge/License-LGPL--3.0-2ea44f)](./LICENSE)
[![Latest Release](https://img.shields.io/github/v/release/shuaiplus/NodeWarden?display_name=tag)](https://github.com/shuaiplus/NodeWarden/releases/latest)
[![Sync Upstream](https://github.com/shuaiplus/NodeWarden/actions/workflows/sync-upstream.yml/badge.svg)](https://github.com/shuaiplus/NodeWarden/actions/workflows/sync-upstream.yml)

[更新日志](./RELEASE_NOTES.md) | [提交问题](https://github.com/shuaiplus/NodeWarden/issues/new/choose) | [最新发布](https://github.com/shuaiplus/NodeWarden/releases/latest)

English: [`README_EN.md`](./README_EN.md)

> **免责声明**  
> 本项目仅供学习与交流使用，请定期备份你的密码库。  
> 本项目与 Bitwarden 官方无关，请不要向 Bitwarden 官方反馈 NodeWarden 的问题。

---

## 与 Bitwarden 官方服务端能力对比

| 能力 | Bitwarden | NodeWarden | 说明 |
|---|---|---|---|
| 网页密码库 | ✅ | ✅ | **原创Web Vault界面** |
| 全量同步 `/api/sync` | ✅ | ✅ | 已针对官方客户端做兼容优化 |
| 附件上传 / 下载 | ✅ | ✅ | Cloudflare R2 或 KV |
| Send | ✅ | ✅ | 支持文本与文件 Send |
| 导入 / 导出 | ✅ | ✅ | 支持 Bitwarden JSON / CSV / **ZIP 导入（包括附件）** |
| **云端备份中心** | ❌ | ✅ | **支持 WebDAV / E3 定时备份** |
| 密码提示（网页端） | ⚠️ 有限 | ✅ | **无需发送邮件** |
| TOTP / Steam TOTP | ✅ | ✅ | 含 `steam://` 支持 |
| 多用户 | ✅ | ✅ | 支持邀请码注册 |
| 组织 / 集合 / 成员权限 | ✅ | ❌ | 未实现 |
| 登录 2FA | ✅ | ⚠️ 部分支持 | 当前仅支持用户级 TOTP |
| SSO / SCIM / 企业目录 | ✅ | ❌ | 未实现 |

---

## 已测试客户端

- ✅ Windows 桌面端
- ✅ 手机 App
- ✅ 浏览器扩展
- ✅ Linux 桌面端
- ⚠️ macOS 桌面端尚未完整验证

---

## 网页部署

1. Fork `NodeWarden` 仓库到自己的 GitHub 账号
2. 进入  [Cloudflare Workers 创建页面](https://dash.cloudflare.com/?to=/:account/workers-and-pages/create)
3. 选择 `Continue with GitHub`
4. 选择你刚刚 Fork 的仓库
5. 保持默认配置继续部署
6. 如果你打算用 KV 模式，把部署命令改成 `npm run deploy:kv`
7. 等部署完成后，打开生成的 Workers 域名
8. 根据页面提示设置`JWT_SECRET` ，不建议临时乱填。这个值直接关系到令牌签发安全，正式环境至少使用 32 个字符以上的随机字符串。

> [!TIP] 
> 默认R2与可选KV的区别：
>   | 储存 | 是否需绑卡 | 单个附件/Send文件上限 | 免费额度 |
>   |---|---|---|---|
>   | R2 | 需要 | 100 MB（软限制可更改） | 10 GB |
>   | KV | 不需要 | 25 MiB（Cloudflare限制） | 1 GB |


## 更新方法：
- 手动：打开你 Fork 的 GitHub 仓库，看到顶部同步提示后，点击 `Sync fork` ➜ `Update branch`
- 自动：进入你的 Fork 仓库 ➜ `Actions` ➜ `Sync upstream` ➜ `Enable workflow`，会在每天凌晨 3 点自动同步上游。



## CLI 部署

```powershell
git clone https://github.com/shuaiplus/NodeWarden.git
cd NodeWarden

npm install
npx wrangler login

# 默认：R2 模式
npm run deploy

# 可选：KV 模式
npm run deploy:kv

# 本地开发
npm run dev
npm run dev:kv
```

---

## 云端备份说明

- 远程备份支持 **WebDAV** 与 **E3**
- 勾选“包含附件”后：
  - ZIP 内仍只包含 `db.json` 与 `manifest.json`
  - 真实附件单独存放在 `attachments/`
  - 后续备份会按稳定 blob 名复用已有附件，不会每次全量重传
- 远程还原时：
  - 会从 `attachments/` 目录按需读取附件
  - 缺失的附件会被安全跳过
  - 被跳过的附件不会在恢复后的数据库中留下脏记录

---

## 导入 / 导出

当前支持的导入来源包括：

- Bitwarden JSON
- Bitwarden CSV
- Bitwarden 密码库 + 附件 ZIP
- NodeWarden JSON
- 网页导入器里可见的多种浏览器 / 密码管理器格式

当前支持的导出方式包括：

- Bitwarden JSON
- Bitwarden 加密 JSON
- 带附件的 ZIP 导出
- NodeWarden JSON 系列
- 备份中心中的实例级完整手动导出

---


## 开源协议

LGPL-3.0 License

---

## 致谢

- [Bitwarden](https://bitwarden.com/) - 原始设计与客户端
- [Vaultwarden](https://github.com/dani-garcia/vaultwarden) - 服务端实现参考
- [Cloudflare Workers](https://workers.cloudflare.com/) - 无服务器平台

---

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=shuaiplus/NodeWarden&type=timeline&legend=top-left)](https://www.star-history.com/#shuaiplus/NodeWarden&type=timeline&legend=top-left)
