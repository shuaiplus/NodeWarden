# NodeWarden
English：[`README_EN.md`](./README_EN.md)

运行在 **Cloudflare Workers** 上的 **Bitwarden 第三方服务端**。

> **免责声明**  
> 本项目仅供学习交流使用。我们不对任何数据丢失负责，强烈建议定期备份您的密码库。  
> 本项目与 Bitwarden 官方无关，请勿向 Bitwarden 官方反馈问题。

---
## 与 Bitwarden 官方服务端能力对比

| 能力项 | Bitwarden | NodeWarden | 说明 |
|---|---|---|---|
| 单用户保管库（登录/笔记/卡片/身份） | ✅ | ✅ | 基于Cloudflare D1 |
| 文件夹 / 收藏 | ✅ | ✅ | 常用管理能力可用 |
| 全量同步 `/api/sync` | ✅ | ✅ | 已做兼容与性能优化 |
| 附件上传/下载 | ✅ | ✅ | 基于 Cloudflare R2 |
| 导入功能 | ✅ | ✅ | 覆盖常见导入路径 |
| 网站图标代理 | ✅ | ✅ | 通过 `/icons/{hostname}/icon.png` |
| passkey、TOTP | ❌ | ✅ |官方需要会员，我们的不需要 |
| 多用户 | ✅ | ❌ | NodeWarden 定位单用户 |
| 组织/集合/成员权限 | ✅ | ❌ | 没必要实现 |
| 登录 2FA（TOTP/WebAuthn/Duo/Email） | ✅ | ⚠️ 部分支持 | 仅支持 TOTP（通过 `TOTP_SECRET`） |
| SSO / SCIM / 企业目录 | ✅ | ❌ | 没必要实现 |
| Send | ✅ | ❌ | 基本没人用 |
| 紧急访问 | ✅ | ❌ | 没必要实现 |
| 管理后台 / 计费订阅 | ✅ | ❌ | 纯免费 |
| 推送通知完整链路 | ✅ | ❌ | 没必要实现 |

## 测试情况：

- ✅ Windows 客户端（v2026.1.0）
- ✅ 手机 App（v2026.1.0）
- ✅ 浏览器扩展（v2026.1.0）
- ⬜ macOS 客户端（未测试）
- ⬜ Linux 客户端（未测试）
---

# 快速开始

### 一键部署

**部署步骤：**

1. 先在右上角fork此项目（若后续不需要更新，可不fork）
2. [![Deploy to Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/shuaiplus/nodewarden)
3. 打开部署后生成的链接，并根据网页提示完成后续操作。

---

## 本地开发

这是一个 Cloudflare Workers 的 TypeScript 项目（Wrangler）。

```bash
npm install
npm run dev
```

## 可选：登录 TOTP（2FA）

- 在 Workers 的 Variables and Secrets 里新增 Secret：`TOTP_SECRET`（Base32）。
- 配置了 `TOTP_SECRET` 就启用登录 TOTP；删除该变量即关闭。
- 客户端流程：密码 -> TOTP 验证码。
- 支持“记住此设备”30 天。

---

## 常见问题

**Q: 如何备份数据？**  
A: 在客户端中选择「导出密码库」，保存 JSON 文件。

**Q: 忘记主密码怎么办？**  
A: 无法恢复，这是端到端加密的特性。建议妥善保管主密码。

**Q: 可以多人使用吗？**  
A: 不建议。本项目为单用户设计，多人使用请选择 Vaultwarden。

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
