<p align="center">
  <img src="./NodeWarden.png" alt="NodeWarden Logo" />
</p>

<p align="center">
  A third-party Bitwarden server running on Cloudflare Workers, fully compatible with official clients.
</p>

[![Powered by Cloudflare](https://img.shields.io/badge/Powered%20by-Cloudflare-F38020?logo=cloudflare&logoColor=white)](https://workers.cloudflare.com/)
[![License: LGPL-3.0](https://img.shields.io/badge/License-LGPL--3.0-2ea44f)](./LICENSE)
[![Latest Release](https://img.shields.io/github/v/release/shuaiplus/NodeWarden?display_name=tag)](https://github.com/shuaiplus/NodeWarden/releases/latest)
[![Sync Upstream](https://github.com/shuaiplus/NodeWarden/actions/workflows/sync-upstream.yml/badge.svg)](https://github.com/shuaiplus/NodeWarden/actions/workflows/sync-upstream.yml)

[Release Notes](./RELEASE_NOTES.md) • [Report an Issue](https://github.com/shuaiplus/NodeWarden/issues/new/choose) • [Latest Release](https://github.com/shuaiplus/NodeWarden/releases/latest)

中文文档：[`README.md`](./README.md)

> **Disclaimer**  
> This project is for learning and communication purposes only. We are not responsible for any data loss; regular vault backups are strongly recommended.  
> This project is not affiliated with Bitwarden. Please do not report issues to the official Bitwarden team.

---

## Feature Comparison Table (vs Official Bitwarden Server)

| Capability | Bitwarden  | NodeWarden | Notes |
|---|---|---|---|
| Web Vault (logins/notes/cards/identities) | ✅ | ✅ | Web-based vault management UI |
| Folders / Favorites | ✅ | ✅ | Common vault organization supported |
| Full sync `/api/sync` | ✅ | ✅ | Compatibility and performance optimized |
| Attachment upload/download | ✅ | ✅ | Choose either Cloudflare R2 or KV |
| Import / export | ✅ | ✅ | Fully implemented, including Bitwarden vault + attachments ZIP import |
| Website icon proxy | ✅ | ✅ | Via `/icons/{hostname}/icon.png` |
| passkey / TOTP fields | ✅ | ✅ | Fully supported, no premium required |
| Send | ✅ | ✅ | Choose either Cloudflare R2 or KV |
| Multi-user | ✅ | ✅ | Full user management with invitation mechanism |
| Organizations / Collections / Member roles | ✅ | ❌ | Not necessary to implement |
| Login 2FA (TOTP/WebAuthn/Duo/Email) | ✅ | ⚠️ Partial | User-level TOTP only |
| SSO / SCIM / Enterprise directory | ✅ | ❌ | Not necessary to implement |
| Emergency access | ✅ | ❌ | Not necessary to implement |
| Admin console / Billing & subscription | ✅ | ❌ | Free only |
| Full push notification pipeline | ✅ | ❌ | Not necessary to implement |

## Tested clients / platforms

- ✅ Windows desktop client (v2026.1.0)
- ✅ Mobile app (v2026.1.0)
- ✅ Browser extension (v2026.1.0)
- ✅ Linux desktop client (v2026.1.0)
- ⬜ macOS desktop client (not tested)

---

## Web deploy

1. Fork this repository. If you find this project helpful, please consider giving it a Star.
2. Open [Workers](https://dash.cloudflare.com/?to=/:account/workers-and-pages/create) -> `Continue with GitHub` -> select your forked repository (`NodeWarden`) -> `Next` -> (R2 storage is used by default; if R2 is unavailable for your account, switch to KV and change the deploy command to `npm run deploy:kv`) -> deploy -> open the generated URL.

| Storage | Card required | Single attachment / Send file limit | Free tier |
|---|---|---|---|
| R2 | Yes | 100 MB (soft limit, can be changed) | 10 GB |
| KV | No | 25 MiB (Cloudflare limit, cannot be changed) | 1 GB |

> [!TIP] 
> Sync upstream (keep your fork updated):
>- Manual: open your fork on GitHub, click `Sync fork`, then click `Update branch`.
>- Automatic: in your fork, go to `Actions` -> `Sync upstream` -> `Enable workflow`. It will automatically sync from upstream every day at 3 AM.

## CLI deploy 

```powershell
# Clone repository
git clone https://github.com/shuaiplus/NodeWarden.git
cd NodeWarden

# Install dependencies
npm install

# Cloudflare CLI login
npx wrangler login

# Deploy to Cloudflare
npm run deploy 

# (Optional) KV mode (no R2 / no credit card)
npm run deploy:kv

# Local development
npm run dev
npm run dev:kv

# To update later, pull the repository again and redeploy
git clone https://github.com/shuaiplus/NodeWarden.git
cd NodeWarden
npm run deploy 
```
---

## FAQ

**Q: How do I back up my data?**  
A: Use **Export vault** in your client and save the JSON file.

**Q: Which import/export formats are supported?**  
A: NodeWarden supports Bitwarden `json/csv/vault + attachments zip` and NodeWarden `vault + attachments json` in both plain and encrypted modes, and every format visible in the import selector is directly importable.  
A: It also supports direct import of Bitwarden `vault + attachments zip`, which is not directly supported by official Bitwarden Web import.

**Q: What if I forget the master password?**  
A: It can’t be recovered (end-to-end encryption). Keep it safe.

**Q: Can multiple people use it?**  
A: Yes. The first registered user becomes the admin. The admin can generate invite codes from the admin panel, and other users register with those codes.

---

## License

LGPL-3.0 License

---

## Credits

- [Bitwarden](https://bitwarden.com/) - original design and clients
- [Vaultwarden](https://github.com/dani-garcia/vaultwarden) - server implementation reference
- [Cloudflare Workers](https://workers.cloudflare.com/) - serverless platform



---
## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=shuaiplus/NodeWarden&type=timeline&legend=top-left)](https://www.star-history.com/#shuaiplus/NodeWarden&type=timeline&legend=top-left)
