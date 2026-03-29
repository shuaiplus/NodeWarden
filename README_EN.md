<p align="center">
  <img src="./NodeWarden.png" alt="NodeWarden Logo" />
</p>

<p align="center">
  A third-party Bitwarden-compatible server running on Cloudflare Workers.
</p>
[![Powered by Cloudflare](https://img.shields.io/badge/Powered%20by-Cloudflare-F38020?logo=cloudflare&logoColor=white)](https://workers.cloudflare.com/)
[![License: LGPL-3.0](https://img.shields.io/badge/License-LGPL--3.0-2ea44f)](./LICENSE)
[![Latest Release](https://img.shields.io/github/v/release/shuaiplus/NodeWarden?display_name=tag)](https://github.com/shuaiplus/NodeWarden/releases/latest)
[![Sync Upstream](https://github.com/shuaiplus/NodeWarden/actions/workflows/sync-upstream.yml/badge.svg)](https://github.com/shuaiplus/NodeWarden/actions/workflows/sync-upstream.yml)
[Release Notes](./RELEASE_NOTES.md) | [Report an Issue](https://github.com/shuaiplus/NodeWarden/issues/new/choose) | [Latest Release](https://github.com/shuaiplus/NodeWarden/releases/latest)
中文说明：[`README.md`](./README.md)

> **Disclaimer**
>
> This project is for learning and discussion purposes only. Please back up your vault regularly.
>
> This project is not affiliated with Bitwarden. Please do not report NodeWarden issues to the official Bitwarden team.

---

## Feature Comparison with the Official Bitwarden Server

| Capability | Bitwarden | NodeWarden | Notes |
|---|---|---|---|
| Web Vault | ✅ | ✅ | **Original Web Vault interface** |
| Full sync `/api/sync` | ✅ | ✅ | Compatibility optimized for official clients |
| Attachment upload / download | ✅ | ✅ | Cloudflare R2 or KV |
| Send | ✅ | ✅ | Supports both text and file Sends |
| Import / Export | ✅ | ✅ | Supports Bitwarden JSON / CSV / **ZIP import with attachments** |
| **Cloud Backup Center** | ❌ | ✅ | **Scheduled backup to WebDAV / E3** |
| Password hint (web) | ⚠️ Limited | ✅ | **No email required** |
| TOTP / Steam TOTP | ✅ | ✅ | Includes `steam://` support |
| Multi-user | ✅ | ✅ | Invite-based registration |
| Organizations / Collections / Member roles | ✅ | ❌ | Not implemented |
| Login 2FA | ✅ | ⚠️ Partial | Currently only user-level TOTP |
| SSO / SCIM / Enterprise directory | ✅ | ❌ | Not implemented |

---

## Tested Clients

- ✅ Windows desktop client
- ✅ Mobile app
- ✅ Browser extension
- ✅ Linux desktop client
- ⚠️ macOS desktop client has not been fully verified yet

---

## Web Deploy

1. Fork this repository. If this project helps you, consider giving it a Star.
2. Open [Workers](https://dash.cloudflare.com/?to=/:account/workers-and-pages/create) -> `Continue with GitHub` -> select your forked repository (`NodeWarden`) -> continue.
3. R2 is used by default. If R2 is not enabled on your account, you can use KV instead by changing the **deploy command** to `npm run deploy:kv`.
4. Deploy and open the generated URL.

| Storage | Card required | Single attachment / Send file limit | Free tier |
|---|---|---|---|
| R2 | Yes | 100 MB (soft limit, adjustable) | 10 GB |
| KV | No | 25 MiB (Cloudflare limit) | 1 GB |

> [!TIP]
> How to keep your fork updated:
> - Manual: open your fork on GitHub, click `Sync fork`, then `Update branch`
> - Automatic: go to your fork -> `Actions` -> `Sync upstream` -> `Enable workflow`; it will sync upstream automatically every day at 3 AM

## CLI Deploy

```powershell
git clone https://github.com/shuaiplus/NodeWarden.git
cd NodeWarden
npm install
npx wrangler login

# Default: R2 mode
npm run deploy

# Optional: KV mode
npm run deploy:kv

# Local development
npm run dev
npm run dev:kv
```

---

## Cloud Backup Notes

- Remote backup supports **WebDAV** and **E3**
- When `Include attachments` is enabled:
- the ZIP still contains only `db.json` and `manifest.json`
- actual attachment files are stored separately under `attachments/`
- later backups reuse existing attachments by stable blob name instead of re-uploading everything every time
- During remote restore:
- required attachment files are loaded from `attachments/` on demand
- missing attachments are skipped safely
- skipped attachments do not leave broken rows in the restored database

---

## Import / Export

Current supported import sources include:

- Bitwarden JSON
- Bitwarden CSV
- Bitwarden vault + attachments ZIP
- NodeWarden JSON
- Multiple browser / password-manager formats available in the web import selector

Current supported export formats include:

- Bitwarden JSON
- Bitwarden encrypted JSON
- ZIP export with attachments
- NodeWarden JSON variants
- Full manual instance export from the backup center

---

## License

LGPL-3.0 License

---

## Credits

- [Bitwarden](https://bitwarden.com/) - Original design and clients
- [Vaultwarden](https://github.com/dani-garcia/vaultwarden) - Server implementation reference
- [Cloudflare Workers](https://workers.cloudflare.com/) - Serverless platform

---

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=shuaiplus/NodeWarden&type=timeline&legend=top-left)](https://www.star-history.com/#shuaiplus/NodeWarden&type=timeline&legend=top-left)
