<p align="center">
  <img src="./NodeWarden.png" alt="NodeWarden Logo" />
</p>

<p align="center">
  A third-party Bitwarden server running on Cloudflare Workers, fully compatible with official clients.
</p>

[![Powered by Cloudflare](https://img.shields.io/badge/Powered%20by-Cloudflare-F38020?logo=cloudflare&logoColor=white)](https://workers.cloudflare.com/)
[![License: LGPL-3.0](https://img.shields.io/badge/License-LGPL--3.0-2ea44f)](./LICENSE)
[![Deploy to Cloudflare Workers](https://img.shields.io/badge/Deploy%20to-Cloudflare%20Workers-F38020?logo=cloudflare&logoColor=white)](https://deploy.workers.cloudflare.com/?url=https://github.com/shuaiplus/NodeWarden)
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
| Single-user vault (logins/notes/cards/identities) | ✅ | ✅ | Based on Cloudflare D1 |
| Folders / Favorites | ✅ | ✅ | Common vault organization supported |
| Full sync `/api/sync` | ✅ | ✅ | Compatibility and performance optimized |
| Attachment upload/download | ✅ | ✅ | Backed by Cloudflare R2 |
| Import flow (common clients) | ✅ | ✅ | Common import paths covered |
| Website icon proxy | ✅ | ✅ | Via `/icons/{hostname}/icon.png` |
| passkey、TOTP fields | ❌ | ✅ | Official service requires premium; NodeWarden does not |
| Multi-user | ✅ | ✅ | Full user management with invitation mechanism |
| Send | ✅ | ✅ | Text Send and File Send are supported |
| Organizations / Collections / Member roles | ✅ | ❌ | Not necessary to implement |
| Login 2FA (TOTP/WebAuthn/Duo/Email) | ✅ | ⚠️ Partial | TOTP-only  via `TOTP_SECRET` |
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

# Quick start

### One-click deploy

**Deploy steps:**

1. Fork this repository and name it **NodeWarden**.
2. Click the deploy button below, rename the project to **NodeWarden2**, and set **JWT_SECRET** to a 32-character random string.
3. [![Deploy to Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/shuaiplus/nodewarden)
4. After deployment, open the Workers settings on the same page and disconnect the **Git repository**.
5. From the same location, reconnect the **Git repository** to the fork you created in step 1.

**Sync upstream (update):**
- Manual: Open your forked repository on GitHub and click **Sync fork** when the sync prompt appears at the top.
- Automatic: Go to your fork → Actions, click "I understand my workflows, go ahead and enable them". The repository will auto-sync with upstream every day at 3 AM.

### CLI deploy 

```powershell
# Clone repository
git clone https://github.com/shuaiplus/NodeWarden.git
cd NodeWarden

# Install dependencies
npm install

# Cloudflare CLI login
npx wrangler login

# Create cloud resources (D1 + R2)
npx wrangler d1 create nodewarden-db
npx wrangler r2 bucket create nodewarden-attachments

# Deploy
npx wrangler deploy

# To update later: re-clone and re-deploy — no need to recreate cloud resources
git clone https://github.com/shuaiplus/NodeWarden.git
cd NodeWarden
npx wrangler deploy
```

---
## Local development

This repo is a Cloudflare Workers TypeScript project (Wrangler).

```bash
npm install
npm run dev
```
---

## FAQ

**Q: How do I back up my data?**  
A: Use **Export vault** in your client and save the JSON file.

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
