# NodeWarden
中文文档：[`README.md`](./README.md)

A **Bitwarden-compatible** server that runs on **Cloudflare Workers**.

> Disclaimer
> - This project is for learning and communication only.
> - We are not responsible for any data loss. Regular vault backups are strongly recommended.
> - This project is not affiliated with Bitwarden. Please do not report issues to the official Bitwarden team.

---

## Feature Comparison Table (vs Official Bitwarden Server)

| Capability | Bitwarden  | NodeWarden | Notes |
|---|---|---|---|
| Single-user vault (logins/notes/cards/identities) | ✅ | ✅ | Core vault model supported |
| Folders / Favorites | ✅ | ✅ | Common vault organization supported |
| Full sync `/api/sync` | ✅ | ✅ | Compatibility-focused implementation |
| Attachment upload/download | ✅ | ✅ | Backed by Cloudflare R2 |
| Import flow (common clients) | ✅ | ✅ | Common import paths covered |
| Website icon proxy | ✅ | ✅ | Via `/icons/{hostname}/icon.png` |
| passkey、TOTP | ❌ | ✅ | Official service requires premium; NodeWarden does not |
| Multi-user | ✅ | ❌ | NodeWarden is single-user by design |
| Organizations / Collections / Member roles | ✅ | ❌ | Not necessary to implement |
| Login 2FA (TOTP/WebAuthn/Duo/Email) | ✅ | ⚠️ Partial | TOTP-only  via `TOTP_SECRET` |
| SSO / SCIM / Enterprise directory | ✅ | ❌ | Not necessary to implement |
| Send | ✅ | ❌ | Not necessary to implement |
| Emergency access | ✅ | ❌ | Not necessary to implement |
| Admin console / Billing & subscription | ✅ | ❌ | Free only |
| Full push notification pipeline | ✅ | ❌ | Not necessary to implement |


## Tested clients / platforms

- ✅ Windows desktop client (v2026.1.0)
- ✅ Android app (v2026.1.0)
- ✅ Browser extension (v2026.1.0)
- ⬜ macOS desktop client (not tested)
- ⬜ Linux desktop client (not tested)

---

# Quick start

### One-click deploy

**Deploy steps:**

1. Fork this project  (you don't need to fork it if you don't need to update it later).
2. [![Deploy to Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/shuaiplus/nodewarden)
3. Open the generated service URL and follow the on-page instructions.


## Local development

This repo is a Cloudflare Workers TypeScript project (Wrangler).

```bash
npm install
npm run dev
```

## Optional Login TOTP (2FA)

- Add Workers Secret `TOTP_SECRET` (Base32) to enable login TOTP.
- Remove `TOTP_SECRET` to disable login TOTP.
- Client flow: password -> TOTP code.
- "Remember this device" is supported for 30 days.

---

## FAQ

**Q: How do I back up my data?**  
A: Use **Export vault** in your client and save the JSON file.

**Q: What if I forget the master password?**  
A: It can’t be recovered (end-to-end encryption). Keep it safe.

**Q: Can multiple people use it?**  
A: Not recommended. This project is designed for single-user usage. For multi-user usage, choose Vaultwarden.

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
