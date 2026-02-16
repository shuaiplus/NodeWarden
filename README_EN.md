# NodeWarden
中文文档：[`README.md`](./README.md)

A **Bitwarden-compatible** server that runs on **Cloudflare Workers**.

> Disclaimer
> - This project is for learning and communication only.
> - We are not responsible for any data loss. Regular vault backups are strongly recommended.
> - This project is not affiliated with Bitwarden. Please do not report issues to the official Bitwarden team.

---

## Features

- ✅ **Completely free, no server deployment needed. Thanks again to the generous sponsor!**
- ✅ Data storage on Cloudflare D1 (SQLite)
- ✅ Full support for logins, notes, cards, and identities
- ✅ Folders and favorites
- ✅ Attachments (Cloudflare R2)
- ✅ Import / export
- ✅ Website icons
- ✅ End-to-end encryption (the server can’t see plaintext)
- ✅ Seamless updates, zero downtime

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

## Scheduled backup (AES zip to R2)

NodeWarden now supports automatic backup in `scheduled()` via cron.

- Backup runs only when `BACKUP_PASSWORD` is set (as a secret).
- If `BACKUP_PASSWORD` is missing, backup is skipped.
- Output is an AES-256 encrypted zip in your R2 bucket.
- Zip content: `export.json` and optional `attachments/`.

Optional env/secrets:

```bash
BACKUP_PASSWORD=your-strong-password
BACKUP_ENABLED=true
BACKUP_KEEP_LAST=30
BACKUP_R2_PREFIX=backups/
BACKUP_INCLUDE_ATTACHMENTS=true
```

Cron is configured in `wrangler.toml` and `wrangler.my.toml`:

```toml
[triggers]
crons = ["0 */6 * * *"]
```

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
