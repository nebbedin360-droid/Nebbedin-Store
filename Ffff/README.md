# Nebbedin Store — MVP

Nebbedin Store is a starter full-stack marketplace for Ethiopian apps, games, and software.

## Included
- Responsive storefront and search/filter UI
- Account registration and login
- Developer dashboard
- Upload form for Android APKs, PC games, browser games, and other software
- File-size limits configurable in `.env`
- Unlimited project submissions (no upload fee)
- Admin moderation dashboard to approve/reject uploads and mark upload fees paid
- SQLite database and local file storage for development
- Download counters, ratings, reviews, reporting, and developer profile pages

## Important launch notes
This is a working **starter/MVP**, not a production-hosted service. Before inviting the public:
1. Deploy on a server with persistent storage.
2. Configure HTTPS, a strong `SESSION_SECRET`, and a unique admin password.
3. Connect a real payment provider (for example, a supported Ethiopian payment gateway). The current extra-upload flow records payment status but does **not** collect money automatically.
4. Add malware scanning and a review process before allowing public downloads. Admin approval is required in this MVP.
5. Configure backups, storage quotas, monitoring, and a privacy/terms/takedown policy.
6. For large PC games, use object storage rather than local disk.
7. Never upload APKs or executables you do not own or have permission to distribute.

## Run locally
Requirements: Node.js 22 and npm.

```bash
cp .env.example .env
# Edit .env and change SESSION_SECRET and ADMIN_PASSWORD
npm install
npm start
```

Open http://localhost:3000

Default admin email/password come from `.env` (`ADMIN_EMAIL`, `ADMIN_PASSWORD`). Change them before launch.

## Upload limits
Defaults:
- APK: 250 MB
- PC game: 1000 MB
- Browser game ZIP: 100 MB
- Other software: 250 MB

Set the values in `.env`. The maximum allowed for a single upload is controlled by the matching type. The server stores uploads in `uploads/`.

## Publishing policy
Project submissions have no upload fee and are unlimited in count. Individual file-size limits still apply, and all projects require moderation before publication.

## Browser game ZIP format
For browser games, upload a ZIP containing `index.html` at its root. In this starter, browser games can be downloaded; running arbitrary uploaded HTML directly on the main domain is disabled for safety. A future deployment should serve approved web games from an isolated subdomain/sandbox.

## Production security checklist
- Use HTTPS and secure cookies behind a correctly configured proxy.
- Replace the default admin credentials.
- Integrate automated malware scanning for executable uploads.
- Keep admin moderation enabled.
- Add a formal abuse/takedown workflow.
- Add object storage/CDN for large files and enforce account-level quotas.
- Integrate real payment processing and verify payment server-side.
