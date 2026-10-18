# Nebbedin Store

A community store for discovering, downloading, and publishing Ethiopian apps, games, and software. The original visual design is retained.

## Run locally

Requires Node.js 22 and npm.

```bash
npm install
cp .env.example .env
npm start
```

Open `http://localhost:3000`. Change the sample admin credentials and session secret in `.env` before exposing the app to anyone. The app creates `data/` and `uploads/` automatically.

## Render deployment

- **Root Directory:** the directory containing `server.js` and `package.json`
- **Build Command:** `npm install`
- **Start Command:** `npm start`
- **Node version:** 22.x
- Add the environment variables below in Render's Environment settings.

Required in production:
- `NODE_ENV=production`
- `APP_URL=https://YOUR-SERVICE.onrender.com` (no trailing slash)
- `SESSION_SECRET` — random secret at least 32 characters
- `ADMIN_EMAIL` — your private admin email
- `ADMIN_PASSWORD` — a unique strong password

Do not use the sample values from `.env.example` as production credentials.

### Persistent storage (important)

This starter uses SQLite and local files. On Render, attach a persistent disk with mount path `/var/data`, then set `DATA_DIR=/var/data/data` and `UPLOAD_DIR=/var/data/uploads` in the service environment. The app creates these folders automatically. Without persistent storage, accounts, sessions, and uploaded files can be lost on restart or redeploy. Back up the database and uploads.

## Email verification (optional integration; credentials required)

Set these Render environment variables using an SMTP email provider:
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `SMTP_FROM`
- `APP_URL` must be your public HTTPS Render URL.
- Set `REQUIRE_EMAIL_VERIFICATION=true`.

When SMTP is configured, email/password sign-up sends a time-limited (30 minute) verification link and the user cannot sign in until verified. Test delivery and spam handling before launch. If SMTP is not configured, this app deliberately does not claim email verification is active and standard sign-up remains enabled unless `REQUIRE_EMAIL_VERIFICATION=true`.

## Google sign-in (optional integration; Google credentials required)

1. In Google Cloud Console, create/select a project and configure the OAuth consent screen.
2. Create an OAuth client ID of type **Web application**.
3. Add your public website URL to **Authorized JavaScript origins** (for example `https://YOUR-SERVICE.onrender.com`).
4. Add this exact **Authorized redirect URI**: `https://YOUR-SERVICE.onrender.com/auth/google/callback`.
5. Set `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, and `APP_URL` in Render. Redeploy.

The “Continue with Google” button only appears when these values are configured. Google accounts must return a verified email address. Test with a separate account before launch.

## Included features

- Public browsing, search, project details, ratings, reviews, and downloads without signing in
- Email/password accounts and session restoration across refreshes
- Optional Google OAuth and SMTP email verification when configured
- Developer dashboard, profile editing, unlimited project submissions, and upload status
- Admin moderation, report handling, approval/rejection, and download counts
- File extension and per-file size checks

## Launch checklist / safety

- Configure and test persistent storage before real users upload files.
- Set unique production admin credentials and a long random session secret.
- Configure email verification and/or Google sign-in, and test on the live HTTPS URL.
- Review all uploads before publication. APKs and executables can be harmful; this starter does not scan malware. Add malware scanning, quotas, abuse handling, privacy/terms pages, and a takedown process before public launch.
- Browser games should be uploaded as ZIP files containing `index.html` at the root. Uploading a folder directly is not supported; compress it to ZIP first.
- Submissions are unlimited in count, but individual files still have size limits.


### Project cover images
The upload form supports an optional JPG, PNG, or WebP cover image (maximum 5 MB). The cover is stored alongside project uploads, associated with the project in SQLite, and displayed on Discover and the project detail page after the project is approved. Existing databases are migrated automatically at startup.
