# TTA Pages repo (the-thoughtful-agency-hub.github.io)

PUBLIC repo (GitHub free plan). Every file pushed here, in any folder, can be read on github.com by anyone.

- `public-encrypted/` - the readable versions of pages; edit pages here. Never sent to GitHub (gitignored); only the locked copies in public/ are.
- `public/` - the locked (encrypted) copies, made automatically on each commit. This is what goes live at https://the-thoughtful-agency-hub.github.io/. Don't edit it directly.
- Only `public/` deploys, via `.github/workflows/deploy-pages.yml` on push to `main`.

## Encrypt vs public
- Default: encrypt. Every page goes in `public-encrypted/` and is encrypted on commit. If unsure, encrypt.
- Always encrypt: anything with client data (performance reports, revenue, ROAS, spend, dashboards); proposals or quotes with pricing; strategy docs, audits, campaign briefs; anything internal to TTA.
- Public only when told "publish this publicly": TTA marketing pages, public case studies with sensitive numbers removed, training and how-to content. Public pages skip encryption and go straight into `public/`.
- One sub-folder per client in `public-encrypted/`, named with a neutral code, never the client's name (folder names show in the public URL and repo).
- Share the URL and the password through different channels, never in the same message.
