# TTA Pages repo (the-thoughtful-agency-hub.github.io)

PUBLIC repo (GitHub free plan). Every file pushed here, in any folder, can be read on github.com by anyone.

- `public-encrypted/` - source files you edit. Pushed to GitHub, so never put client data, customer details or anything sensitive here in plain text.
- `public/` - what goes live at https://the-thoughtful-agency-hub.github.io/ (generated; the folder path is the URL path).
- Only `public/` deploys, via `.github/workflows/deploy-pages.yml` on push to `main`.
- Sensitive pages wait for the CCM M08 L06 encryption setup.
