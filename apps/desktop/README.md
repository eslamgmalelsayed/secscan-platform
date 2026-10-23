# SecScan Desktop (Electron)

A thin Electron shell around the existing platform. It starts the single-process
server (`scripts/serve.mjs` — API + web console + `/api` proxy, dev-trust local
mode) inside Electron's Node runtime and opens a window on it. Because the main
process is full Node.js, the native capabilities (raw sockets for LAN/port
scans, `arp`/`nmcli` for the WiFi/ARP agent, filesystem for APK/binary analysis)
are available without the browser sandbox.

## Run in dev (from the repo root)

```bash
npm install                    # installs electron + electron-builder for this workspace
npm run build                  # builds engine/checks/api/web/etc.
npm --workspace @secscan/desktop run start
```

The window opens on `http://127.0.0.1:5173`. Drop an `identities.json` at the
repo root to enable the IDOR/BFLA engine; use the Quick scan box for your own
targets.

## Build a Windows installer

```bash
npm --workspace @secscan/desktop run dist:win
```

Produces an NSIS installer under `apps/desktop/dist/`.

### Packaging notes (tune on first build)

- `electron-builder` must bundle the server script, the built web, every
  `packages/*/dist`, and `node_modules`. The `build.extraResources` globs in
  `package.json` are a starting point; adjust paths if a `require` fails at
  runtime in the packaged app (check the DevTools console / terminal).
- `@secscan/api` runs `prisma generate` during build — run `npm run build` once
  with network access so the generated client exists before packaging.
- Code-signing (Windows Authenticode, macOS notarization) is separate and must
  be configured with your own certificates before distribution.

This shell reuses the web UI as-is; the API stays server-runnable, so the
web/SaaS path remains open alongside the desktop app.

## Code-signing & auto-update (for distribution)

Unsigned installers trigger SmartScreen/Gatekeeper warnings. Signing needs your
own certificate — add it to `build` in `package.json` (nothing to commit here):

- **Windows (Authenticode):** set env `CSC_LINK` (path to your `.pfx`) and
  `CSC_KEY_PASSWORD`, then run `dist:win`. electron-builder signs automatically.
- **macOS (notarization):** set `CSC_LINK`/`CSC_KEY_PASSWORD` plus
  `APPLE_ID`, `APPLE_APP_SPECIFIC_PASSWORD`, `APPLE_TEAM_ID`.

**Auto-update:** add an electron-builder `publish` target (e.g. a GitHub
releases provider) and wire `electron-updater` in `main.cjs`
(`autoUpdater.checkForUpdatesAndNotify()` on `app.whenReady`). Left out by
default so the app has no network/update behaviour until you choose a channel.
