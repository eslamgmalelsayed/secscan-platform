/**
 * SecScan desktop shell (Electron).
 *
 * Boots the single-process server (scripts/serve.mjs — API + web + /api proxy,
 * dev-trust) inside Electron's own Node runtime, waits for it, and opens a
 * window on it. The main process is full Node.js, so every native capability
 * (raw sockets for LAN/port scans, child_process for arp/nmcli, filesystem for
 * APK/binary analysis) is available to the agent without a browser sandbox.
 *
 * Dev:   from the repo root, `npm run build` then `npm --workspace @secscan/desktop run start`.
 * Build: `npm --workspace @secscan/desktop run dist:win` (needs electron + electron-builder installed).
 */
const { app, BrowserWindow, shell, ipcMain, session } = require('electron');
const { fork } = require('node:child_process');
const http = require('node:http');
const path = require('node:path');

const WEB_PORT = 5173;
const URL = `http://127.0.0.1:${WEB_PORT}`;
let server = null;

// In a packaged build the server script lives under resources/app; in dev it is
// the repo's scripts/serve.mjs two levels up from this file.
function serverScript() {
  const packaged = path.join(process.resourcesPath || '', 'app', 'scripts', 'serve.mjs');
  return app.isPackaged ? packaged : path.resolve(__dirname, '..', '..', 'scripts', 'serve.mjs');
}

function startServer() {
  // ELECTRON_RUN_AS_NODE makes Electron's binary run the script as plain Node.
  server = fork(serverScript(), [], {
    env: { ...process.env, ELECTRON_RUN_AS_NODE: '1', SECSCAN_WEB_PORT: String(WEB_PORT) },
    stdio: 'inherit',
  });
  server.on('exit', (code) => { if (code) console.error(`[desktop] server exited (${code})`); });
}

function waitForServer(cb, tries = 160) {
  const req = http.get(URL, () => cb()).on('error', () => {
    if (tries <= 0) return cb();
    setTimeout(() => waitForServer(cb, tries - 1), 250);
  });
  req.setTimeout(1000, () => req.destroy());
}

function createWindow() {
  const win = new BrowserWindow({
    width: 1440, height: 920, title: 'SecScan',
    webPreferences: { contextIsolation: true, nodeIntegration: false, preload: path.join(__dirname, 'preload.cjs') },
  });
  win.removeMenu?.();
  win.loadURL(URL);
  // open external links in the system browser, not inside the app window
  win.webContents.setWindowOpenHandler(({ url }) => { shell.openExternal(url); return { action: 'deny' }; });
}

/**
 * Open a real browser window at the target site, let the user sign in, and when
 * they close it, read the session cookies from that window's isolated partition
 * and POST them to the local API as a test account. This is the "normal user"
 * path — no DevTools, no copy-paste.
 */
ipcMain.handle('secscan:capture-login', async (_evt, opts) => {
  try {
    const { url, role, tenant } = opts ?? {};
    if (!url || !role) return { error: 'url and role are required' };
    const partition = `persist:capture-${Date.now()}`;
    const win = new BrowserWindow({ width: 1000, height: 760, title: `Sign in to capture — ${role}`, webPreferences: { partition } });
    win.loadURL(url);

    await new Promise((resolve) => win.once('closed', resolve)); // user logs in, then closes the window

    const sess = session.fromPartition(partition);
    const host = new URL(url).hostname;
    const cookies = await sess.cookies.get({ domain: host }).catch(() => []);
    const jar = {};
    for (const c of cookies) jar[c.name] = c.value;
    await sess.clearStorageData().catch(() => {}); // don't leave the login persisted on disk
    if (!Object.keys(jar).length) return { error: 'no cookies captured — was the login completed before closing?' };

    const body = JSON.stringify({ role, tenant: tenant || null, cookies: jar });
    const result = await new Promise((resolve) => {
      const req = http.request(`${URL}/api/identities/capture`, { method: 'POST', headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) } }, (res) => {
        let d = ''; res.on('data', (c) => (d += c)); res.on('end', () => { try { resolve(JSON.parse(d)); } catch { resolve({ error: 'capture failed' }); } });
      });
      req.on('error', () => resolve({ error: 'could not reach the local API' }));
      req.write(body); req.end();
    });
    return result;
  } catch (e) {
    return { error: String(e && e.message ? e.message : e) };
  }
});

app.whenReady().then(() => { startServer(); waitForServer(createWindow); });
app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
app.on('window-all-closed', () => { if (server) server.kill(); app.quit(); });
app.on('before-quit', () => { if (server) server.kill(); });
