/**
 * Preload bridge (contextIsolation on). Exposes a minimal, explicit surface to
 * the renderer — never raw Node. `captureLogin` opens a real login window and
 * returns the captured session as a test account.
 */
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('secscan', {
  desktop: true,
  platform: process.platform,
  version: process.versions.electron,
  // Open a window at `url`, let the user sign in, and capture the session on
  // close as a test account (role/tenant). Returns { captured, identities } or { error }.
  captureLogin: (opts) => ipcRenderer.invoke('secscan:capture-login', opts),
});
