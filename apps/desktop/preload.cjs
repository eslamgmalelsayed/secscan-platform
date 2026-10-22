/**
 * Preload bridge. Kept minimal and safe (contextIsolation on): the renderer is
 * the same web console that runs in a browser, so it talks to the API over HTTP
 * exactly as before. Native-only desktop capabilities (LAN/WiFi agent, binary
 * analysis) will be exposed here as explicit, audited IPC methods as they land —
 * never raw Node in the renderer.
 */
const { contextBridge } = require('electron');

contextBridge.exposeInMainWorld('secscan', {
  desktop: true,
  platform: process.platform,
  version: process.versions.electron,
});
