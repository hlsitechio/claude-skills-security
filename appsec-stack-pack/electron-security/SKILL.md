---
name: electron-security
description: Security audit for Electron desktop applications including context isolation, nodeIntegration, sandbox config, preload scripts, IPC (ipcMain/ipcRenderer/contextBridge), webview tag risks, deep link handling, auto-updater security, and Electron CVE awareness. Use this skill whenever the user mentions Electron, electron-builder, contextBridge, nodeIntegration, preload.js, BrowserWindow webPreferences, ipcMain, ipcRenderer, electron-updater, or asks "audit my Electron app", "Electron security", "is my preload safe". Trigger when the codebase contains `electron` in package.json or `electron.js`/`main.ts` referenced as entry.
---

# Electron Security Audit

Audit Electron desktop apps. Electron combines a Chromium renderer with a Node main process — the most dangerous configurations let renderer code call Node APIs directly.

## When this skill applies

- Reviewing BrowserWindow webPreferences
- Auditing preload scripts and contextBridge usage
- Reviewing IPC channels for unsafe exposure
- Checking deep link / protocol handler implementations
- Reviewing auto-updater configuration

## Workflow

Follow `../_shared/audit-workflow.md`.

### Phase 1: Stack detection

```bash
grep -E '"electron":' package.json
electron --version 2>/dev/null
find . -name 'electron-builder.*' -o -name 'forge.config.*' 2>/dev/null
```

Electron version matters — Chromium and Node versions update together; old Electron = old Chromium = unpatched browser CVEs.

### Phase 2: Inventory

```bash
# BrowserWindow configs
grep -rn 'new BrowserWindow\|webPreferences' src/ main/ 2>/dev/null

# Preload references
grep -rn 'preload:' src/ main/ 2>/dev/null

# IPC handlers
grep -rn 'ipcMain.handle\|ipcMain.on\|ipcRenderer.send\|ipcRenderer.invoke' src/ main/ renderer/ 2>/dev/null

# Context bridge
grep -rn 'contextBridge.exposeInMainWorld' src/ main/ 2>/dev/null

# Webview tags
grep -rn '<webview\|webview:' src/ main/ 2>/dev/null

# Protocol handlers
grep -rn 'app.setAsDefaultProtocolClient\|protocol.registerSchemesAsPrivileged' src/ main/ 2>/dev/null
```

### Phase 3: Detection — the checks

#### BrowserWindow webPreferences

The default-secure pattern (Electron 12+):

```js
new BrowserWindow({
  webPreferences: {
    contextIsolation: true,      // ← must be true
    nodeIntegration: false,      // ← must be false
    sandbox: true,                // ← preferred true
    webSecurity: true,            // ← default true; never disable
    allowRunningInsecureContent: false,  // ← never true
    preload: path.join(__dirname, 'preload.js'),
  },
});
```

- **ELC-WP-1** `contextIsolation: true`. False = renderer can access Node APIs directly via globals.
- **ELC-WP-2** `nodeIntegration: false`. True = `require('child_process').exec(...)` works from any rendered page.
- **ELC-WP-3** `sandbox: true` when feasible. Sandboxed renderer can't use Node even in preload (use contextBridge for safe IPC).
- **ELC-WP-4** `webSecurity: true` (default). Never disable; turns off same-origin policy.
- **ELC-WP-5** `allowRunningInsecureContent: false`.
- **ELC-WP-6** `experimentalFeatures: false`.
- **ELC-WP-7** `enableRemoteModule: false` (removed in Electron 14+; check for `@electron/remote` use which has similar risks).

The above is non-negotiable for any app loading remote content. For apps that load only local files, defaults are still recommended (defense in depth).

#### Preload scripts and contextBridge

With `contextIsolation: true`, the preload script has access to a privileged context separated from the renderer's web context. To expose APIs to the renderer:

```js
// preload.js
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('api', {
  // EXPOSE specific, narrow APIs
  saveFile: (data) => ipcRenderer.invoke('save-file', data),
  loadFile: (path) => ipcRenderer.invoke('load-file', path),
});
```

- **ELC-PL-1** Preload doesn't expose generic functions like `eval`, `require`, full `ipcRenderer`, or `fs` directly.
- **ELC-PL-2** Each exposed function in `api.*` corresponds to a vetted main-process handler. The renderer can call only what's exposed.
- **ELC-PL-3** Exposed functions don't accept renderer-controlled arguments that the main process trusts as filesystem paths, command strings, or URLs without validation.

#### IPC handlers

```js
// main.js
ipcMain.handle('load-file', async (event, filepath) => {
  // BAD — renderer can pass any path
  return fs.readFile(filepath);
  
  // GOOD — validate path is in allowed directory
  const safeRoot = path.resolve(app.getPath('userData'), 'documents');
  const resolved = path.resolve(safeRoot, filepath);
  if (!resolved.startsWith(safeRoot + path.sep)) {
    throw new Error('Forbidden path');
  }
  return fs.readFile(resolved);
});
```

- **ELC-IPC-1** Every `ipcMain.handle` / `ipcMain.on` validates inputs from the renderer.
- **ELC-IPC-2** No IPC handler does shell command execution with renderer-supplied args.
- **ELC-IPC-3** No IPC handler reads arbitrary filesystem paths — confine to known directories.
- **ELC-IPC-4** Verify `event.senderFrame` if multiple webContents could send IPC; subframes are a vector.
- **ELC-IPC-5** No `ipcMain.on` (fire-and-forget) for security-sensitive operations — use `ipcMain.handle` so renderer can't replay without ack.

#### Webview tag

`<webview>` is the in-app browser; it's notoriously dangerous.

- **ELC-WV-1** `<webview>` disabled if not used — set `webviewTag: false` in webPreferences.
- **ELC-WV-2** If used: handle `will-attach-webview` to constrain webPreferences:
  ```js
  app.on('web-contents-created', (event, contents) => {
    contents.on('will-attach-webview', (e, webPreferences, params) => {
      delete webPreferences.preload;
      webPreferences.nodeIntegration = false;
      webPreferences.contextIsolation = true;
      // Block navigation to internal pages
      if (!params.src.startsWith('https://')) e.preventDefault();
    });
  });
  ```
- **ELC-WV-3** Prefer `<iframe>` with appropriate `sandbox` over `<webview>` when possible.

#### Navigation control

Renderer should not be able to navigate the BrowserWindow to arbitrary URLs:

- **ELC-NAV-1** `will-navigate` handler restricts navigation to allowlisted origins:
  ```js
  contents.on('will-navigate', (e, url) => {
    const parsedUrl = new URL(url);
    if (!['app.yourorg.com'].includes(parsedUrl.host)) {
      e.preventDefault();
    }
  });
  ```
- **ELC-NAV-2** `setWindowOpenHandler` (replaces `new-window`) restricts what `window.open` / target=_blank does:
  ```js
  contents.setWindowOpenHandler(({ url }) => {
    shell.openExternal(url);   // open in default browser
    return { action: 'deny' };
  });
  ```

#### Content Security Policy

- **ELC-CSP-1** App's CSP set via meta tag or main-process header injection. Same patterns as web — restrict script-src, no `unsafe-inline` unless required.
- **ELC-CSP-2** Local content uses `app://` or `file://` carefully; consider registering a custom protocol and serving from it (better security model than file://).

#### Deep links / protocol handlers

```js
app.setAsDefaultProtocolClient('myapp');
app.on('open-url', (event, url) => {
  // url is from any source — validate
});
```

- **ELC-DL-1** Protocol handler validates the URL structure before acting.
- **ELC-DL-2** Deep links don't trust embedded data (e.g., `myapp://auth?token=...` — verify the token, don't blindly accept).
- **ELC-DL-3** On macOS, the `open-url` event fires when the app is opened via the protocol; queue handling until app is ready.

#### Auto-updater

- **ELC-AU-1** Updates served over HTTPS only.
- **ELC-AU-2** Updates signed; signature verified before installation (electron-updater handles this if configured).
- **ELC-AU-3** Update server URL verified — not user-configurable.
- **ELC-AU-4** Squirrel.Windows / NSIS updaters have known issues with installer hijacking on Windows; confirm using current electron-updater versions with signed installers.

#### Native dependencies

- **ELC-NAT-1** Native modules (`node-gyp`-compiled) audited and pinned. Native modules execute with full process privileges.
- **ELC-NAT-2** ASAR archive integrity considered — ASAR files are not encrypted; anyone with the binary can extract source. Don't put secrets in ASAR.

#### Electron version

- **ELC-VER-1** Electron version current. Chromium CVEs land in Electron releases roughly monthly; old Electron = exploitable browser. Check `electron --version` matches a current supported line (last 2-3 majors).

#### Process model

- **ELC-PM-1** Main process doesn't run user-supplied JavaScript via `vm` or `Function`.
- **ELC-PM-2** Renderer-to-renderer IPC (between BrowserWindows) goes through main; no shared globals.

### Phase 4: Triage

Critical: `nodeIntegration: true`; missing context isolation; IPC handler executing shell with renderer-controlled args; webview with permissive config.

### Phase 5: Report

Use `../_shared/findings-schema.md`. Prefix IDs with `ELC-`.
