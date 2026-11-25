/**
 * Wiretap — Electron preload script.
 *
 * EN: Minimal bridge between the sandboxed renderer and the main process.
 *     `contextIsolation` is enabled, so this is the ONLY surface the web
 *     page can see — keep it that way.
 *     `getToken` / `getPort` let the renderer reach the backend API without
 *     the token ever appearing in the page, the DOM, or logs. `getVersion`
 *     resolves via app.getVersion() in the main process — the old
 *     npm_package_version read returned "1.0.0" forever in production.
 * FR: Pont minimal entre le renderer en sandbox et le processus principal.
 *     `contextIsolation` est activé : c'est la SEULE surface visible par la
 *     page web — gardons-la ainsi.
 *     `getToken` / `getPort` permettent au renderer de joindre l'API backend
 *     sans que le jeton apparaisse jamais dans la page, le DOM ou les logs.
 *     `getVersion` se résout via app.getVersion() dans le processus
 *     principal — l'ancienne lecture de npm_package_version renvoyait « 1.0.0 »
 *     pour toujours en production.
 */

const { contextBridge, ipcRenderer } = require('electron')

contextBridge.exposeInMainWorld('wiretap', {
  // EN: Async — resolves to the per-launch API token held by the main process.
  // FR: Asynchrone — résout vers le jeton API par lancement détenu par le processus principal.
  getToken:   () => ipcRenderer.invoke('wiretap:get-token'),
  // EN: Async — resolves to the free port the backend was spawned on.
  // FR: Asynchrone — résout vers le port libre sur lequel le backend a été lancé.
  getPort:    () => ipcRenderer.invoke('wiretap:get-port'),
  // EN: Async — real app version (package.json via app.getVersion()).
  // FR: Asynchrone — vraie version de l'app (package.json via app.getVersion()).
  getVersion: () => ipcRenderer.invoke('wiretap:get-version'),
  // EN: Async — asks the main process to open the log directory in the OS
  //     file manager (shell.openPath — cross-platform, no shelling out).
  // FR: Asynchrone — demande au processus principal d'ouvrir le dossier des
  //     logs dans le gestionnaire de fichiers (shell.openPath — multi-OS).
  openLogs:   () => ipcRenderer.invoke('wiretap:open-logs'),
  // EN: Launch-at-login getters/setters (Windows/macOS; Linux always false).
  // FR: Lecture/écriture du lancement au démarrage (Windows/macOS ; toujours
  //     false sous Linux).
  getAutoLaunch: () => ipcRenderer.invoke('wiretap:get-auto-launch'),
  setAutoLaunch: (enabled) => ipcRenderer.invoke('wiretap:set-auto-launch', enabled),
  // EN: Auto-update bridge — status push channel plus the four controls the
  //     Settings panel needs. `onUpdateStatus` returns an unsubscribe fn.
  // FR: Pont de mise à jour — canal de statut poussé + les quatre contrôles
  //     du panneau Réglages. `onUpdateStatus` renvoie une fonction de
  //     désabonnement.
  getUpdateStatus:  () => ipcRenderer.invoke('wiretap:get-update-status'),
  getUpdateCheck:   () => ipcRenderer.invoke('wiretap:get-update-check'),
  setUpdateCheck:   (on) => ipcRenderer.invoke('wiretap:set-update-check', on),
  checkUpdates:     () => ipcRenderer.invoke('wiretap:check-updates'),
  installUpdate:    () => ipcRenderer.invoke('wiretap:install-update'),
  onUpdateStatus:   (cb) => {
    const handler = (_e, s) => cb(s)
    ipcRenderer.on('wiretap:update-status', handler)
    return () => ipcRenderer.removeListener('wiretap:update-status', handler)
  },
})
