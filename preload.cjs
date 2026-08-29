const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('mirageAPI', {
  getSystemInfo: () => ipcRenderer.invoke('mirage:system-info'),
  getSystemStatus: () => ipcRenderer.invoke('mirage:system-status'),
  autocomplete: (queryPath) => ipcRenderer.invoke('mirage:autocomplete', queryPath),
  getShortcuts: () => ipcRenderer.invoke('mirage:system-shortcuts'),
  browseDir: (targetPath) => ipcRenderer.invoke('mirage:browse-dir', targetPath),
  getFileInfo: (filePath) => ipcRenderer.invoke('mirage:file-info', filePath),
  encrypt: (payload) => ipcRenderer.invoke('mirage:encrypt', payload),
  decrypt: (payload) => ipcRenderer.invoke('mirage:decrypt', payload),
  getEmergencyConfig: () => ipcRenderer.invoke('mirage:emergency-config'),
  saveEmergencyConfig: (config) => ipcRenderer.invoke('mirage:emergency-config-save', config),
  scanEmergency: (options) => ipcRenderer.invoke('mirage:emergency-scan', options),
  executeEmergency: (options) => ipcRenderer.invoke('mirage:emergency-execute', options),
  restoreEmergency: (options) => ipcRenderer.invoke('mirage:emergency-restore', options),
  getEmergencyLogs: () => ipcRenderer.invoke('mirage:emergency-logs')
});
