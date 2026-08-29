/**
 * Unified Client API for Project Mirage
 * Communicates natively with Electron's Main Process via secure IPC (mirageAPI).
 * Zero HTTP network sockets, 100% offline.
 */

const getBridge = () => {
  if (typeof window !== 'undefined' && window.mirageAPI) {
    return window.mirageAPI;
  }
  return null;
};

export const api = {
  getSystemInfo: async () => {
    const bridge = getBridge();
    if (bridge) return await bridge.getSystemInfo();
    return { uuid: 'OFFLINE_IPC', platform: 'desktop', arch: 'arm64', nodeVersion: 'v20' };
  },

  getSystemStatus: async () => {
    const bridge = getBridge();
    if (bridge) return await bridge.getSystemStatus();
    return {
      status: 'online',
      uptime: 0,
      memory: { rss: 0, heapUsed: 0 },
      version: '1.0.0',
      upToDate: true,
      selfTests: { overall: true, results: [] }
    };
  },

  autocomplete: async (queryPath) => {
    const bridge = getBridge();
    if (bridge) return await bridge.autocomplete(queryPath);
    return { currentDir: queryPath, items: [] };
  },

  getShortcuts: async () => {
    const bridge = getBridge();
    if (bridge) return await bridge.getShortcuts();
    return { shortcuts: [], drives: [] };
  },

  browseDir: async (targetPath) => {
    const bridge = getBridge();
    if (bridge) return await bridge.browseDir(targetPath);
    return { currentPath: '', parentPath: null, items: [] };
  },

  getFileInfo: async (filePath) => {
    const bridge = getBridge();
    if (bridge) return await bridge.getFileInfo(filePath);
    return { exists: false };
  },

  encrypt: async (payload) => {
    const bridge = getBridge();
    if (!bridge) throw new Error('Electron IPC Bridge not available.');
    return await bridge.encrypt(payload);
  },

  decrypt: async (payload) => {
    const bridge = getBridge();
    if (!bridge) throw new Error('Electron IPC Bridge not available.');
    return await bridge.decrypt(payload);
  },

  getEmergencyConfig: async () => {
    const bridge = getBridge();
    if (bridge) return await bridge.getEmergencyConfig();
    return { targets: [] };
  },

  saveEmergencyConfig: async (config) => {
    const bridge = getBridge();
    if (bridge) return await bridge.saveEmergencyConfig(config);
    return { success: true };
  },

  scanEmergency: async (options) => {
    const bridge = getBridge();
    if (bridge) return await bridge.scanEmergency(options);
    return { success: true, files: [], totalFiles: 0, totalSize: 0 };
  },

  executeEmergency: async (options) => {
    const bridge = getBridge();
    if (!bridge) throw new Error('Electron IPC Bridge not available.');
    return await bridge.executeEmergency(options);
  },

  restoreEmergency: async (options) => {
    const bridge = getBridge();
    if (!bridge) throw new Error('Electron IPC Bridge not available.');
    return await bridge.restoreEmergency(options);
  },

  getEmergencyLogs: async () => {
    const bridge = getBridge();
    if (bridge) return await bridge.getEmergencyLogs();
    return { success: true, logs: [] };
  }
};

export default api;
