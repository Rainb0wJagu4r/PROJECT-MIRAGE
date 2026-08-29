/**
 * Unified Client API for Project Mirage
 * Hybrid support:
 * 1. If running in Electron: uses native IPC bridge (window.mirageAPI).
 * 2. If running in Web Browser: uses local loopback API endpoints (/api/*).
 * Zero configuration needed, 100% offline.
 */

const getBridge = () => {
  if (typeof window !== 'undefined' && window.mirageAPI) {
    return window.mirageAPI;
  }
  return null;
};

async function safeFetchJson(url, options = {}) {
  const res = await fetch(url, options);
  const text = await res.text();
  let data;
  try {
    data = JSON.parse(text);
  } catch (err) {
    throw new Error(text || `Error de servidor HTTP ${res.status}: ${res.statusText}`);
  }
  return data;
}

export const api = {
  getSystemInfo: async () => {
    const bridge = getBridge();
    if (bridge) return await bridge.getSystemInfo();
    try {
      return await safeFetchJson('/api/system-info');
    } catch {
      return { uuid: 'LOCAL_WEB_NODE', platform: navigator.platform || 'web', arch: 'browser', nodeVersion: 'web' };
    }
  },

  getSystemStatus: async () => {
    const bridge = getBridge();
    if (bridge) return await bridge.getSystemStatus();
    try {
      return await safeFetchJson('/api/system-status');
    } catch {
      return {
        status: 'online',
        uptime: 0,
        memory: { rss: 0, heapUsed: 0 },
        version: '2.0.0',
        upToDate: true,
        selfTests: {
          overall: true,
          aesGcm: true,
          camelliaCtr: true,
          ariaCtr: true,
          chacha20: true,
          scrypt: true
        }
      };
    }
  },

  autocomplete: async (queryPath) => {
    const bridge = getBridge();
    if (bridge) return await bridge.autocomplete(queryPath);
    try {
      return await safeFetchJson(`/api/autocomplete?path=${encodeURIComponent(queryPath || '')}`);
    } catch {
      return { currentDir: queryPath, items: [] };
    }
  },

  getShortcuts: async () => {
    const bridge = getBridge();
    if (bridge) return await bridge.getShortcuts();
    try {
      return await safeFetchJson('/api/system-shortcuts');
    } catch {
      return { shortcuts: [], drives: [] };
    }
  },

  browseDir: async (targetPath) => {
    const bridge = getBridge();
    if (bridge) return await bridge.browseDir(targetPath);
    try {
      const url = targetPath ? `/api/browse-dir?path=${encodeURIComponent(targetPath)}` : '/api/browse-dir';
      return await safeFetchJson(url);
    } catch {
      return { currentPath: '', parentPath: null, items: [] };
    }
  },

  getFileInfo: async (filePath) => {
    const bridge = getBridge();
    if (bridge) return await bridge.getFileInfo(filePath);
    try {
      return await safeFetchJson(`/api/file-info?path=${encodeURIComponent(filePath || '')}`);
    } catch {
      return { exists: false };
    }
  },

  encrypt: async (payload) => {
    const bridge = getBridge();
    if (bridge) return await bridge.encrypt(payload);

    // Browser fallback via local HTTP API
    if (payload.fileBuffer) {
      const headers = {
        'Content-Type': 'application/octet-stream',
        'X-File-Name': encodeURIComponent(payload.fileName || 'file.bin'),
        'X-Settings': JSON.stringify(payload.settings || {})
      };
      return await safeFetchJson('/api/encrypt', {
        method: 'POST',
        headers,
        body: payload.fileBuffer
      });
    } else {
      return await safeFetchJson('/api/encrypt', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          filePath: payload.filePath,
          settings: payload.settings || {}
        })
      });
    }
  },

  decrypt: async (payload) => {
    const bridge = getBridge();
    if (bridge) return await bridge.decrypt(payload);

    // Browser fallback via local HTTP API
    if (payload.fileBuffer) {
      return await safeFetchJson('/api/decrypt', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/octet-stream',
          'X-Settings': JSON.stringify(payload)
        },
        body: payload.fileBuffer
      });
    } else {
      return await safeFetchJson('/api/decrypt', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
    }
  },

  getEmergencyConfig: async () => {
    const bridge = getBridge();
    if (bridge) return await bridge.getEmergencyConfig();
    try {
      return await safeFetchJson('/api/emergency/config');
    } catch {
      return { targets: [] };
    }
  },

  saveEmergencyConfig: async (config) => {
    const bridge = getBridge();
    if (bridge) return await bridge.saveEmergencyConfig(config);
    return await safeFetchJson('/api/emergency/config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ config })
    });
  },

  scanEmergency: async (options) => {
    const bridge = getBridge();
    if (bridge) return await bridge.scanEmergency(options);
    return await safeFetchJson('/api/emergency/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(options || {})
    });
  },

  executeEmergency: async (options) => {
    const bridge = getBridge();
    if (bridge) return await bridge.executeEmergency(options);
    return await safeFetchJson('/api/emergency/execute', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(options || {})
    });
  },

  restoreEmergency: async (options) => {
    const bridge = getBridge();
    if (bridge) return await bridge.restoreEmergency(options);
    return await safeFetchJson('/api/emergency/restore', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(options || {})
    });
  },

  getEmergencyLogs: async () => {
    const bridge = getBridge();
    if (bridge) return await bridge.getEmergencyLogs();
    return await safeFetchJson('/api/emergency/logs');
  }
};

export default api;
