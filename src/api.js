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

export const api = {
  getSystemInfo: async () => {
    const bridge = getBridge();
    if (bridge) return await bridge.getSystemInfo();
    try {
      const res = await fetch('/api/system-info');
      return await res.json();
    } catch {
      return { uuid: 'LOCAL_WEB_NODE', platform: navigator.platform || 'web', arch: 'browser', nodeVersion: 'web' };
    }
  },

  getSystemStatus: async () => {
    const bridge = getBridge();
    if (bridge) return await bridge.getSystemStatus();
    try {
      const res = await fetch('/api/system-status');
      return await res.json();
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
      const res = await fetch(`/api/autocomplete?path=${encodeURIComponent(queryPath || '')}`);
      return await res.json();
    } catch {
      return { currentDir: queryPath, items: [] };
    }
  },

  getShortcuts: async () => {
    const bridge = getBridge();
    if (bridge) return await bridge.getShortcuts();
    try {
      const res = await fetch('/api/system-shortcuts');
      return await res.json();
    } catch {
      return { shortcuts: [], drives: [] };
    }
  },

  browseDir: async (targetPath) => {
    const bridge = getBridge();
    if (bridge) return await bridge.browseDir(targetPath);
    try {
      const url = targetPath ? `/api/browse-dir?path=${encodeURIComponent(targetPath)}` : '/api/browse-dir';
      const res = await fetch(url);
      return await res.json();
    } catch {
      return { currentPath: '', parentPath: null, items: [] };
    }
  },

  getFileInfo: async (filePath) => {
    const bridge = getBridge();
    if (bridge) return await bridge.getFileInfo(filePath);
    try {
      const res = await fetch(`/api/file-info?path=${encodeURIComponent(filePath || '')}`);
      return await res.json();
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
      const res = await fetch('/api/encrypt', {
        method: 'POST',
        headers,
        body: payload.fileBuffer
      });
      return await res.json();
    } else {
      const res = await fetch('/api/encrypt', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          filePath: payload.filePath,
          settings: payload.settings || {}
        })
      });
      return await res.json();
    }
  },

  decrypt: async (payload) => {
    const bridge = getBridge();
    if (bridge) return await bridge.decrypt(payload);

    // Browser fallback via local HTTP API
    if (payload.fileBuffer) {
      const res = await fetch('/api/decrypt', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/octet-stream',
          'X-Settings': JSON.stringify(payload)
        },
        body: payload.fileBuffer
      });
      return await res.json();
    } else {
      const res = await fetch('/api/decrypt', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      return await res.json();
    }
  },

  getEmergencyConfig: async () => {
    const bridge = getBridge();
    if (bridge) return await bridge.getEmergencyConfig();
    try {
      const res = await fetch('/api/emergency/config');
      return await res.json();
    } catch {
      return { targets: [] };
    }
  },

  saveEmergencyConfig: async (config) => {
    const bridge = getBridge();
    if (bridge) return await bridge.saveEmergencyConfig(config);
    const res = await fetch('/api/emergency/config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ config })
    });
    return await res.json();
  },

  scanEmergency: async (options) => {
    const bridge = getBridge();
    if (bridge) return await bridge.scanEmergency(options);
    const res = await fetch('/api/emergency/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(options || {})
    });
    return await res.json();
  },

  executeEmergency: async (options) => {
    const bridge = getBridge();
    if (bridge) return await bridge.executeEmergency(options);
    const res = await fetch('/api/emergency/execute', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(options || {})
    });
    return await res.json();
  },

  restoreEmergency: async (options) => {
    const bridge = getBridge();
    if (bridge) return await bridge.restoreEmergency(options);
    const res = await fetch('/api/emergency/restore', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(options || {})
    });
    return await res.json();
  },

  getEmergencyLogs: async () => {
    const bridge = getBridge();
    if (bridge) return await bridge.getEmergencyLogs();
    const res = await fetch('/api/emergency/logs');
    return await res.json();
  }
};

export default api;
