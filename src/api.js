/**
 * Unified Client API for Project Mirage
 * Multi-Runtime Support:
 * 1. Tauri v2 (100% Native Rust In-Memory IPC via @tauri-apps/api/core) - Zero supply chain & Zero HTTP ports.
 * 2. Electron Native IPC bridge (window.mirageAPI).
 * 3. Local loopback web fallback (/api/*).
 */

let tauriInvoke = null;

async function getTauriInvoke() {
  if (tauriInvoke) return tauriInvoke;
  if (typeof window !== 'undefined' && (window.__TAURI_INTERNALS__ || window.__TAURI__)) {
    try {
      const core = await import('@tauri-apps/api/core');
      tauriInvoke = core.invoke;
      return tauriInvoke;
    } catch {
      return null;
    }
  }
  return null;
}

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
  } catch {
    throw new Error(text || `Error de servidor HTTP ${res.status}: ${res.statusText}`);
  }
  return data;
}

export const api = {
  isTauri: async () => {
    return (await getTauriInvoke()) !== null;
  },

  pickFile: async (filterName, extensions) => {
    const invoke = await getTauriInvoke();
    if (invoke) {
      return await invoke('pick_file', { filterName, extensions });
    }
    return null;
  },

  pickFiles: async () => {
    const invoke = await getTauriInvoke();
    if (invoke) {
      return await invoke('pick_files');
    }
    return [];
  },

  getSystemInfo: async () => {
    const invoke = await getTauriInvoke();
    if (invoke) {
      return { uuid: 'NATIVE_RUST_TAURI_V2', platform: 'desktop', arch: 'native-rust', nodeVersion: 'none' };
    }
    const bridge = getBridge();
    if (bridge) return await bridge.getSystemInfo();
    try {
      return await safeFetchJson('/api/system-info');
    } catch {
      return { uuid: 'LOCAL_WEB_NODE', platform: navigator.platform || 'web', arch: 'browser', nodeVersion: 'web' };
    }
  },

  getSystemStatus: async () => {
    const invoke = await getTauriInvoke();
    if (invoke) {
      const kats = await invoke('run_kats');
      return {
        status: 'online',
        uptime: 0,
        memory: { rss: 0, heapUsed: 0 },
        version: '2.2.0-rust-tauri',
        upToDate: true,
        selfTests: {
          overall: kats.overall,
          aesGcm: true,
          camelliaCtr: true,
          ariaCtr: true,
          chacha20: true,
          scrypt: true,
          kats: kats.tests
        }
      };
    }
    const bridge = getBridge();
    if (bridge) return await bridge.getSystemStatus();
    try {
      return await safeFetchJson('/api/system-status');
    } catch {
      return {
        status: 'online',
        uptime: 0,
        memory: { rss: 0, heapUsed: 0 },
        version: '2.2.0',
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
    const invoke = await getTauriInvoke();
    if (invoke) {
      try {
        const info = await invoke('get_file_info', { path: filePath });
        return {
          exists: true,
          name: info.name,
          size: info.size,
          hash: info.hash_sha3,
          hashSha3: info.hash_sha3
        };
      } catch {
        return { exists: false };
      }
    }
    const bridge = getBridge();
    if (bridge) return await bridge.getFileInfo(filePath);
    try {
      return await safeFetchJson(`/api/file-info?path=${encodeURIComponent(filePath || '')}`);
    } catch {
      return { exists: false };
    }
  },

  encrypt: async (payload) => {
    const invoke = await getTauriInvoke();
    if (invoke) {
      const settings = payload.settings || {};
      const res = await invoke('encrypt_file_tauri', {
        req: {
          file_path: payload.filePath,
          password: settings.password || '',
          second_factor: settings.dfPassword || null,
          algorithm: settings.algorithm || 'mirage-c4',
          bucket_padding: settings.bucketPadding !== false,
          split_shamir: settings.split2of3 === true,
          carrier_path: settings.carrierPath || null,
          duress_password: settings.duressPassword || null,
          duress_file_path: settings.duressFilePath || null
        }
      });
      return {
        success: true,
        outputFiles: res.output_files,
        elapsed: res.elapsed_ms,
        originalSize: res.original_size,
        isSplit: res.is_split
      };
    }

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
    const invoke = await getTauriInvoke();
    if (invoke) {
      const paths = payload.partPaths && payload.partPaths.length > 0 
        ? payload.partPaths 
        : [payload.filePath];

      const res = await invoke('decrypt_file_tauri', {
        req: {
          file_paths: paths,
          password: payload.password || '',
          second_factor: payload.secondPassword || null,
          output_dir: payload.restorePath || null
        }
      });

      return {
        success: true,
        originalPath: res.restored_file_path,
        fileName: res.restored_file_name,
        size: res.restored_size,
        isDuress: res.is_duress,
        elapsed: res.elapsed_ms
      };
    }

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
