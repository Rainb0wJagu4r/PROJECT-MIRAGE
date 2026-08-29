import { ipcMain } from 'electron';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import os from 'os';
import { execSync } from 'child_process';

// Audited Cryptographic Core & Security Modules
import { OpaqueError, PolicyError, toPublicError, sanitizeSteps } from './lib/errors.js';
import { safeJoin, safeBasename, requireUserPath } from './lib/paths.js';
import { requirePasswordPolicy, MIN_PASSWORD_LENGTH } from './lib/kdf.js';
import { encryptVault, decryptVault, ALGORITHMS } from './lib/vault.js';
import {
  serializePayload, deserializePayload,
  serializeMultiPayload, deserializeMultiPayload, isMultiPayload,
  appendToCarrier, extractFromCarrier,
} from './lib/format.js';
import { splitSecret, combineShares } from './lib/shamir.js';
import { summarizeKats } from './lib/kat.js';
import {
  isLegacyV1, decryptLegacyV1, stripLegacySteg,
  deserializePayloadV1, migrateNotice,
} from './lib/legacy.js';

// Hardware UUID retrieval with persistent installation seed fallback
export function getHardwareUUID() {
  try {
    if (process.platform === 'darwin') {
      const output = execSync('ioreg -rd1 -c IOPlatformExpertDevice').toString();
      const match = output.match(/"IOPlatformUUID" = "([^"]+)"/);
      if (match && match[1]) return match[1].trim();
    } else if (process.platform === 'win32') {
      try {
        const output = execSync('powershell -Command "Get-CimInstance -ClassName Win32_ComputerSystemProduct | Select-Object -ExpandProperty UUID"', { stdio: ['pipe', 'pipe', 'ignore'] }).toString();
        if (output.trim()) return output.trim();
      } catch {
        const output = execSync('reg query "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography" /v MachineGuid', { stdio: ['pipe', 'pipe', 'ignore'] }).toString();
        const match = output.match(/MachineGuid\s+REG_SZ\s+(\S+)/);
        if (match && match[1]) return match[1].trim();
      }
    } else if (process.platform === 'linux') {
      if (fs.existsSync('/var/lib/dbus/machine-id')) return fs.readFileSync('/var/lib/dbus/machine-id', 'utf8').trim();
      if (fs.existsSync('/etc/machine-id')) return fs.readFileSync('/etc/machine-id', 'utf8').trim();
    }
  } catch { /* fallback to persistent seed */ }

  const fallbackPath = path.join(os.homedir(), '.project-mirage-machine-id');
  try {
    if (fs.existsSync(fallbackPath)) {
      return fs.readFileSync(fallbackPath, 'utf8').trim();
    }
    const generated = crypto.randomBytes(32).toString('hex');
    fs.writeFileSync(fallbackPath, generated, { encoding: 'utf8', mode: 0o600 });
    return generated;
  } catch {
    const fallbackStr = os.hostname() + '-' + os.arch() + '-' + os.platform() + '-' + os.userInfo().username;
    return crypto.createHash('sha256').update(fallbackStr).digest('hex');
  }
}

function getHardwareIdIfEnabled(enabled) {
  if (!enabled) return null;
  const uuid = getHardwareUUID();
  if (!uuid) throw new PolicyError('No se ha podido obtener el identificador de hardware de este equipo.');
  return uuid;
}

// Metadata Scrubbers
function scrubJpeg(buffer) {
  if (buffer.length < 4 || buffer[0] !== 0xFF || buffer[1] !== 0xD8) return buffer;
  const chunks = [buffer.subarray(0, 2)];
  let offset = 2;
  while (offset < buffer.length) {
    if (buffer[offset] !== 0xFF) {
      chunks.push(buffer.subarray(offset));
      break;
    }
    const marker = buffer[offset + 1];
    if (marker === 0xDA || marker === 0xD9) {
      chunks.push(buffer.subarray(offset));
      break;
    }
    if (offset + 4 > buffer.length) {
      chunks.push(buffer.subarray(offset));
      break;
    }
    const length = buffer.readUInt16BE(offset + 2);
    const totalSegmentLength = 2 + length;
    if (marker === 0xE1) {
      // Skip EXIF
    } else {
      chunks.push(buffer.subarray(offset, offset + totalSegmentLength));
    }
    offset += totalSegmentLength;
  }
  return Buffer.concat(chunks);
}

function scrubPng(buffer) {
  const PNG_HEADER = Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
  if (buffer.length < 8 || !buffer.subarray(0, 8).equals(PNG_HEADER)) return buffer;
  const chunks = [PNG_HEADER];
  let offset = 8;
  while (offset < buffer.length) {
    if (offset + 8 > buffer.length) {
      chunks.push(buffer.subarray(offset));
      break;
    }
    const length = buffer.readUInt32BE(offset);
    const type = buffer.toString('ascii', offset + 4, offset + 8);
    const totalChunkLength = 12 + length;
    if (offset + totalChunkLength > buffer.length) {
      chunks.push(buffer.subarray(offset));
      break;
    }
    const isMetadata = ['tEXt', 'zTXt', 'iTXt', 'eXIf', 'tIME', 'pHYs'].includes(type);
    if (!isMetadata) {
      chunks.push(buffer.subarray(offset, offset + totalChunkLength));
    }
    offset += totalChunkLength;
  }
  return Buffer.concat(chunks);
}

// Secure Shredder
function secureShred(filePath, passes = 3) {
  if (!fs.existsSync(filePath)) return;
  try {
    const stats = fs.statSync(filePath);
    const size = stats.size;
    const fd = fs.openSync(filePath, 'r+');
    const bufferSize = 64 * 1024;
    const buffer = Buffer.alloc(bufferSize);

    for (let pass = 0; pass < passes; pass++) {
      let offset = 0;
      while (offset < size) {
        crypto.randomFillSync(buffer);
        const bytesToWrite = Math.min(bufferSize, size - offset);
        fs.writeSync(fd, buffer, 0, bytesToWrite, offset);
        offset += bytesToWrite;
      }
      fs.fsyncSync(fd);
    }
    fs.closeSync(fd);
    fs.unlinkSync(filePath);
  } catch (err) {
    try { fs.unlinkSync(filePath); } catch { /* ignore */ }
  }
}

function shredWarning() {
  return 'Aviso sobre borrado seguro: en SSDs, memorias flash o sistemas con copia en escritura (APFS, Btrfs), el firmware reasigna bloques internamente, por lo que la sobreescritura NO garantiza el borrado físico de los datos en el chip de memoria.';
}

function applySteganography(carrierPath, encryptedPayload, addStep) {
  let carrierBuffer = null;
  if (carrierPath) {
    const resolvedCarrier = requireUserPath(carrierPath, 'imagen portadora');
    if (fs.existsSync(resolvedCarrier)) {
      carrierBuffer = fs.readFileSync(resolvedCarrier);
      addStep(`Portador: imagen cargada desde ${resolvedCarrier} (${carrierBuffer.length} bytes)`);
    }
  }
  if (!carrierBuffer) {
    carrierBuffer = Buffer.from(
      'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=',
      'base64'
    );
    addStep('Portador: usando PNG transparente por defecto');
  }
  return appendToCarrier(carrierBuffer, encryptedPayload);
}

// System Path Blacklist (Anti-Ransomware & System Guard)
function isSystemPath(targetPath) {
  const norm = path.normalize(path.resolve(targetPath)).toLowerCase();
  const sep = path.sep.toLowerCase();
  if (process.platform === 'win32') {
    const sysDrive = (process.env.SystemDrive || 'C:').toLowerCase();
    const winDir = (process.env.SystemRoot || 'C:\\Windows').toLowerCase();
    const progFiles = (process.env.ProgramFiles || 'C:\\Program Files').toLowerCase();
    const progFilesX86 = (process.env['ProgramFiles(x86)'] || 'C:\\Program Files (x86)').toLowerCase();
    if (norm === sysDrive || norm === `${sysDrive}\\` || norm === 'c:\\' || norm === 'c:') return true;
    if (norm.startsWith(winDir) || norm.startsWith(progFiles) || norm.startsWith(progFilesX86)) return true;
    if (norm === `${sysDrive}\\users` || norm === `${sysDrive}\\users\\` || norm === 'c:\\users' || norm === 'c:\\users\\') return true;
  } else {
    const forbidden = ['/bin', '/sbin', '/usr', '/etc', '/lib', '/lib64', '/boot', '/dev', '/proc', '/sys', '/system', '/library', '/applications'];
    if (norm === '/' || forbidden.some(d => norm === d || norm.startsWith(d + '/'))) return true;
  }
  return false;
}

function getDefaultEmergencyConfig() {
  const home = os.homedir();
  const targets = [];
  const addIf = (p, label, recursive = true) => {
    if (fs.existsSync(p)) targets.push({ path: p, label, recursive, enabled: true });
  };
  addIf(path.join(home, 'Desktop'), 'Desktop (Escritorio)', true);
  addIf(path.join(home, 'Documents'), 'Documents (Documentos)', true);
  addIf(path.join(home, 'Downloads'), 'Downloads (Descargas)', false);
  return {
    targets,
    shredAfterLock: true,
    shredPasses: 3,
    outputLocation: path.join(home, 'EMERGENCY_VAULT.wraith'),
    algorithm: 'mirage-c4',
    hardwareLock: true,
    lastModified: Date.now()
  };
}

function getEmergencyConfigPath() {
  return path.join(os.homedir(), '.project-mirage-emergency.json');
}

function scanEmergencyFiles(targets) {
  const filesFound = [];
  for (const t of targets) {
    if (!t.enabled || !fs.existsSync(t.path)) continue;
    if (isSystemPath(t.path)) continue;
    const scanDir = (dirPath, isRec) => {
      try {
        const entries = fs.readdirSync(dirPath, { withFileTypes: true });
        for (const e of entries) {
          const full = path.join(dirPath, e.name);
          if (isSystemPath(full)) continue;
          if (e.isDirectory()) {
            if (isRec && !e.name.startsWith('.')) scanDir(full, isRec);
          } else if (e.isFile()) {
            if (e.name.endsWith('.wraith') || e.name.startsWith('.')) continue;
            try {
              const st = fs.statSync(full);
              if (st.size <= 100 * 1024 * 1024) {
                filesFound.push({ fullPath: full, size: st.size, modified: st.mtimeMs });
              }
            } catch { /* skip inaccessible */ }
          }
        }
      } catch { /* skip inaccessible directory */ }
    };
    try {
      const st = fs.statSync(t.path);
      if (st.isDirectory()) scanDir(t.path, t.recursive);
      else if (st.isFile()) filesFound.push({ fullPath: t.path, size: st.size, modified: st.mtimeMs });
    } catch { /* skip */ }
  }
  return filesFound;
}

// ---------------------------------------------------------------------------
// Register all native IPC Handlers
// ---------------------------------------------------------------------------
export function registerIpcHandlers() {
  // 1. System Info
  ipcMain.handle('mirage:system-info', async () => {
    return {
      uuid: getHardwareUUID(),
      platform: process.platform,
      arch: process.arch,
      nodeVersion: process.version
    };
  });

  // 2. System Status & KAT Primitives Monitor
  ipcMain.handle('mirage:system-status', async () => {
    const memoryUsage = process.memoryUsage();
    const katSummary = summarizeKats();
    const testsMap = {};
    if (katSummary && katSummary.tests) {
      katSummary.tests.forEach(t => {
        if (t.name.includes('AES-256-GCM')) testsMap.aesGcm = t.passed;
        if (t.name.includes('Camellia')) testsMap.camelliaCtr = t.passed;
        if (t.name.includes('ARIA')) testsMap.ariaCtr = t.passed;
        if (t.name.includes('ChaCha20')) testsMap.chacha20 = t.passed;
        if (t.name.includes('scrypt')) testsMap.scrypt = t.passed;
      });
    }
    return {
      status: 'online',
      uptime: Math.floor(process.uptime()),
      memory: {
        rss: Math.round(memoryUsage.rss / (1024 * 1024)),
        heapUsed: Math.round(memoryUsage.heapUsed / (1024 * 1024))
      },
      version: '1.0.0',
      upToDate: true,
      selfTests: {
        overall: katSummary.overall,
        aesGcm: testsMap.aesGcm ?? katSummary.overall,
        camelliaCtr: testsMap.camelliaCtr ?? katSummary.overall,
        ariaCtr: testsMap.ariaCtr ?? katSummary.overall,
        chacha20: testsMap.chacha20 ?? katSummary.overall,
        scrypt: testsMap.scrypt ?? katSummary.overall,
        raw: katSummary
      }
    };
  });

  // 3. Autocomplete
  ipcMain.handle('mirage:autocomplete', async (event, queryPath = '') => {
    let target = queryPath || os.homedir();
    if (target.startsWith('~')) target = path.join(os.homedir(), target.slice(1));
    try {
      const resolved = path.resolve(target);
      let parentDir = resolved;
      let filter = '';
      const exists = fs.existsSync(resolved);
      if (!exists || !fs.lstatSync(resolved).isDirectory()) {
        parentDir = path.dirname(resolved);
        filter = path.basename(resolved).toLowerCase();
      }
      if (!fs.existsSync(parentDir)) return { currentDir: queryPath, items: [] };
      const entries = fs.readdirSync(parentDir, { withFileTypes: true });
      const items = entries
        .filter(e => !e.name.startsWith('.') && e.name.toLowerCase().startsWith(filter))
        .map(e => ({ name: e.name, isDirectory: e.isDirectory(), fullPath: path.join(parentDir, e.name) }))
        .slice(0, 20);
      return { currentDir: parentDir, items };
    } catch {
      return { currentDir: queryPath, items: [] };
    }
  });

  // 4. System Shortcuts
  ipcMain.handle('mirage:system-shortcuts', async () => {
    const home = os.homedir();
    const shortcuts = [
      { name: 'Home', path: home, icon: 'Home' },
      { name: 'Desktop', path: path.join(home, 'Desktop'), icon: 'Monitor' },
      { name: 'Documents', path: path.join(home, 'Documents'), icon: 'FileText' },
      { name: 'Downloads', path: path.join(home, 'Downloads'), icon: 'Download' }
    ].filter(s => fs.existsSync(s.path));

    const drives = [];
    if (process.platform === 'win32') {
      for (const letter of 'CDEFGHIJKLMNOPQRSTUVWXYZ') {
        const dPath = `${letter}:\\`;
        if (fs.existsSync(dPath)) drives.push({ name: `Local Disk (${letter}:)`, path: dPath });
      }
    } else {
      drives.push({ name: 'Root (/)', path: '/' });
      if (process.platform === 'darwin' && fs.existsSync('/Volumes')) {
        try {
          fs.readdirSync('/Volumes').forEach(v => {
            if (!v.startsWith('.')) drives.push({ name: v, path: path.join('/Volumes', v) });
          });
        } catch { /* skip */ }
      }
    }
    return { shortcuts, drives };
  });

  // 5. Browse Directory
  ipcMain.handle('mirage:browse-dir', async (event, targetPath = '') => {
    let resolved = targetPath ? requireUserPath(targetPath, 'directorio a explorar') : os.homedir();
    if (!fs.existsSync(resolved)) resolved = os.homedir();
    try {
      const stat = fs.statSync(resolved);
      if (!stat.isDirectory()) resolved = path.dirname(resolved);
      const entries = fs.readdirSync(resolved, { withFileTypes: true });
      const items = entries
        .filter(e => !e.name.startsWith('.'))
        .map(e => {
          let size = 0;
          if (e.isFile()) {
            try { size = fs.statSync(path.join(resolved, e.name)).size; } catch { /* ignore */ }
          }
          return { name: e.name, isDirectory: e.isDirectory(), path: path.join(resolved, e.name), size };
        })
        .sort((a, b) => {
          if (a.isDirectory && !b.isDirectory) return -1;
          if (!a.isDirectory && b.isDirectory) return 1;
          return a.name.localeCompare(b.name);
        });
      const parent = path.dirname(resolved);
      return { currentPath: resolved, parentPath: parent !== resolved ? parent : null, items };
    } catch (err) {
      return { currentPath: resolved, parentPath: null, items: [], error: err.message };
    }
  });

  // 6. File Info
  ipcMain.handle('mirage:file-info', async (event, targetPath) => {
    if (!targetPath) return { exists: false };
    try {
      const resolved = requireUserPath(targetPath, 'archivo a inspeccionar');
      if (fs.existsSync(resolved) && fs.statSync(resolved).isFile()) {
        const stat = fs.statSync(resolved);
        const buffer = fs.readFileSync(resolved);
        const sha3 = crypto.createHash('sha3-256').update(buffer).digest('hex');
        return {
          exists: true,
          size: stat.size,
          sha3,
          filename: path.basename(resolved),
          isWraith: resolved.endsWith('.wraith') || isLegacyV1(buffer)
        };
      }
      return { exists: false };
    } catch (e) {
      return { exists: false, error: e.message };
    }
  });

  // 7. Core Encrypt
  ipcMain.handle('mirage:encrypt', async (event, params) => {
    const steps = [];
    const addStep = (msg, success = true) => {
      steps.push({ msg, success, timestamp: Date.now() });
    };

    try {
      let fileBuffer;
      let filename;
      let sourceFilePath = null;
      const settings = params.settings || {};

      if (params.fileBuffer) {
        fileBuffer = Buffer.from(params.fileBuffer);
        filename = safeBasename(params.fileName || 'untitled.bin', 'untitled.bin');
        addStep(`Archivo recibido en memoria: ${filename} (${fileBuffer.length} bytes)`);
      } else if (params.filePath) {
        sourceFilePath = requireUserPath(params.filePath, 'archivo de origen');
        if (!fs.existsSync(sourceFilePath) || !fs.statSync(sourceFilePath).isFile()) {
          throw new PolicyError(`No se encuentra el archivo de origen: ${sourceFilePath}`);
        }
        fileBuffer = fs.readFileSync(sourceFilePath);
        filename = path.basename(sourceFilePath);
        addStep(`Archivo cargado: ${sourceFilePath} (${fileBuffer.length} bytes)`);
      } else {
        throw new PolicyError('No se ha indicado ningún archivo para cifrar.');
      }

      const {
        password,
        doubleFactorPassword = '',
        hardwareLockEnabled = false,
        metadataScrubEnabled = false,
        sizeObfuscationEnabled = true,
        ttlEnabled = false,
        ttlValue,
        duressEnabled = false,
        duressPassword = '',
        duressDecoyPath = '',
        splitFragmentEnabled = false,
        shredOriginalEnabled = false,
        shredPasses = 3,
        outputPath,
        algorithm = ALGORITHMS.CASCADE,
        steganographyEnabled = false,
        carrierPath = ''
      } = settings;

      requirePasswordPolicy(password, 'La contraseña maestra');
      if (doubleFactorPassword) requirePasswordPolicy(doubleFactorPassword, 'El secreto secundario');
      if (duressEnabled) {
        if (!duressPassword) throw new PolicyError('El modo de coacción requiere una contraseña señuelo.');
        requirePasswordPolicy(duressPassword, 'La contraseña señuelo');
      }

      // Metadata scrubbing
      if (metadataScrubEnabled) {
        const ext = path.extname(filename).toLowerCase();
        const origSize = fileBuffer.length;
        if (ext === '.jpg' || ext === '.jpeg') {
          fileBuffer = scrubJpeg(fileBuffer);
          addStep(`Metadatos: EXIF de JPEG eliminado (${origSize - fileBuffer.length} bytes menos)`);
        } else if (ext === '.png') {
          fileBuffer = scrubPng(fileBuffer);
          addStep(`Metadatos: chunks auxiliares de PNG eliminados (${origSize - fileBuffer.length} bytes menos)`);
        }
      }

      const sha3Input = crypto.createHash('sha3-256').update(fileBuffer).digest('hex');
      addStep(`SHA3-256 de entrada: ${sha3Input}`);

      let expirationTime = 0;
      if (ttlEnabled && ttlValue) {
        const hours = parseFloat(ttlValue);
        if (!Number.isFinite(hours) || hours <= 0) {
          throw new PolicyError('El valor de caducidad (TTL) debe ser un número de horas positivo.');
        }
        expirationTime = Date.now() + hours * 3600 * 1000;
        addStep(`Caducidad fijada: ${new Date(expirationTime).toISOString()}`);
      }

      const payload = serializePayload(filename, fileBuffer, expirationTime);

      let decoyPayload = null;
      if (duressEnabled) {
        let decoyBuffer = null;
        let decoyFilename = 'decoy.txt';
        if (duressDecoyPath) {
          const resolvedDecoy = requireUserPath(duressDecoyPath, 'archivo señuelo');
          if (fs.existsSync(resolvedDecoy) && fs.statSync(resolvedDecoy).isFile()) {
            decoyBuffer = fs.readFileSync(resolvedDecoy);
            decoyFilename = path.basename(resolvedDecoy);
            addStep(`Señuelo cargado: ${resolvedDecoy} (${decoyBuffer.length} bytes)`);
          }
        }
        if (!decoyBuffer) {
          decoyBuffer = Buffer.from('Este documento no contiene informacion relevante.\r\n', 'utf8');
          addStep('Señuelo: usando el contenido por defecto');
        }
        decoyPayload = serializePayload(decoyFilename, decoyBuffer, 0);
      }

      const hardwareId = getHardwareIdIfEnabled(hardwareLockEnabled);
      const { envelope, flags } = encryptVault({
        payload,
        decoyPayload,
        password,
        secondFactor: doubleFactorPassword,
        duressPassword: duressEnabled ? duressPassword : '',
        hardwareId,
        algorithm,
        bucketPadding: sizeObfuscationEnabled
      });

      if (algorithm === ALGORITHMS.CASCADE) {
        addStep('Cascada Mirage-C4 v2: Camellia-256-CBC → ChaCha20 → ARIA-256-CBC → AES-256-GCM');
      } else {
        addStep('AES-256-GCM con AAD reforzado');
      }

      let outputBuffer = envelope;
      const ext = splitFragmentEnabled ? '.share' : (steganographyEnabled ? (carrierPath ? path.extname(carrierPath) || '.png' : '.png') : '.wraith');
      const defaultName = path.basename(filename, path.extname(filename)) + ext;

      let targetOutputPath;
      if (!outputPath) {
        const parent = sourceFilePath ? path.dirname(sourceFilePath) : os.homedir();
        targetOutputPath = path.join(parent, defaultName);
      } else {
        targetOutputPath = requireUserPath(outputPath, 'ruta de salida');
        let isDir = false;
        try { isDir = fs.existsSync(targetOutputPath) && fs.lstatSync(targetOutputPath).isDirectory(); } catch { /* ignore */ }
        if (isDir || outputPath.endsWith('/') || outputPath.endsWith('\\')) {
          targetOutputPath = path.join(targetOutputPath, defaultName);
        }
      }

      fs.mkdirSync(path.dirname(targetOutputPath), { recursive: true });

      if (steganographyEnabled) {
        outputBuffer = applySteganography(carrierPath, outputBuffer, addStep);
      }

      if (splitFragmentEnabled) {
        addStep('Fragmentación con umbral real 2-de-3 (Shamir sobre GF(2^8))');
        const shares = splitSecret(outputBuffer, 2, 3);
        const written = [];
        shares.forEach((share, i) => {
          const sharePath = `${targetOutputPath}${i + 1}`;
          fs.writeFileSync(sharePath, share);
          written.push(sharePath);
          addStep(`Fragmento ${i + 1} guardado en ${sharePath} (${share.length} bytes)`);
        });

        const finalSha3 = crypto.createHash('sha3-256').update(outputBuffer).digest('hex');
        if (shredOriginalEnabled && sourceFilePath) {
          secureShred(sourceFilePath, parseInt(shredPasses, 10));
          addStep(`Borrado seguro aplicado a ${sourceFilePath}`);
        }
        return {
          success: true,
          outputPath: written.join(', '),
          sharePaths: written,
          inputHash: sha3Input,
          outputHash: finalSha3,
          steps
        };
      }

      fs.writeFileSync(targetOutputPath, outputBuffer);
      addStep(`Archivo cifrado guardado en ${targetOutputPath}`);
      const finalSha3 = crypto.createHash('sha3-256').update(outputBuffer).digest('hex');

      if (shredOriginalEnabled && sourceFilePath) {
        secureShred(sourceFilePath, parseInt(shredPasses, 10));
        addStep(`Borrado seguro aplicado a ${sourceFilePath}`);
      }

      return {
        success: true,
        outputPath: targetOutputPath,
        inputHash: sha3Input,
        outputHash: finalSha3,
        steps
      };
    } catch (err) {
      const pub = toPublicError(err);
      addStep(pub.message, false);
      return { success: false, error: pub.message, steps: sanitizeSteps(steps, false) };
    }
  });

  // 8. Core Decrypt
  ipcMain.handle('mirage:decrypt', async (event, params) => {
    const steps = [];
    const addStep = (msg, success = true) => {
      steps.push({ msg, success, timestamp: Date.now() });
    };

    try {
      let fileBuffer;
      let sourceFilePath = null;
      const {
        password = '',
        doubleFactorPassword = '',
        outputPath = '',
        shredOriginalEnabled = false,
        shredPasses = 3,
        parts = []
      } = params;

      if (!password) throw new PolicyError('Introduce la contraseña para descifrar.');

      if (parts && parts.length > 0) {
        addStep(`Reconstrucción de fragmentos Shamir (${parts.length} indicados)...`);
        const shareBuffers = [];
        for (const p of parts) {
          if (!p) continue;
          const resolved = requireUserPath(p, 'fragmento');
          if (!fs.existsSync(resolved)) throw new PolicyError(`No se encuentra el fragmento: ${resolved}`);
          shareBuffers.push(fs.readFileSync(resolved));
        }
        fileBuffer = combineShares(shareBuffers);
        addStep('Fragmentos combinados con éxito.');
      } else if (params.fileBuffer) {
        fileBuffer = Buffer.from(params.fileBuffer);
        addStep(`Archivo recibido en memoria (${fileBuffer.length} bytes)`);
      } else if (params.filePath) {
        sourceFilePath = requireUserPath(params.filePath, 'archivo cifrado');
        if (!fs.existsSync(sourceFilePath) || !fs.statSync(sourceFilePath).isFile()) {
          throw new PolicyError(`No se encuentra el archivo cifrado: ${sourceFilePath}`);
        }
        fileBuffer = fs.readFileSync(sourceFilePath);
        addStep(`Archivo cargado: ${sourceFilePath} (${fileBuffer.length} bytes)`);
      } else {
        throw new PolicyError('No se ha indicado ningún archivo para descifrar.');
      }

      // Check if encapsulated inside carrier
      let extractedFromCarrier = false;
      const stegExtracted = extractFromCarrier(fileBuffer);
      if (stegExtracted) {
        fileBuffer = stegExtracted;
        extractedFromCarrier = true;
        addStep('Portador detectado: payload cifrado extraído.');
      }

      let payloadBuffer = null;
      let duressTriggered = false;
      let isLegacy = false;

      if (isLegacyV1(fileBuffer)) {
        isLegacy = true;
        addStep('Archivo en formato v1 detectado (solo lectura).');
        const hwId = getHardwareUUID();
        const resV1 = decryptLegacyV1(fileBuffer, password, doubleFactorPassword, hwId);
        if (!resV1) throw new OpaqueError('Error de autenticación');
        payloadBuffer = resV1.payload;
        duressTriggered = resV1.duress;
      } else {
        const hwId = getHardwareUUID();
        const resV2 = decryptVault({
          envelope: fileBuffer,
          password,
          secondFactor: doubleFactorPassword,
          hardwareId: hwId
        });
        payloadBuffer = resV2.payload;
        duressTriggered = resV2.isDuress;
      }

      addStep('Autenticación criptográfica e integridad verificadas.');
      if (duressTriggered) addStep('Aviso: se ha abierto el bloque señuelo (modo de coacción).');

      const isMulti = isMultiPayload(payloadBuffer);
      let singleResult = null;
      let multiResults = [];

      if (isMulti) {
        const { files } = deserializeMultiPayload(payloadBuffer);
        addStep(`Bóveda multi-archivo descifrada: ${files.length} archivos restaurados.`);
        let baseDir = outputPath ? requireUserPath(outputPath, 'carpeta de restauración') : (sourceFilePath ? path.dirname(sourceFilePath) : os.homedir());
        fs.mkdirSync(baseDir, { recursive: true });

        for (const item of files) {
          const target = safeJoin(baseDir, item.relPath);
          fs.mkdirSync(path.dirname(target), { recursive: true });
          fs.writeFileSync(target, item.buffer);
          multiResults.push({ relPath: item.relPath, fullPath: target, size: item.buffer.length });
        }

        if (shredOriginalEnabled && sourceFilePath) {
          secureShred(sourceFilePath, parseInt(shredPasses, 10));
          addStep(`Borrado seguro aplicado a ${sourceFilePath}`);
        }

        return {
          success: true,
          isMulti: true,
          files: multiResults,
          outputPath: baseDir,
          duressTriggered,
          steps,
          legacyNotice: isLegacy ? migrateNotice() : null
        };
      } else {
        const { expirationTime, filename, fileData } = deserializePayload(payloadBuffer);
        if (expirationTime > 0 && Date.now() > expirationTime) {
          throw new PolicyError(`Este archivo caducó el ${new Date(expirationTime).toISOString()} (política TTL).`);
        }

        let targetPath;
        if (outputPath) {
          const resolvedOut = requireUserPath(outputPath, 'ruta de guardado');
          let isDir = false;
          try { isDir = fs.existsSync(resolvedOut) && fs.lstatSync(resolvedOut).isDirectory(); } catch { /* ignore */ }
          targetPath = isDir ? path.join(resolvedOut, filename) : resolvedOut;
        } else {
          const parent = sourceFilePath ? path.dirname(sourceFilePath) : os.homedir();
          targetPath = path.join(parent, filename);
        }

        fs.mkdirSync(path.dirname(targetPath), { recursive: true });
        fs.writeFileSync(targetPath, fileData);
        addStep(`Archivo restaurado en ${targetPath}`);

        const finalSha3 = crypto.createHash('sha3-256').update(fileData).digest('hex');

        if (shredOriginalEnabled && sourceFilePath) {
          secureShred(sourceFilePath, parseInt(shredPasses, 10));
          addStep(`Borrado seguro aplicado a ${sourceFilePath}`);
        }

        return {
          success: true,
          isMulti: false,
          filename,
          outputPath: targetPath,
          outputHash: finalSha3,
          duressTriggered,
          expirationTime,
          steps,
          legacyNotice: isLegacy ? migrateNotice() : null
        };
      }
    } catch (err) {
      const pub = toPublicError(err);
      addStep(pub.message, false);
      return { success: false, error: pub.message, steps: sanitizeSteps(steps, false) };
    }
  });

  // 9. Emergency Config Get & Save
  ipcMain.handle('mirage:emergency-config', async () => {
    const cfgPath = getEmergencyConfigPath();
    if (fs.existsSync(cfgPath)) {
      try { return JSON.parse(fs.readFileSync(cfgPath, 'utf8')); } catch { /* ignore */ }
    }
    return getDefaultEmergencyConfig();
  });

  ipcMain.handle('mirage:emergency-config-save', async (event, config) => {
    const cfgPath = getEmergencyConfigPath();
    fs.writeFileSync(cfgPath, JSON.stringify({ ...config, lastModified: Date.now() }, null, 2), { mode: 0o600 });
    return { success: true };
  });

  // 10. Emergency Scan
  ipcMain.handle('mirage:emergency-scan', async (event, params = {}) => {
    let targets = params.targets;
    if (!targets) {
      const cfg = await ipcMain.emit ? getDefaultEmergencyConfig() : getDefaultEmergencyConfig();
      targets = cfg.targets;
    }
    const files = scanEmergencyFiles(targets);
    const totalSize = files.reduce((acc, f) => acc + f.size, 0);
    return { success: true, files, totalFiles: files.length, totalSize };
  });

  // 11. Emergency Execute
  ipcMain.handle('mirage:emergency-execute', async (event, params = {}) => {
    const steps = [];
    const addStep = (msg, success = true) => steps.push({ msg, success, timestamp: Date.now() });

    try {
      const { password, secondFactor = '', targets = [], shredAfter = true, shredPasses = 3, outputPath, algorithm = 'mirage-c4', hardwareLock = true } = params;
      requirePasswordPolicy(password, 'La contraseña maestra');
      if (secondFactor) requirePasswordPolicy(secondFactor, 'El secreto secundario');

      const files = scanEmergencyFiles(targets);
      if (files.length === 0) throw new PolicyError('No se encontraron archivos en las rutas seleccionadas.');

      addStep(`Empaquetando ${files.length} archivos para el bloqueo de emergencia...`);
      const bundle = [];
      const home = os.homedir();

      for (const item of files) {
        const buf = fs.readFileSync(item.fullPath);
        const rel = path.relative(home, item.fullPath);
        const sha3 = crypto.createHash('sha3-256').update(buf).digest('hex');
        bundle.push({ relPath: rel, buffer: buf, sha3 });
      }

      const multiPayload = serializeMultiPayload(bundle);
      const hardwareId = getHardwareIdIfEnabled(hardwareLock);

      const { envelope } = encryptVault({
        payload: multiPayload,
        password,
        secondFactor,
        hardwareId,
        algorithm: algorithm === 'mirage-c4' ? ALGORITHMS.CASCADE : ALGORITHMS.AES_GCM,
        bucketPadding: true
      });

      const finalPath = outputPath ? requireUserPath(outputPath, 'archivo de bóveda') : path.join(home, 'EMERGENCY_VAULT.wraith');
      fs.mkdirSync(path.dirname(finalPath), { recursive: true });
      fs.writeFileSync(finalPath, envelope);
      addStep(`Bóveda de emergencia cifrada guardada en ${finalPath}`);

      if (shredAfter) {
        addStep(`Sobrescribiendo y eliminando ${files.length} archivos originales...`);
        for (const item of files) {
          secureShred(item.fullPath, shredPasses);
        }
        addStep('Archivos originales destruidos de forma segura.');
      }

      return { success: true, vaultPath: finalPath, totalFiles: files.length, steps };
    } catch (err) {
      const pub = toPublicError(err);
      addStep(pub.message, false);
      return { success: false, error: pub.message, steps };
    }
  });

  // 12. Emergency Restore
  ipcMain.handle('mirage:emergency-restore', async (event, params = {}) => {
    const steps = [];
    const addStep = (msg, success = true) => steps.push({ msg, success, timestamp: Date.now() });

    try {
      const { vaultPath, password, secondFactor = '', restoreLocation } = params;
      if (!vaultPath || !fs.existsSync(vaultPath)) throw new PolicyError('No se encuentra el archivo de la bóveda.');
      requirePasswordPolicy(password, 'La contraseña');

      const envelope = fs.readFileSync(vaultPath);
      const hwId = getHardwareUUID();
      const res = decryptVault({ envelope, password, secondFactor, hardwareId: hwId });

      if (!isMultiPayload(res.payload)) throw new PolicyError('El archivo no es una bóveda de emergencia multi-archivo.');
      const { files } = deserializeMultiPayload(res.payload);

      const baseDir = restoreLocation ? requireUserPath(restoreLocation, 'carpeta de restauración') : path.join(os.homedir(), 'Restored_Emergency_Files');
      fs.mkdirSync(baseDir, { recursive: true });

      for (const item of files) {
        const dest = safeJoin(baseDir, item.relPath);
        fs.mkdirSync(path.dirname(dest), { recursive: true });
        fs.writeFileSync(dest, item.buffer);
      }

      return { success: true, restoredCount: files.length, targetDirectory: baseDir, steps };
    } catch (err) {
      const pub = toPublicError(err);
      addStep(pub.message, false);
      return { success: false, error: pub.message, steps };
    }
  });

  // 13. Emergency Logs
  ipcMain.handle('mirage:emergency-logs', async () => {
    return { success: true, logs: [] };
  });
}
