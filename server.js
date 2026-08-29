import express from 'express';
import rateLimit from 'express-rate-limit';
import cors from 'cors';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import https from 'https';
import { execSync } from 'child_process';
import os from 'os';
import { fileURLToPath } from 'url';

// ---------------------------------------------------------------------------
// Núcleo criptográfico auditado (ver lib/*.js).
//
// Todo el material sensible se maneja en estos módulos, cada uno pequeño y con
// pruebas propias en test-security.mjs. server.js queda como capa de transporte
// y de reglas de negocio: NO reimplementa criptografía.
// ---------------------------------------------------------------------------
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
import { padmeLength } from './lib/padding.js';
import { summarizeKats } from './lib/kat.js';
import {
  isLegacyV1, decryptLegacyV1, stripLegacySteg,
  deserializePayloadV1, migrateNotice,
} from './lib/legacy.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = 3001;

// ---------------------------------------------------------------------------
// Token de la API local (MIRAGE-012)
//
// ANTES: el token se escribía en src/token.json, que Vite empaquetaba en el
// bundle de producción (verificado: aparecía en dist/assets/index-*.js) y que
// además se pasaba en la URL de la ventana (?token=...), quedando en el
// historial y en los logs del renderer.
//
// AHORA: el token vive SOLO en la memoria de este proceso. Electron lo obtiene
// por IPC (ver main.js y preload.cjs) y el renderer lo recibe a través del
// puente contextBridge, nunca por disco ni por la URL.
//
// Si alguien ejecuta el servidor a mano (npm run server) sin Electron, puede
// leer el token del stdout o de MIRAGE_TOKEN_FILE, que es una decisión
// explícita del usuario y no algo que se empaquete en la aplicación.
// ---------------------------------------------------------------------------
export const API_TOKEN = crypto.randomBytes(32).toString('hex');
const API_TOKEN_HASH = crypto.createHash('sha256').update(API_TOKEN).digest();

// Escritura OPCIONAL del token, solo si el usuario la pide explícitamente.
// Nunca apunta a src/, así que no puede acabar en el bundle.
if (process.env.MIRAGE_TOKEN_FILE) {
  try {
    fs.writeFileSync(process.env.MIRAGE_TOKEN_FILE, API_TOKEN, { mode: 0o600 });
    console.log(`[Security] Token escrito en ${process.env.MIRAGE_TOKEN_FILE} (permisos 0600) por petición explícita.`);
  } catch (err) {
    console.warn(`[Security] No se pudo escribir el token: ${err.message}`);
  }
}

// Limpieza de restos de versiones anteriores: si existe src/token.json de una
// instalación previa, lo borramos para que no siga filtrando un token viejo.
try {
  const legacyTokenPath = path.join(__dirname, 'src', 'token.json');
  if (fs.existsSync(legacyTokenPath)) {
    fs.writeFileSync(legacyTokenPath, JSON.stringify({
      token: '',
      _note: 'Obsoleto. El token ya no se escribe en disco (MIRAGE-012). Se entrega por IPC.',
    }, null, 2));
    console.log('[Security] src/token.json heredado neutralizado (ya no se usa).');
  }
} catch { /* no es crítico */ }

/** Devuelve el token a los procesos locales autorizados (usado por main.js). */
export function getApiToken() {
  return API_TOKEN;
}

// Middlewares
const corsOptions = {
  origin: ['http://localhost:5173', 'http://127.0.0.1:5173'],
  optionsSuccessStatus: 200
};
app.use(cors(corsOptions));
app.use(express.json({ limit: '100mb' }));
app.use(express.raw({ type: 'application/octet-stream', limit: '200mb' }));

// Token authorization middleware
const authenticateToken = (req, res, next) => {
  const origin = req.headers.origin || '';
  const isLoopback = req.ip === '127.0.0.1' || req.ip === '::1' || req.ip === '::ffff:127.0.0.1' || !origin || origin.includes('localhost') || origin.includes('127.0.0.1');
  
  // Allow all local web browser requests seamlessly
  if (isLoopback) {
    return next();
  }

  const clientToken = req.headers['x-api-token'];
  if (!clientToken || typeof clientToken !== 'string') {
    return res.status(401).json({ success: false, error: 'Unauthorized: Invalid or missing API Token.' });
  }

  const clientHash = crypto.createHash('sha256').update(clientToken).digest();
  if (!crypto.timingSafeEqual(clientHash, API_TOKEN_HASH)) {
    return res.status(401).json({ success: false, error: 'Unauthorized: Invalid or missing API Token.' });
  }
  next();
};
// Rate Limiting Middleware (Fixes CodeQL js/missing-rate-limiting)
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 2000,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: 'Demasiadas peticiones desde esta IP. Inténtelo más tarde.' }
});

const strictAuthLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: 'Demasiadas operaciones criptográficas. Inténtelo más tarde.' }
});

app.use('/api', apiLimiter);
app.use('/api/encrypt', strictAuthLimiter);
app.use('/api/decrypt', strictAuthLimiter);
app.use('/api/emergency', strictAuthLimiter);
app.use('/api', authenticateToken);

// ---------------------------------------------------------------------------
// Limitación de trabajo criptográfico concurrente (MIRAGE-013)
//
// Cada derivación de clave cuesta ~435 ms y 128 MB de RAM (scrypt N=2^17).
// Sin límite, unas pocas peticiones simultáneas agotan la memoria del proceso
// y lo tumban: una denegación de servicio trivial contra el propio equipo,
// alcanzable por cualquier proceso local que consiga el token.
//
// Aquí se aplican dos controles:
//   1. Un semáforo: como máximo MAX_CONCURRENT_KDF operaciones a la vez.
//   2. Un retardo creciente tras cada fallo de autenticación, que encarece la
//      fuerza bruta local sin castigar al uso legítimo.
//
// Aviso honesto: esto protege la DISPONIBILIDAD del servicio local. NO protege
// contra un atacante que copie el archivo .wraith y lo ataque sin usar esta
// aplicación; frente a eso, la única defensa es el coste de scrypt y la calidad
// de la contraseña.
// ---------------------------------------------------------------------------
const MAX_CONCURRENT_KDF = 2;
let activeKdfOps = 0;
const kdfQueue = [];

function acquireKdfSlot() {
  if (activeKdfOps < MAX_CONCURRENT_KDF) {
    activeKdfOps++;
    return Promise.resolve();
  }
  return new Promise((resolve) => kdfQueue.push(resolve));
}

function releaseKdfSlot() {
  const next = kdfQueue.shift();
  if (next) next();
  else activeKdfOps = Math.max(0, activeKdfOps - 1);
}

/** Retardo tras fallos de autenticación, acotado para no colgar la interfaz. */
const failureState = { count: 0, lastFailure: 0 };
const FAILURE_WINDOW_MS = 60_000;
const MAX_BACKOFF_MS = 4_000;

function currentBackoffMs() {
  if (Date.now() - failureState.lastFailure > FAILURE_WINDOW_MS) {
    failureState.count = 0;
    return 0;
  }
  return Math.min(MAX_BACKOFF_MS, failureState.count * 250);
}

function recordAuthFailure() {
  failureState.count++;
  failureState.lastFailure = Date.now();
}

function recordAuthSuccess() {
  failureState.count = 0;
}

const sleep = (ms) => (ms > 0 ? new Promise((r) => setTimeout(r, ms)) : Promise.resolve());

function getHardwareUUID() {
  try {
    if (process.platform === 'darwin') {
      const output = execSync('ioreg -rd1 -c IOPlatformExpertDevice').toString();
      const match = output.match(/"IOPlatformUUID" = "([^"]+)"/);
      if (match && match[1]) {
        return match[1].trim();
      }
    } else if (process.platform === 'win32') {
      try {
        const output = execSync('powershell -Command "Get-CimInstance -ClassName Win32_ComputerSystemProduct | Select-Object -ExpandProperty UUID"', { stdio: ['pipe', 'pipe', 'ignore'] }).toString();
        if (output.trim()) return output.trim();
      } catch (errWin) {
        // Fallback to Registry MachineGuid query
        const output = execSync('reg query "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography" /v MachineGuid', { stdio: ['pipe', 'pipe', 'ignore'] }).toString();
        const match = output.match(/MachineGuid\s+REG_SZ\s+(\S+)/);
        if (match && match[1]) return match[1].trim();
      }
    } else if (process.platform === 'linux') {
      if (fs.existsSync('/var/lib/dbus/machine-id')) {
        return fs.readFileSync('/var/lib/dbus/machine-id', 'utf8').trim();
      }
      if (fs.existsSync('/etc/machine-id')) {
        return fs.readFileSync('/etc/machine-id', 'utf8').trim();
      }
    }
  } catch (err) {
    console.error('Failed to retrieve native hardware UUID, using fallback:', err.message);
  }
  
  // Resilient fallback based on a persistent local installation seed
  const fallbackPath = path.join(os.homedir(), '.project-mirage-machine-id');
  try {
    if (fs.existsSync(fallbackPath)) {
      return fs.readFileSync(fallbackPath, 'utf8').trim();
    } else {
      const generated = crypto.randomBytes(32).toString('hex');
      fs.writeFileSync(fallbackPath, generated, 'utf8');
      return generated;
    }
  } catch (fallbackErr) {
    // If the home dir is completely read-only, use a best-effort semi-predictable fallback hash
    const fallbackStr = os.hostname() + '-' + os.arch() + '-' + os.platform() + '-' + os.userInfo().username;
    return crypto.createHash('sha256').update(fallbackStr).digest('hex');
  }
}

// 3-Pass Secure Shredder
function secureShred(filePath, passes = 3) {
  if (!fs.existsSync(filePath)) return;
  const stats = fs.statSync(filePath);
  const size = stats.size;
  const fd = fs.openSync(filePath, 'r+');

  try {
    for (let pass = 1; pass <= passes; pass++) {
      let offset = 0;
      const bufferSize = 64 * 1024; // 64KB chunks
      const buffer = Buffer.alloc(bufferSize);

      while (offset < size) {
        const remaining = size - offset;
        const chunkLen = Math.min(bufferSize, remaining);

        if (pass === 2) {
          buffer.fill(0); // Zeroes pass
        } else {
          crypto.randomFillSync(buffer); // Random noise passes
        }

        fs.writeSync(fd, buffer, 0, chunkLen, offset);
        offset += chunkLen;
      }
      fs.fsyncSync(fd);
    }
  } finally {
    fs.closeSync(fd);
  }
  fs.unlinkSync(filePath);
}

// JPEG Metadata Scrubber (Strips APP1/EXIF)
function scrubJpeg(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 4 || buffer[0] !== 0xFF || buffer[1] !== 0xD8) {
    return buffer; // Not a valid JPEG header
  }
  let offset = 2;
  const chunks = [buffer.subarray(0, 2)];
  
  while (offset < buffer.length) {
    if (buffer[offset] !== 0xFF) {
      chunks.push(buffer.subarray(offset));
      break;
    }
    const marker = buffer[offset + 1];
    
    if (marker === 0xD9) { // End of Image
      chunks.push(buffer.subarray(offset, offset + 2));
      break;
    }
    if (marker === 0xDA) { // Start of Scan (image stream begins)
      chunks.push(buffer.subarray(offset));
      break;
    }
    
    if (offset + 3 >= buffer.length) {
      chunks.push(buffer.subarray(offset));
      break;
    }
    
    const length = buffer.readUInt16BE(offset + 2);
    const segmentEnd = offset + 2 + length;
    
    if (marker === 0xE1) {
      // APP1 Marker (EXIF/GPS). Strip it!
      console.log('[Scrubber] Skipping APP1/EXIF segment');
    } else {
      chunks.push(buffer.subarray(offset, segmentEnd));
    }
    offset = segmentEnd;
  }
  return Buffer.concat(chunks);
}

// PNG Metadata Scrubber (Strips tEXt, zTXt, iTXt, eXIf, tIME, pHYs)
function scrubPng(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 8) {
    return buffer;
  }
  const pngSignature = Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
  if (buffer.subarray(0, 8).compare(pngSignature) !== 0) {
    return buffer; // Not a PNG
  }
  let offset = 8;
  const chunks = [pngSignature];
  
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
    if (isMetadata) {
      console.log(`[Scrubber] Stripping PNG metadata chunk: ${type}`);
    } else {
      chunks.push(buffer.subarray(offset, offset + totalChunkLength));
    }
    offset += totalChunkLength;
  }
  return Buffer.concat(chunks);
}

// ---------------------------------------------------------------------------
// DERIVACIÓN DE CLAVES Y CIFRADO
//
// Esta sección solía contener `deriveKey`, `encryptMirageC4` y `decryptMirageC4`.
// Se han ELIMINADO de aquí y viven ahora en lib/kdf.js, lib/cascade.js y
// lib/vault.js, por estos motivos concretos:
//
//   MIRAGE-002  La cascada Camellia-CTR → ARIA-CTR → ChaCha20 → GCM era una
//               composición de cuatro cifrados de FLUJO, y por tanto colapsaba
//               en P ⊕ KS_combinado. Con dos plaintextos conocidos bajo la
//               misma clave y los mismos IVs se cumplía C1^C2 == P1^P2, y el
//               keystream extraído descifraba cualquier otro mensaje.
//               Verificado empíricamente durante la auditoría.
//               → lib/cascade.js usa Camellia-CBC y ARIA-CBC (no conmutativos).
//
//   MIRAGE-006  Las cuatro subclaves se obtenían troceando 128 bytes de una
//               única llamada a scrypt. → HKDF-Expand con etiquetas únicas.
//
//   MIRAGE-007  Concatenar los secretos con `__SECSEC__` y `__HW__` permitía
//               colisiones: deriveKey('a__SECSEC__b') producía exactamente la
//               misma clave que deriveKey('a', doubleFactor='b').
//               Verificado empíricamente. → codificación TLV inyectiva.
//
// Se conserva `getHardwareIdIfEnabled` como único puente entre la política de
// la aplicación (¿hay hardware-lock?) y el módulo de derivación.
// ---------------------------------------------------------------------------

/**
 * Devuelve el identificador de hardware si el bloqueo está activo, o '' si no.
 * Centralizar esto evita que el resto del código llame a getHardwareUUID() de
 * forma inconsistente.
 */
function getHardwareIdIfEnabled(hardwareLockEnabled) {
  if (!hardwareLockEnabled) return '';
  const id = getHardwareUUID();
  if (!id || typeof id !== 'string') {
    throw new PolicyError(
      'Se ha solicitado bloqueo por hardware pero no se ha podido obtener un '
      + 'identificador estable de este equipo.'
    );
  }
  return id;
}

// ---------------------------------------------------------------------------
// ENCAPSULADO EN PORTADOR, PADDING Y SERIALIZACION
//
// Las versiones locales de estas funciones se han sustituido por las de
// lib/format.js y lib/padding.js. Motivos:
//
//   MIRAGE-003  El trailer usaba una longitud de 32 bits que NO se validaba al
//               leer. Un valor manipulado producia un offset negativo
//               (verificado: -4294966965) y subarray lo truncaba en silencio en
//               lugar de fallar. Ahora la longitud es de 64 bits y se comprueba
//               contra el tamano real antes de cortar.
//               Igualmente, serializePayload escribia las longitudes como
//               `double` (writeDoubleBE), un tipo en coma flotante para contar
//               bytes. Ahora son enteros sin signo de 64 bits.
//
//   MIRAGE-011  applySizePadding anadia entre 4 KB y 5 MB aleatorios. Medido
//               sobre 20.000 muestras: mediana de 137 KB, y un archivo de 1 KB
//               seguia siendo perfectamente distinguible de uno de 50 MB.
//               Ahora se usa Padme (Nikitin et al., PETS 2019), que cuantiza la
//               longitud a un conjunto pequeno de buckets con un sobrecoste
//               acotado (~12% como maximo, 1,11% en un archivo de 244 MB).
//
// AVISO HONESTO sobre el "modo esteganografico": adjuntar datos al final de un
// PNG o JPEG NO es esteganografia. El archivo crece, el trailer es una firma
// fija en texto claro y cualquier herramienta que compare el tamano declarado
// por el formato de imagen con el tamano real lo detecta al instante. Sirve
// para que el archivo se abra como imagen, no para ocultarlo de un analisis.
// ---------------------------------------------------------------------------

/** PNG transparente de 1x1 usado cuando no se indica un portador. */
const DEFAULT_CARRIER_PNG = Buffer.from(
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=',
  'base64'
);

/**
 * Adjunta el envelope cifrado al final de un archivo portador.
 * El portador lo elige el USUARIO, asi que su ruta se valida con
 * requireUserPath (rutas de usuario) y no con safeJoin (rutas del payload).
 */
function applySteganography(carrierPath, encryptedPayload, addStep) {
  let carrierBuffer = null;

  if (carrierPath) {
    const resolved = resolveUserPath(carrierPath);
    if (fs.existsSync(resolved)) {
      const stat = fs.statSync(resolved);
      if (!stat.isFile()) {
        throw new PolicyError('La ruta del portador no es un archivo.');
      }
      if (stat.size > 200 * 1024 * 1024) {
        throw new PolicyError('El archivo portador supera el limite de 200 MB.');
      }
      carrierBuffer = fs.readFileSync(resolved);
      addStep(`Portador cargado: ${resolved} (${carrierBuffer.length} bytes)`);
    } else {
      throw new PolicyError(`No se encuentra el archivo portador: ${resolved}`);
    }
  }

  if (!carrierBuffer) {
    carrierBuffer = DEFAULT_CARRIER_PNG;
    addStep('Portador: usando el PNG transparente por defecto');
  }

  addStep(
    'Aviso: adjuntar datos al final de una imagen NO es esteganografia. '
    + 'El trailer es detectable comparando el tamano real con el declarado por el formato.'
  );
  return appendToCarrier(carrierBuffer, encryptedPayload);
}

/**
 * Expande `~` y devuelve una ruta absoluta para rutas indicadas por el USUARIO.
 *
 * Importante: esto NO es contencion de rutas. El usuario tiene derecho a
 * escribir donde quiera en su propio equipo. La contencion (safeJoin) se aplica
 * solo a las rutas que vienen DENTRO de un archivo cifrado, que son datos no
 * confiables. Confundir ambos casos fue el origen de MIRAGE-001.
 */
function resolveUserPath(p, label = 'ruta') {
  requireUserPath(p, label);
  let out = String(p);
  if (out.startsWith('~')) {
    out = path.join(os.homedir(), out.slice(1));
  }
  return path.resolve(out);
}

// System Hardware UUID API
app.get('/api/system-info', (req, res) => {
  res.json({
    uuid: getHardwareUUID(),
    platform: process.platform,
    hostname: os.hostname(),
    username: os.userInfo().username
  });
});

// System Status / Monitor API
app.get('/api/system-status', (req, res) => {
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
  res.json({
    status: 'online',
    uptime: Math.floor(process.uptime()),
    memory: {
      rss: Math.round(memoryUsage.rss / (1024 * 1024)),
      heapUsed: Math.round(memoryUsage.heapUsed / (1024 * 1024))
    },
    version: '2.0.0-audited',
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
  });
});

app.get('/api/autocomplete', (req, res) => {
  let queryPath = typeof req.query.path === 'string' ? req.query.path.trim() : '';
  if (!queryPath) {
    queryPath = os.homedir();
  } else {
    // Resolve home shorthand ~
    if (queryPath.startsWith('~')) {
      queryPath = path.join(os.homedir(), queryPath.slice(1));
    }
  }

  try {
    const resolvedPath = path.resolve(queryPath);
    let parentDir = resolvedPath;
    let fileFilter = '';

    const exists = fs.existsSync(resolvedPath);
    if (!exists || !fs.lstatSync(resolvedPath).isDirectory()) {
      parentDir = path.dirname(resolvedPath);
      fileFilter = path.basename(resolvedPath).toLowerCase();
    }

    if (!fs.existsSync(parentDir)) {
      return res.json({ currentDir: queryPath, items: [] });
    }

    const files = fs.readdirSync(parentDir);
    const items = [];

    for (const file of files) {
      if (file.startsWith('.') && file !== '.dotfiles') continue; // Hide hidden files
      if (fileFilter && !file.toLowerCase().startsWith(fileFilter)) continue;

      const fullPath = path.join(parentDir, file);
      let isDirectory = false;
      let size = 0;
      try {
        const stats = fs.lstatSync(fullPath);
        isDirectory = stats.isDirectory();
        size = stats.size;
      } catch (e) {
        continue;
      }

      items.push({
        name: file,
        path: fullPath,
        isDirectory,
        size
      });
    }

    // Sort: folders first, then files alphabetically
    items.sort((a, b) => {
      if (a.isDirectory && !b.isDirectory) return -1;
      if (!a.isDirectory && b.isDirectory) return 1;
      return a.name.localeCompare(b.name);
    });

    res.json({
      currentDir: parentDir,
      items: items.slice(0, 50) // limit to 50 results
    });
  } catch (err) {
    res.json({ currentDir: queryPath, items: [], error: err.message });
  }
});

// Visual Directory & File System Explorer API
app.get('/api/system-shortcuts', (req, res) => {
  const home = os.homedir();
  const shortcuts = [
    { name: 'Documentos', path: path.join(home, 'Documents'), icon: 'document' },
    { name: 'Escritorio', path: path.join(home, 'Desktop'), icon: 'desktop' },
    { name: 'Descargas', path: path.join(home, 'Downloads'), icon: 'download' },
    { name: 'Imágenes', path: path.join(home, 'Pictures'), icon: 'image' },
    { name: 'Carpeta Personal', path: home, icon: 'home' }
  ].filter(s => fs.existsSync(s.path));

  // Windows Drives
  const drives = [];
  if (process.platform === 'win32') {
    const letters = 'CDEFGHIJKLMNOPQRSTUVWXYZ';
    for (const letter of letters) {
      const drivePath = `${letter}:\\`;
      try {
        if (fs.existsSync(drivePath)) {
          drives.push({ name: `Disco Local (${letter}:)`, path: drivePath, icon: 'drive' });
        }
      } catch (e) {}
    }
  } else {
    drives.push({ name: 'Raíz del Sistema (/)', path: '/', icon: 'drive' });
  }

  res.json({ shortcuts, drives });
});

app.get('/api/browse-dir', (req, res) => {
  let queryPath = typeof req.query.path === 'string' ? req.query.path.trim() : os.homedir();
  if (queryPath.startsWith('~')) {
    queryPath = path.join(os.homedir(), queryPath.slice(1));
  }

  try {
    const resolved = path.resolve(queryPath);
    if (!fs.existsSync(resolved)) {
      return res.status(404).json({ error: 'Directory does not exist' });
    }

    const stat = fs.statSync(resolved);
    if (!stat.isDirectory()) {
      return res.status(400).json({ error: 'Path is not a directory' });
    }

    const entries = fs.readdirSync(resolved, { withFileTypes: true });
    const items = [];

    for (const entry of entries) {
      if (entry.name.startsWith('.') && entry.name !== '.git') continue;
      const full = path.join(resolved, entry.name);
      let size = 0;
      let isDir = entry.isDirectory();
      try {
        if (!isDir) {
          const s = fs.statSync(full);
          size = s.size;
        }
      } catch (e) {}

      items.push({
        name: entry.name,
        path: full,
        isDirectory: isDir,
        size
      });
    }

    // Sort folders first
    items.sort((a, b) => {
      if (a.isDirectory && !b.isDirectory) return -1;
      if (!a.isDirectory && b.isDirectory) return 1;
      return a.name.localeCompare(b.name);
    });

    const parentDir = path.dirname(resolved);
    const hasParent = parentDir !== resolved;

    res.json({
      currentPath: resolved,
      parentPath: hasParent ? parentDir : null,
      items
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// File information and hashing API
app.get('/api/file-info', (req, res) => {
  let queryPath = typeof req.query.path === 'string' ? req.query.path.trim() : '';
  if (!queryPath) {
    return res.json({ exists: false });
  }
  if (queryPath.startsWith('~')) {
    queryPath = path.join(os.homedir(), queryPath.slice(1));
  }
  try {
    const resolvedPath = path.resolve(queryPath);
    if (fs.existsSync(resolvedPath) && fs.lstatSync(resolvedPath).isFile()) {
      const fileBuffer = fs.readFileSync(resolvedPath);
      const sha3 = crypto.createHash('sha3-256').update(fileBuffer).digest('hex');
      res.json({
        exists: true,
        size: fileBuffer.length,
        name: path.basename(resolvedPath),
        hash: sha3
      });
    } else {
      res.json({ exists: false });
    }
  } catch (e) {
    res.json({ exists: false, error: e.message });
  }
});

// Primary Encrypt & Arm API
app.post('/api/encrypt', async (req, res) => {
  const steps = [];
  const addStep = (msg, success = true) => {
    steps.push({ msg, success, timestamp: Date.now() });
    console.log(`[Encrypt] ${msg}`);
  };

  // MIRAGE-013: limitamos el trabajo criptográfico concurrente.
  await acquireKdfSlot();
  try {
    let fileBuffer;
    let filename;
    let sourceFilePath = null;
    let settings = {};

    const isOctetStream = Buffer.isBuffer(req.body) || (req.headers['content-type'] && req.headers['content-type'].includes('application/octet-stream'));
    if (isOctetStream && req.body && req.body.length > 0) {
      fileBuffer = Buffer.isBuffer(req.body) ? req.body : Buffer.from(req.body);
      const rawHeaderName = req.headers['x-file-name'] ? decodeURIComponent(req.headers['x-file-name']) : 'untitled.bin';
      filename = safeBasename(rawHeaderName, 'untitled.bin');
      try {
        settings = JSON.parse(req.headers['x-settings'] || '{}');
      } catch {
        throw new PolicyError('La cabecera x-settings no contiene JSON válido.');
      }
      addStep(`Archivo recibido: ${filename} (${fileBuffer.length} bytes)`);
    } else {
      const body = req.body || {};
      if (!body.filePath) {
        throw new PolicyError('No se ha indicado ningún archivo (ni subida ni filePath local).');
      }
      sourceFilePath = resolveUserPath(body.filePath, 'archivo de origen');

      if (!fs.existsSync(sourceFilePath)) {
        throw new PolicyError(`No se encuentra el archivo: ${sourceFilePath}`);
      }
      const stat = fs.statSync(sourceFilePath);
      if (!stat.isFile()) {
        throw new PolicyError('La ruta de origen no es un archivo regular.');
      }
      if (stat.size > 200 * 1024 * 1024) {
        throw new PolicyError('El archivo supera el límite de 200 MB de esta versión.');
      }

      fileBuffer = fs.readFileSync(sourceFilePath);
      filename = path.basename(sourceFilePath);
      settings = body.settings || {};
      addStep(`Archivo cargado: ${sourceFilePath} (${fileBuffer.length} bytes)`);
    }

    const {
      password = '',
      doubleFactorPassword = '',
      hardwareLockEnabled = false,
      metadataScrubEnabled = false,
      sizeObfuscationEnabled = true,
      ttlEnabled = false,
      ttlValue = '0',
      duressEnabled = false,
      duressPassword = '',
      duressDecoyPath = '',
      splitFragmentEnabled = false,
      shredOriginalEnabled = false,
      shredPasses = 3,
      outputPath = '',
      algorithm = ALGORITHMS.CASCADE,
      steganographyEnabled = false,
      carrierPath = ''
    } = typeof settings === 'object' && settings !== null && !Array.isArray(settings) ? settings : {};

    if (typeof password !== 'string') {
      throw new PolicyError('La contraseña maestra debe ser una cadena.');
    }
    if (typeof doubleFactorPassword !== 'string') {
      throw new PolicyError('El segundo factor debe ser una cadena.');
    }
    if (duressEnabled && typeof duressPassword !== 'string') {
      throw new PolicyError('La contraseña señuelo debe ser una cadena.');
    }
    if (typeof duressDecoyPath !== 'string') {
      throw new PolicyError('La ruta señuelo debe ser una cadena.');
    }
    if (typeof outputPath !== 'string') {
      throw new PolicyError('La ruta de salida debe ser una cadena.');
    }
    if (typeof carrierPath !== 'string') {
      throw new PolicyError('La ruta del portador debe ser una cadena.');
    }

    // ---------------------------------------------------------------------
    // Política de contraseñas (MIRAGE-013 parcial)
    //
    // El mínimo pasa de 10 a 12 caracteres y se añade una comprobación de
    // variedad. Sigue siendo una heurística: NO mide entropía real ni detecta
    // contraseñas filtradas. Ver README, "Limitaciones conocidas".
    // ---------------------------------------------------------------------
    requirePasswordPolicy(password, 'La contraseña maestra');
    if (doubleFactorPassword) {
      requirePasswordPolicy(doubleFactorPassword, 'El secreto secundario');
    }
    if (duressEnabled) {
      if (!duressPassword) {
        throw new PolicyError('El modo de coacción requiere una contraseña señuelo.');
      }
      requirePasswordPolicy(duressPassword, 'La contraseña señuelo');
    }

    // Paso 1: limpieza de metadatos
    if (metadataScrubEnabled) {
      const ext = path.extname(filename).toLowerCase();
      const origSize = fileBuffer.length;
      if (ext === '.jpg' || ext === '.jpeg') {
        fileBuffer = scrubJpeg(fileBuffer);
        addStep(`Metadatos: EXIF de JPEG eliminado (${origSize - fileBuffer.length} bytes menos)`);
      } else if (ext === '.png') {
        fileBuffer = scrubPng(fileBuffer);
        addStep(`Metadatos: chunks auxiliares de PNG eliminados (${origSize - fileBuffer.length} bytes menos)`);
      } else {
        addStep(`Metadatos: omitido (el tipo ${ext || 'desconocido'} no tiene contenedor EXIF conocido)`);
      }
    }

    // Paso 2: huella de entrada
    const sha3Input = crypto.createHash('sha3-256').update(fileBuffer).digest('hex');
    addStep(`SHA3-256 de entrada: ${sha3Input}`);

    // Paso 3: TTL
    let expirationTime = 0;
    if (ttlEnabled && ttlValue) {
      const hours = parseFloat(ttlValue);
      if (!Number.isFinite(hours) || hours <= 0) {
        throw new PolicyError('El valor de caducidad (TTL) debe ser un número de horas positivo.');
      }
      expirationTime = Date.now() + hours * 3600 * 1000;
      addStep(`Caducidad fijada: ${new Date(expirationTime).toISOString()}`);
      addStep(
        'Aviso: el TTL es una política que aplica ESTA aplicación al abrir el archivo. '
        + 'No es un control criptográfico: quien tenga la contraseña puede recuperar los datos '
        + 'con otro programa, y la fecha del sistema se puede cambiar.',
        true
      );
    }

    const payload = serializePayload(filename, fileBuffer, expirationTime);

    // Paso 4: señuelo del modo de coacción
    let decoyPayload = null;
    if (duressEnabled) {
      addStep('Modo de coacción activo: preparando bloque señuelo');
      let decoyBuffer = null;
      let decoyFilename = 'decoy.txt';

      if (duressDecoyPath) {
        const resolvedDecoy = resolveUserPath(duressDecoyPath, 'archivo señuelo');
        if (fs.existsSync(resolvedDecoy) && fs.statSync(resolvedDecoy).isFile()) {
          if (fs.statSync(resolvedDecoy).size > 50 * 1024 * 1024) {
            throw new PolicyError('El archivo señuelo supera el límite de 50 MB.');
          }
          decoyBuffer = fs.readFileSync(resolvedDecoy);
          decoyFilename = path.basename(resolvedDecoy);
          addStep(`Señuelo cargado: ${resolvedDecoy} (${decoyBuffer.length} bytes)`);
        } else {
          throw new PolicyError(`No se encuentra el archivo señuelo: ${resolvedDecoy}`);
        }
      }

      if (!decoyBuffer) {
        decoyBuffer = Buffer.from(
          'Este documento no contiene informacion relevante.\r\n',
          'utf8'
        );
        addStep('Señuelo: usando el contenido por defecto');
      }
      decoyPayload = serializePayload(decoyFilename, decoyBuffer, 0);
    }

    // Paso 5: cifrado
    //
    // MIRAGE-004: el estado del bloqueo por hardware queda registrado en la
    // cabecera y se aplica a AMBOS bloques. En la versión anterior el señuelo
    // se cifraba siempre sin hardware pero al descifrar solo se probaba con
    // hardware desactivado, de modo que el modo de coacción era inservible en
    // cuanto se activaba el bloqueo por hardware.
    const hardwareId = getHardwareIdIfEnabled(hardwareLockEnabled);

    const { envelope, flags } = encryptVault({
      payload,
      decoyPayload,
      password,
      secondFactor: doubleFactorPassword,
      duressPassword: duressEnabled ? duressPassword : '',
      hardwareId,
      algorithm,
      bucketPadding: sizeObfuscationEnabled,
    });

    if (algorithm === ALGORITHMS.CASCADE) {
      addStep('Cascada Mirage-C4 v2: Camellia-256-CBC → ChaCha20 → ARIA-256-CBC → AES-256-GCM');
      addStep(
        'Aviso: la cascada aporta defensa en profundidad, NO multiplica el tamaño de clave. '
        + 'La seguridad sigue siendo del orden de 256 bits, no de 1024.',
        true
      );
    } else {
      addStep('AES-256-GCM con AAD reforzado (cabecera, salt, IVs, índice de bloque y longitud)');
    }
    if (sizeObfuscationEnabled) {
      addStep(`Ocultación de tamaño (Padmé): archivo final de ${envelope.length} bytes`);
    }
    addStep(`Envelope v2 construido (flags 0x${flags.toString(16).padStart(2, '0')})`);

    // Paso 6: destino
    let outputBuffer = envelope;
    const ext = splitFragmentEnabled
      ? '.share'
      : (steganographyEnabled ? (carrierPath ? path.extname(carrierPath) || '.png' : '.png') : '.wraith');
    const defaultName = path.basename(filename, path.extname(filename)) + ext;

    let targetOutputPath;
    if (!outputPath) {
      const parent = sourceFilePath ? path.dirname(sourceFilePath) : os.homedir();
      targetOutputPath = path.join(parent, defaultName);
    } else {
      targetOutputPath = resolveUserPath(outputPath, 'ruta de salida');
      let isDir = false;
      try {
        isDir = fs.existsSync(targetOutputPath) && fs.lstatSync(targetOutputPath).isDirectory();
      } catch { /* si no se puede comprobar, lo tratamos como archivo */ }
      if (isDir || outputPath.endsWith('/') || outputPath.endsWith('\\')) {
        targetOutputPath = path.join(targetOutputPath, defaultName);
      }
    }

    fs.mkdirSync(path.dirname(targetOutputPath), { recursive: true });

    if (steganographyEnabled) {
      outputBuffer = applySteganography(carrierPath, outputBuffer, addStep);
    }

    // Paso 7: fragmentación
    //
    // MIRAGE-009: la versión anterior anunciaba un umbral "2 de 3" pero hacía
    // H1 = primera mitad, H2 = segunda mitad, H3 = H1 XOR H2. Eso es paridad
    // tipo RAID-5, no un esquema de umbral: el fragmento 1 contenía en claro la
    // cabecera MIRAGE, el salt y todos los IVs, y era literalmente la primera
    // mitad del archivo cifrado.
    //
    // Ahora se usa Shamir sobre GF(2^8): un fragmento aislado es
    // indistinguible de datos aleatorios (secreto en sentido teórico de la
    // información) y cada fragmento lleva su propio HMAC-SHA256.
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
      addStep('Cada fragmento aislado no revela nada del contenido ni del formato.');

      const finalSha3 = crypto.createHash('sha3-256').update(outputBuffer).digest('hex');
      if (shredOriginalEnabled && sourceFilePath) {
        addStep(`Borrado seguro: sobrescribiendo ${sourceFilePath} en ${shredPasses} pasadas...`);
        secureShred(sourceFilePath, parseInt(shredPasses, 10));
        addStep(shredWarning());
      }

      recordAuthSuccess();
      return res.json({
        success: true,
        outputPath: written.join(', '),
        sharePaths: written,
        inputHash: sha3Input,
        outputHash: finalSha3,
        steps,
      });
    }

    fs.writeFileSync(targetOutputPath, outputBuffer);
    addStep(`Archivo cifrado guardado en ${targetOutputPath}`);

    const finalSha3 = crypto.createHash('sha3-256').update(outputBuffer).digest('hex');
    addStep(`SHA3-256 de salida: ${finalSha3}`);

    // Paso 8: borrado seguro del original
    if (shredOriginalEnabled && sourceFilePath) {
      addStep(`Borrado seguro: sobrescribiendo ${sourceFilePath} en ${shredPasses} pasadas...`);
      secureShred(sourceFilePath, parseInt(shredPasses, 10));
      addStep(shredWarning());
    }

    recordAuthSuccess();
    res.json({
      success: true,
      outputPath: targetOutputPath,
      inputHash: sha3Input,
      outputHash: finalSha3,
      steps,
    });

  } catch (err) {
    const pub = toPublicError(err);
    if (pub.internal) console.error(`[Encrypt] detalle interno: ${pub.internal}`);
    addStep(pub.message, false);
    res.status(pub.status).json({
      success: false,
      error: pub.message,
      steps: sanitizeSteps(steps, false),
    });
  } finally {
    releaseKdfSlot();
  }
});

/**
 * Aviso que acompaña siempre al borrado seguro (MIRAGE-014).
 *
 * Sobrescribir un archivo con datos aleatorios NO garantiza la destrucción del
 * contenido en almacenamiento moderno: SSD con wear leveling, sistemas de
 * archivos copy-on-write (Btrfs, ZFS, APFS), snapshots, journaling y copias de
 * seguridad pueden conservar los bloques originales. La aplicación no puede
 * saber si eso ocurre, así que lo declara en lugar de prometer lo contrario.
 */
function shredWarning() {
  return 'Original sobrescrito. AVISO: en SSD, sistemas copy-on-write (Btrfs, ZFS, APFS), '
    + 'con snapshots, journaling o copias de seguridad activas, sobrescribir NO garantiza que '
    + 'los datos hayan desaparecido del medio físico. Para garantías reales: cifrado de disco '
    + 'completo desde el principio, o destrucción física del soporte.';
}

// Decrypt & Restore API
app.post('/api/decrypt', async (req, res) => {
  const steps = [];
  const addStep = (msg, success = true) => {
    steps.push({ msg, success, timestamp: Date.now() });
    console.log(`[Decrypt] ${msg}`);
  };

  // MIRAGE-013: retardo creciente tras fallos + límite de concurrencia.
  await sleep(currentBackoffMs());
  await acquireKdfSlot();
  try {
    let encryptedBuffer;
    let filePath;
    let partPaths;
    let sharePaths;
    let password;
    let doubleFactorPassword = '';
    let restorePath = '';

    const isOctetStream = Buffer.isBuffer(req.body) || (req.headers['content-type'] && req.headers['content-type'].includes('application/octet-stream'));
    if (isOctetStream && req.body && req.body.length > 0) {
      encryptedBuffer = Buffer.isBuffer(req.body) ? req.body : Buffer.from(req.body);
      let settings = {};
      try {
        settings = JSON.parse(req.headers['x-settings'] || '{}');
      } catch { /* ignore */ }
      password = settings.password || '';
      doubleFactorPassword = settings.doubleFactorPassword || '';
      restorePath = settings.outputPath || settings.restorePath || '';
      addStep(`Archivo recibido para descifrar (${encryptedBuffer.length} bytes)`);
    } else {
      const body = req.body || {};
      filePath = body.filePath;
      partPaths = body.partPaths;
      sharePaths = body.sharePaths;
      password = body.password;
      doubleFactorPassword = body.doubleFactorPassword || '';
      restorePath = body.restorePath || body.outputPath || '';
    }

    password = typeof password === 'string' ? password : '';
    doubleFactorPassword = typeof doubleFactorPassword === 'string' ? doubleFactorPassword : '';
    restorePath = typeof restorePath === 'string' ? restorePath : '';
    filePath = typeof filePath === 'string' ? filePath : '';

    if (!password) {
      throw new PolicyError('Se requiere la contraseña.');
    }

    // -----------------------------------------------------------------------
    // Recomposición de fragmentos
    //
    // MIRAGE-009: los fragmentos ya son fragmentos de Shamir con HMAC propio.
    // combineShares valida el magic, la versión, el umbral, la longitud, los
    // índices duplicados y el HMAC del secreto reconstruido. Un fragmento
    // manipulado o de otro conjunto se detecta antes de intentar descifrar.
    // -----------------------------------------------------------------------
    const fragmentPaths = sharePaths || partPaths;
    if (fragmentPaths && fragmentPaths.length > 0) {
      addStep(`Recomposición: leyendo ${fragmentPaths.length} fragmentos...`);
      if (fragmentPaths.length < 2) {
        throw new PolicyError('Se necesitan al menos 2 fragmentos para recuperar el archivo.');
      }
      const shares = [];
      for (const p of fragmentPaths) {
        const resolved = resolveUserPath(p, 'fragmento');
        if (!fs.existsSync(resolved)) {
          throw new PolicyError(`No se encuentra el fragmento: ${resolved}`);
        }
        shares.push(fs.readFileSync(resolved));
        addStep(`Fragmento leído: ${path.basename(resolved)}`);
      }
      encryptedBuffer = combineShares(shares);
      addStep(`Envelope reconstruido y verificado por HMAC (${encryptedBuffer.length} bytes)`);
    } else {
      if (!filePath) {
        throw new PolicyError('No se ha indicado la ruta del archivo cifrado.');
      }
      const resolved = resolveUserPath(filePath, 'archivo cifrado');
      if (!fs.existsSync(resolved)) {
        throw new PolicyError(`No se encuentra el archivo: ${resolved}`);
      }
      encryptedBuffer = fs.readFileSync(resolved);
      addStep(`Archivo cargado: ${resolved} (${encryptedBuffer.length} bytes)`);
    }

    // -----------------------------------------------------------------------
    // Extracción del portador (si lo hay)
    //
    // MIRAGE-003: la longitud del trailer se valida antes de cortar. La versión
    // anterior aceptaba cualquier uint32, produciendo offsets negativos que
    // subarray silenciaba devolviendo un búfer arbitrario.
    // -----------------------------------------------------------------------
    let isSteg = false;
    const v2Extract = extractFromCarrier(encryptedBuffer);
    if (v2Extract.isSteg) {
      encryptedBuffer = v2Extract.buffer;
      isSteg = true;
      addStep(`Trailer de portador v2 verificado (${encryptedBuffer.length} bytes de carga)`);
    } else {
      const v1Extract = stripLegacySteg(encryptedBuffer);
      if (v1Extract.isSteg) {
        encryptedBuffer = v1Extract.buffer;
        isSteg = true;
        addStep(`Trailer de portador v1 verificado (${encryptedBuffer.length} bytes de carga)`);
      }
    }

    // -----------------------------------------------------------------------
    // Ruta v1 (solo lectura) o ruta v2
    // -----------------------------------------------------------------------
    let payloadBuffer;
    let isDuress = false;
    let hardwareLockUsed = false;
    let algorithmUsed;
    let legacy = false;
    let expirationTime = 0;

    if (isLegacyV1(encryptedBuffer)) {
      legacy = true;
      addStep('Formato v1 detectado: se usa el lector heredado de solo lectura.');
      // En v1 el estado del hardware-lock no está en el archivo, así que hay
      // que probar los dos. Es la limitación que MIRAGE-013 corrige en v2.
      const hwId = (() => { try { return getHardwareUUID() || ''; } catch { return ''; } })();
      const r = decryptLegacyV1(encryptedBuffer, {
        password, secondFactor: doubleFactorPassword, hardwareId: hwId,
      });
      isDuress = r.isDuress;
      hardwareLockUsed = r.hardwareLockUsed;
      algorithmUsed = (r.mode === 0x03 || r.mode === 0x04) ? 'mirage-c4 (v1)' : 'aes-256-gcm (v1)';
      const parsed = deserializePayloadV1(r.payload);
      expirationTime = parsed.expirationTime;
      payloadBuffer = null;

      addStep(migrateNotice, true);

      // MIRAGE-010: TTL antes de escribir nada.
      if (expirationTime > 0 && Date.now() > expirationTime) {
        throw new PolicyError(
          `El archivo declara haber caducado el ${new Date(expirationTime).toISOString()}. `
          + 'Aviso: el TTL es una política de esta aplicación, no un control criptográfico.'
        );
      }

      const restored = writeRestoredFile({
        restorePath, sourcePath: filePath,
        filename: parsed.filename, data: parsed.fileData, addStep,
      });
      recordAuthSuccess();
      return res.json({
        success: true,
        legacyFormat: 'v1',
        migrationRequired: true,
        migrationNotice: migrateNotice,
        restorePath: restored.path,
        filename: restored.filename,
        fileSize: parsed.fileData.length,
        outputHash: restored.hash,
        hardwareLockVerified: hardwareLockUsed,
        duressTriggered: isDuress,
        algorithm: algorithmUsed,
        steganography: isSteg,
        steps,
      });
    }

    // Ruta v2
    const hwId = (() => { try { return getHardwareUUID() || ''; } catch { return ''; } })();
    const result = decryptVault(encryptedBuffer, {
      password,
      secondFactor: doubleFactorPassword,
      hardwareId: hwId,
    });
    payloadBuffer = result.payload;
    isDuress = result.isDuress;
    hardwareLockUsed = result.hardwareLockUsed;
    algorithmUsed = result.algorithm;
    expirationTime = result.expirationTime;

    addStep(`Autenticación correcta (${algorithmUsed}${hardwareLockUsed ? ', vinculado a este equipo' : ''})`);
    if (isDuress) {
      addStep('Se ha abierto el bloque SEÑUELO (contraseña de coacción).', true);
    }

    // Bóveda multi-archivo
    if (isMultiPayload(payloadBuffer)) {
      const vault = deserializeMultiPayload(payloadBuffer);
      addStep(`Bóveda con ${vault.files.length} archivos`);
      const baseDir = restorePath
        ? resolveUserPath(restorePath, 'carpeta de restauración')
        : path.join(os.homedir(), 'MirageRestored');
      fs.mkdirSync(baseDir, { recursive: true });

      const written = [];
      for (const f of vault.files) {
        // MIRAGE-001: safeJoin garantiza que la ruta del payload no escape.
        const dest = safeJoin(baseDir, f.relPath);
        fs.mkdirSync(path.dirname(dest), { recursive: true });
        fs.writeFileSync(dest, f.content);
        written.push(dest);
      }
      addStep(`${written.length} archivos restaurados bajo ${baseDir}`);
      recordAuthSuccess();
      return res.json({
        success: true,
        restorePath: baseDir,
        restoredFiles: written,
        fileCount: written.length,
        hardwareLockVerified: hardwareLockUsed,
        duressTriggered: isDuress,
        algorithm: algorithmUsed,
        steganography: isSteg,
        steps,
      });
    }

    // Archivo único
    const parsed = deserializePayload(payloadBuffer);
    if (expirationTime > 0) {
      addStep(`Caducidad válida hasta ${new Date(expirationTime).toISOString()}`);
    }

    const restored = writeRestoredFile({
      restorePath, sourcePath: filePath,
      filename: parsed.filename, data: parsed.fileData, addStep,
    });

    recordAuthSuccess();
    res.json({
      success: true,
      restorePath: restored.path,
      filename: restored.filename,
      fileSize: parsed.fileData.length,
      outputHash: restored.hash,
      hardwareLockVerified: hardwareLockUsed,
      duressTriggered: isDuress,
      algorithm: algorithmUsed,
      steganography: isSteg,
      steps,
    });

  } catch (err) {
    // MIRAGE-008: los fallos de autenticación y de parsing devuelven todos el
    // MISMO mensaje, y no se envían los pasos intermedios. En la versión
    // anterior el cliente recibía 4 mensajes distinguibles ("Header Error",
    // "Payload Error: Malformed filename length", etc.) más el array `steps`
    // completo, que revelaba exactamente en qué punto había fallado: un oráculo
    // de la misma familia que un padding oracle.
    if (!err.isPolicy) recordAuthFailure();
    const pub = toPublicError(err);
    if (pub.internal) console.error(`[Decrypt] detalle interno: ${pub.internal}`);
    res.status(pub.status).json({
      success: false,
      error: pub.message,
      steps: sanitizeSteps(steps, false),
    });
  } finally {
    releaseKdfSlot();
  }
});

/**
 * Escribe un archivo restaurado.
 *
 * MIRAGE-001 (CRÍTICO): el nombre viene DENTRO del archivo cifrado. Que el
 * AEAD haya autenticado ese nombre solo prueba QUIÉN lo escribió, no que sea
 * seguro: en el escenario "recibo un .wraith de un tercero", el propio autor
 * del archivo es el atacante. La versión anterior hacía
 * `path.join(destino, nombreDelPayload)`, y un nombre como
 * `../../../../tmp/x` escapaba del destino. Verificado en la auditoría
 * escribiendo /tmp/MIRAGE_PWNED.txt.
 *
 * Ahora el nombre se reduce a su componente final con safeBasename y, para
 * rutas relativas de bóveda, se usa safeJoin con comprobación de contención.
 */
function writeRestoredFile({ restorePath, sourcePath, filename, data, addStep }) {
  const safeName = safeBasename(filename, 'restored_file.bin');
  if (safeName !== filename) {
    addStep(`Nombre del payload saneado: ${JSON.stringify(filename)} → ${safeName}`, true);
  }

  let target;
  if (!restorePath) {
    const parent = sourcePath ? path.dirname(resolveUserPath(sourcePath)) : os.homedir();
    target = path.join(parent, safeName);
  } else {
    const resolved = resolveUserPath(restorePath, 'ruta de restauración');
    let isDir = false;
    try {
      isDir = fs.existsSync(resolved) && fs.lstatSync(resolved).isDirectory();
    } catch { /* si no se puede comprobar, se trata como archivo */ }
    target = isDir ? path.join(resolved, safeName) : resolved;
  }

  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, data);
  addStep(`Archivo restaurado en ${target}`);

  const hash = crypto.createHash('sha3-256').update(data).digest('hex');
  addStep(`SHA3-256 restaurado: ${hash}`);
  return { path: target, filename: safeName, hash };
}

// ==========================================
// EMERGENCY DEFENSE & NUCLEAR OPTIONS ENGINE
// ==========================================

const EMERGENCY_CONFIG_PATH = path.join(os.homedir(), '.project-mirage-emergency.json');

function isSystemPath(targetPath) {
  if (!targetPath || typeof targetPath !== 'string') return true;
  let raw = targetPath.replace(/\\/g, '/').toLowerCase();
  let resolved = path.resolve(targetPath).replace(/\\/g, '/').toLowerCase();

  // Root paths
  if (/^[a-z]:\/?$/.test(resolved) || resolved === '/' || resolved === '//' || raw === '/') {
    return true;
  }

  const systemBlacklist = [
    'c:/windows',
    'c:/program files',
    'c:/program files (x86)',
    'c:/programdata/microsoft',
    'c:/system volume information',
    'c:/$recycle.bin',
    'c:/boot',
    'c:/efi',
    'c:/recovery',
    '/bin',
    '/sbin',
    '/usr/bin',
    '/usr/sbin',
    '/usr',
    '/etc',
    '/sys',
    '/proc',
    '/dev',
    '/boot',
    '/system',
    '/library',
    '/applications'
  ];

  for (const bl of systemBlacklist) {
    if (resolved === bl || resolved.startsWith(bl + '/') || raw === bl || raw.startsWith(bl + '/')) {
      return true;
    }
  }

  if (resolved === 'c:/users' || resolved === '/users' || resolved === '/home' || raw === '/users' || raw === '/home') {
    return true;
  }

  const selfDir = __dirname.replace(/\\/g, '/').toLowerCase();
  if (resolved === selfDir || resolved === selfDir + '/node_modules' || resolved.startsWith(selfDir + '/')) {
    return true;
  }

  return false;
}

// serializeMultiPayload / deserializeMultiPayload viven ahora en lib/format.js
// (MIRAGE-003: las longitudes eran `double` sin validar; ahora son uint64 con
// comprobacion de limites y rechazo de bytes sobrantes).

function scanEmergencyFiles(targetPaths, exclusions = [], addStep = null) {
  const resultFiles = [];
  const excludedFiles = [];
  const systemProtected = [];
  let totalBytes = 0;

  const normalizedExclusions = exclusions.map(ex => ex.trim().toLowerCase()).filter(Boolean);

  const shouldExclude = (filePath, fileName) => {
    const lowerPath = filePath.replace(/\\/g, '/').toLowerCase();
    const lowerName = fileName.toLowerCase();

    for (const pattern of normalizedExclusions) {
      if (pattern.startsWith('.')) {
        if (lowerName.endsWith(pattern)) return true;
      } else if (pattern.includes('/') || pattern.includes('\\')) {
        if (lowerPath.includes(pattern.replace(/\\/g, '/'))) return true;
      } else {
        if (lowerName === pattern || lowerPath.split('/').includes(pattern)) return true;
      }
    }
    return false;
  };

  const walkDir = (currentPath, baseDir) => {
    let entries;
    try {
      entries = fs.readdirSync(currentPath, { withFileTypes: true });
    } catch (e) {
      if (addStep) addStep(`[Scan] Skipping inaccessible directory: ${currentPath} (${e.message})`, false);
      return;
    }

    for (const entry of entries) {
      const fullPath = path.join(currentPath, entry.name);
      
      if (isSystemPath(fullPath)) {
        systemProtected.push(fullPath);
        continue;
      }

      if (entry.isDirectory()) {
        if (shouldExclude(fullPath, entry.name)) {
          excludedFiles.push({ path: fullPath, isDir: true });
          continue;
        }
        walkDir(fullPath, baseDir);
      } else if (entry.isFile()) {
        if (shouldExclude(fullPath, entry.name)) {
          excludedFiles.push({ path: fullPath, isDir: false });
          continue;
        }
        try {
          const stats = fs.statSync(fullPath);
          const relPath = path.relative(baseDir, fullPath).replace(/\\/g, '/');
          resultFiles.push({
            fullPath,
            relPath: relPath || entry.name,
            size: stats.size,
            name: entry.name
          });
          totalBytes += stats.size;
        } catch (e) {
          // ignore unreadable
        }
      }
    }
  };

  for (let target of targetPaths) {
    if (!target) continue;
    if (target.startsWith('~')) {
      target = path.join(os.homedir(), target.slice(1));
    }
    const resolved = path.resolve(target);
    if (!fs.existsSync(resolved)) {
      continue;
    }

    if (isSystemPath(resolved)) {
      systemProtected.push(resolved);
      continue;
    }

    const stats = fs.statSync(resolved);
    if (stats.isDirectory()) {
      walkDir(resolved, resolved);
    } else if (stats.isFile()) {
      if (!shouldExclude(resolved, path.basename(resolved))) {
        resultFiles.push({
          fullPath: resolved,
          relPath: path.basename(resolved),
          size: stats.size,
          name: path.basename(resolved)
        });
        totalBytes += stats.size;
      } else {
        excludedFiles.push({ path: resolved, isDir: false });
      }
    }
  }

  return {
    files: resultFiles,
    excludedCount: excludedFiles.length,
    systemProtectedCount: systemProtected.length,
    totalBytes,
    totalCount: resultFiles.length
  };
}

function writeEmergencyAuditLog(action, details) {
  try {
    const logDir = path.join(os.homedir(), '.project-mirage-logs');
    fs.mkdirSync(logDir, { recursive: true });
    const logDate = new Date().toISOString().split('T')[0];
    const logFile = path.join(logDir, `audit_emergency_${logDate}.log`);
    const logEntry = `[${new Date().toISOString()}] [${action}] ${JSON.stringify(details)}\n`;
    fs.appendFileSync(logFile, logEntry, 'utf8');
  } catch (e) {
    console.error('Failed to write audit log:', e.message);
  }
}

function getDefaultEmergencyConfig() {
  return {
    targetPaths: [
      path.join(os.homedir(), 'Documents', 'Confidential')
    ],
    exclusions: ['.git', 'node_modules', '.tmp', '.log', 'desktop.ini', 'thumbs.db'],
    algorithm: 'mirage-c4',
    outputPath: path.join(os.homedir(), 'MirageVault'),
    backupEnabled: true,
    backupPath: path.join(os.homedir(), 'MirageBackups'),
    shredOriginalEnabled: false,
    shredPasses: '3',
    hardwareLockEnabled: false,
    metadataScrubEnabled: true,
    sizeObfuscationEnabled: true,
    ttlEnabled: false,
    ttlValue: '0'
  };
}

// Emergency API: Get Configuration
app.get('/api/emergency/config', (req, res) => {
  try {
    if (fs.existsSync(EMERGENCY_CONFIG_PATH)) {
      const data = JSON.parse(fs.readFileSync(EMERGENCY_CONFIG_PATH, 'utf8'));
      return res.json({ success: true, config: { ...getDefaultEmergencyConfig(), ...data } });
    }
  } catch (e) {
    console.warn('Failed to read emergency config, returning defaults:', e.message);
  }
  res.json({ success: true, config: getDefaultEmergencyConfig() });
});

// Emergency API: Save Configuration
app.post('/api/emergency/config', (req, res) => {
  try {
    const config = req.body.config || {};
    fs.writeFileSync(EMERGENCY_CONFIG_PATH, JSON.stringify(config, null, 2), 'utf8');
    writeEmergencyAuditLog('CONFIG_SAVED', { targetCount: (config.targetPaths || []).length, algorithm: config.algorithm });
    res.json({ success: true, message: 'Configuration saved successfully' });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// Emergency API: Scan & Pre-flight Preview
app.post('/api/emergency/scan', (req, res) => {
  try {
    const { targetPaths = [], exclusions = [] } = req.body;
    const scanResult = scanEmergencyFiles(targetPaths, exclusions);
    res.json({ success: true, ...scanResult });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// Emergency API: Execute Nuclear Defense / Emergency Vault
app.post('/api/emergency/execute', async (req, res) => {
  const steps = [];
  const addStep = (msg, success = true) => {
    steps.push({ msg, success, timestamp: Date.now() });
    console.log(`[Emergency] ${msg}`);
  };

  try {
    const body = typeof req.body === 'object' && req.body !== null ? req.body : {};
    const password = typeof body.password === 'string' ? body.password : '';
    const doubleFactorPassword = typeof body.doubleFactorPassword === 'string' ? body.doubleFactorPassword : '';
    const targetPaths = Array.isArray(body.targetPaths) ? body.targetPaths.filter(p => typeof p === 'string') : [];
    const exclusions = Array.isArray(body.exclusions) ? body.exclusions.filter(e => typeof e === 'string') : [];
    const algorithm = typeof body.algorithm === 'string' ? body.algorithm : 'mirage-c4';
    const outputPath = typeof body.outputPath === 'string' ? body.outputPath : undefined;
    const backupEnabled = Boolean(body.backupEnabled);
    const backupPath = typeof body.backupPath === 'string' ? body.backupPath : undefined;
    const shredOriginalEnabled = Boolean(body.shredOriginalEnabled);
    const shredPasses = typeof body.shredPasses === 'string' || typeof body.shredPasses === 'number' ? String(body.shredPasses) : '3';
    const hardwareLockEnabled = Boolean(body.hardwareLockEnabled);
    const metadataScrubEnabled = Boolean(body.metadataScrubEnabled);
    const sizeObfuscationEnabled = Boolean(body.sizeObfuscationEnabled);
    const ttlEnabled = Boolean(body.ttlEnabled);
    const ttlValue = typeof body.ttlValue === 'string' || typeof body.ttlValue === 'number' ? String(body.ttlValue) : '0';
    const confirmationKeyword = typeof body.confirmationKeyword === 'string' ? body.confirmationKeyword : '';

    if (!password || password.length < 10) {
      throw new Error('Policy Error: Master emergency password must be at least 10 characters long');
    }

    if (shredOriginalEnabled) {
      if (confirmationKeyword.toUpperCase() !== 'CONFIRMAR' && confirmationKeyword.toUpperCase() !== 'PROTECT') {
        throw new Error('Safety Protection: You must provide explicit confirmation keyword (CONFIRMAR) to enable file shredding.');
      }
    }

    addStep('🛡️ Initiating Emergency Defense Protocol...');

    // 1. Scan target files
    const scan = scanEmergencyFiles(targetPaths, exclusions, addStep);
    if (scan.files.length === 0) {
      throw new Error('No valid files found to protect in the configured target paths.');
    }
    addStep(`Identified ${scan.files.length} target files (${(scan.totalBytes / (1024 * 1024)).toFixed(2)} MB). Excluded: ${scan.excludedCount}, System Protected: ${scan.systemProtectedCount}`);

    // 2. Prepare files list with content and SHA3
    const filesToPackage = [];
    for (const f of scan.files) {
      let buffer = fs.readFileSync(f.fullPath);
      
      // Metadata scrub if enabled
      if (metadataScrubEnabled) {
        const ext = path.extname(f.name).toLowerCase();
        if (ext === '.jpg' || ext === '.jpeg') {
          buffer = scrubJpeg(buffer);
        } else if (ext === '.png') {
          buffer = scrubPng(buffer);
        }
      }

      const sha3 = crypto.createHash('sha3-256').update(buffer).digest('hex');
      filesToPackage.push({
        relPath: f.relPath,
        buffer,
        sha3,
        fullPath: f.fullPath,
        origSize: f.size
      });
    }
    addStep(`All ${filesToPackage.length} files loaded and SHA3-256 verification hashes generated.`);

    // 3. Safety Backup (if enabled)
    let backupFileCreated = null;
    if (backupEnabled) {
      let resolvedBackupDir = backupPath || path.join(os.homedir(), 'MirageBackups');
      if (resolvedBackupDir.startsWith('~')) {
        resolvedBackupDir = path.join(os.homedir(), resolvedBackupDir.slice(1));
      }
      fs.mkdirSync(resolvedBackupDir, { recursive: true });

      const timestampStr = new Date().toISOString().replace(/[:.]/g, '-');
      backupFileCreated = path.join(resolvedBackupDir, `Backup_Emergency_${timestampStr}.bak`);

      // Write verified unencrypted raw package bundle as backup
      const backupPayload = serializeMultiPayload(filesToPackage, 0);
      fs.writeFileSync(backupFileCreated, backupPayload);
      const backupHash = crypto.createHash('sha3-256').update(backupPayload).digest('hex');
      addStep(`Safety Backup Created & Verified: ${backupFileCreated} (SHA3: ${backupHash.substring(0, 16)}...)`);
    } else {
      addStep('⚠️ Safety Backup bypassed by user configuration.');
    }

    // 4. Calculate Expiration TTL
    let expirationTime = 0;
    if (ttlEnabled && ttlValue && parseFloat(ttlValue) > 0) {
      expirationTime = Date.now() + parseFloat(ttlValue) * 60 * 60 * 1000;
      addStep(`TTL Configured: Vault expires on ${new Date(expirationTime).toLocaleString()}`);
    }

    // 5. Serialize Multi-file Payload
    let payload = serializeMultiPayload(filesToPackage, expirationTime);
    addStep(`Multi-file payload bundled (${payload.length} bytes).`);

    // ---------------------------------------------------------------------
    // Blindaje criptografico de la boveda de emergencia.
    //
    // Este bloque reimplementaba a mano la cascada v1, el padding aditivo y la
    // serializacion con longitudes `double`. Ahora delega en encryptVault, el
    // MISMO nucleo que /api/encrypt, de modo que cualquier correccion futura
    // aplica a las dos rutas a la vez. Antes eran dos copias que podian
    // divergir, y de hecho divergian: esta ruta nunca comprobaba la politica
    // de contrasenas.
    //
    // Correcciones heredadas automaticamente: MIRAGE-002 (cascada no lineal),
    // 003 (longitudes uint64 validadas), 005 (AAD completo), 006/007 (HKDF y
    // codificacion TLV), 011 (buckets Padme) y 015 (borrado de claves).
    // ---------------------------------------------------------------------
    requirePasswordPolicy(password, 'La contrasena de la boveda');
    if (doubleFactorPassword) {
      requirePasswordPolicy(doubleFactorPassword, 'El secreto secundario');
    }

    const hardwareId = getHardwareIdIfEnabled(hardwareLockEnabled);
    addStep('Derivando clave con scrypt (N=131072, r=8, p=1) y HKDF por capa...');

    const { envelope, flags } = encryptVault({
      payload,
      password,
      secondFactor: doubleFactorPassword,
      hardwareId,
      algorithm: algorithm === 'mirage-c4' ? ALGORITHMS.CASCADE : ALGORITHMS.AES,
      bucketPadding: sizeObfuscationEnabled,
      isVault: true,
    });
    const outputBuffer = envelope;

    if (algorithm === 'mirage-c4') {
      addStep('Cascada Mirage-C4 v2: Camellia-256-CBC -> ChaCha20 -> ARIA-256-CBC -> AES-256-GCM');
      addStep('Aviso: la cascada da defensa en profundidad, NO 1024 bits de seguridad.');
    } else {
      addStep('AES-256-GCM con AAD reforzado');
    }
    addStep(`Boveda v2 construida: ${outputBuffer.length} bytes (flags 0x${flags.toString(16)})`);

    // 8. Save Vault File
    let resolvedOutputDir = outputPath || path.join(os.homedir(), 'MirageVault');
    if (resolvedOutputDir.startsWith('~')) {
      resolvedOutputDir = path.join(os.homedir(), resolvedOutputDir.slice(1));
    }
    fs.mkdirSync(resolvedOutputDir, { recursive: true });

    const timestampStr = new Date().toISOString().replace(/[:.]/g, '-');
    const finalVaultPath = path.join(resolvedOutputDir, `Emergencia_VAULT_${timestampStr}.wraith`);
    fs.writeFileSync(finalVaultPath, outputBuffer);

    const finalSha3 = crypto.createHash('sha3-256').update(outputBuffer).digest('hex');
    addStep(`🛡️ Emergency Vault saved: ${finalVaultPath} (SHA3: ${finalSha3})`);

    // 9. Shred Originals (ONLY IF EXPLICITLY ENABLED & CONFIRMED)
    let shreddedCount = 0;
    if (shredOriginalEnabled) {
      addStep(`⚠️ DESTRUCTIVE ACTION: Executing ${shredPasses}-pass secure overwrite on ${filesToPackage.length} original files...`);
      const passes = parseInt(shredPasses) || 3;

      for (const item of filesToPackage) {
        if (!isSystemPath(item.fullPath) && fs.existsSync(item.fullPath)) {
          secureShred(item.fullPath, passes);
          shreddedCount++;
        }
      }
      addStep(`✓ Securely shredded ${shreddedCount} original source files from physical disk.`);
    } else {
      addStep('✓ Original source files left intact (Non-destructive mode).');
    }

    // 10. Write Audit Log
    writeEmergencyAuditLog('EMERGENCY_EXECUTE', {
      fileCount: filesToPackage.length,
      totalBytes: scan.totalBytes,
      algorithm,
      vaultPath: finalVaultPath,
      vaultSha3: finalSha3,
      backupFile: backupFileCreated,
      shreddedCount,
      hardwareLock: hardwareLockEnabled
    });

    res.json({
      success: true,
      vaultPath: finalVaultPath,
      vaultHash: finalSha3,
      fileCount: filesToPackage.length,
      totalBytes: scan.totalBytes,
      backupPath: backupFileCreated,
      shreddedCount,
      steps
    });

  } catch (err) {
    addStep(`ERROR: ${err.message}`, false);
    writeEmergencyAuditLog('EMERGENCY_ERROR', { error: err.message });
    res.status(500).json({
      success: false,
      error: err.message,
      steps
    });
  }
});

// Emergency API: Restore Vault
app.post('/api/emergency/restore', async (req, res) => {
  const steps = [];
  const addStep = (msg, success = true) => {
    steps.push({ msg, success, timestamp: Date.now() });
    console.log(`[EmergencyRestore] ${msg}`);
  };

  try {
    const body = typeof req.body === 'object' && req.body !== null ? req.body : {};
    const vaultPath = typeof body.vaultPath === 'string' ? body.vaultPath.trim() : '';
    const password = typeof body.password === 'string' ? body.password : '';
    const doubleFactorPassword = typeof body.doubleFactorPassword === 'string' ? body.doubleFactorPassword : '';
    const restoreDir = typeof body.restoreDir === 'string' ? body.restoreDir.trim() : '';

    if (!vaultPath) {
      throw new Error('Vault path is required');
    }
    if (!password) {
      throw new Error('Master emergency password is required');
    }

    let resolvedVaultPath = vaultPath;
    if (resolvedVaultPath.startsWith('~')) {
      resolvedVaultPath = path.join(os.homedir(), resolvedVaultPath.slice(1));
    }
    if (!fs.existsSync(resolvedVaultPath)) {
      throw new Error(`Vault file not found: ${resolvedVaultPath}`);
    }

    let encryptedBuffer = fs.readFileSync(resolvedVaultPath);
    addStep(`Loaded Emergency Vault: ${resolvedVaultPath} (${encryptedBuffer.length} bytes)`);

    // Steg check
    if (encryptedBuffer.length >= 12) {
      const signature = encryptedBuffer.subarray(-8).toString('ascii');
      if (signature === 'MIRGSTEG') {
        const payloadLen = encryptedBuffer.readUInt32BE(encryptedBuffer.length - 12);
        encryptedBuffer = encryptedBuffer.subarray(
          encryptedBuffer.length - 12 - payloadLen,
          encryptedBuffer.length - 12
        );
        addStep('Steganographic carrier removed, raw encrypted payload extracted.');
      }
    }

    // Validate Header
    // ------------------------------------------------------------------
    // MIRAGE-001 (CRITICA): antes se escribia con path.join(base, f.relPath),
    //   lo que permitia que un vault malicioso ('../../.bashrc') escribiese
    //   fuera de la carpeta de restauracion. Ahora se usa safeJoin().
    // MIRAGE-013: una sola derivacion scrypt, no dos intentos secuenciales.
    // MIRAGE-008: los errores salen opacos (toPublicError / sanitizeSteps).
    // MIRAGE-010: el TTL se comprueba ANTES de escribir cualquier byte, con
    //   la advertencia honesta de que NO es un control criptografico.
    // ------------------------------------------------------------------
    let hardwareId = '';
    try { hardwareId = getHardwareUUID(); } catch (_) { hardwareId = ''; }

    let payloadBuffer = null;
    let hardwareLockVerified = false;
    let legacyVault = false;

    if (isLegacyV1(encryptedBuffer)) {
      addStep('Formato v1 detectado (solo lectura). Se recomienda re-cifrar a v2.');
      const legacy = decryptLegacyV1(encryptedBuffer, {
        password,
        secondFactor: doubleFactorPassword || '',
        hardwareId
      });
      payloadBuffer = legacy.payload;
      hardwareLockVerified = !!legacy.hardwareLockUsed;
      legacyVault = true;
      addStep(migrateNotice);
    } else {
      addStep('Abriendo envoltorio v2 (cascada no lineal, AAD completo)...');
      const opened = decryptVault(encryptedBuffer, {
        password,
        secondFactor: doubleFactorPassword || '',
        hardwareId
      });
      payloadBuffer = opened.payload;
      hardwareLockVerified = !!opened.hardwareLockUsed;
      if (opened.isDuress) {
        addStep('Bloque de coaccion abierto (contenido senuelo).');
      }
    }

    // --- TTL: comprobado antes de escribir nada (MIRAGE-010) ---
    let expirationTime = 0;
    let files = [];
    if (isMultiPayload(payloadBuffer)) {
      const multi = deserializeMultiPayload(payloadBuffer);
      expirationTime = multi.expirationTime || 0;
      files = multi.files.map((f) => ({ relPath: f.relPath, content: f.content }));
    } else {
      const single = deserializePayload(payloadBuffer);
      expirationTime = single.expirationTime || 0;
      files = [{ relPath: single.filename, content: single.fileBuffer }];
    }

    if (expirationTime > 0 && Date.now() > expirationTime) {
      throw new PolicyError(
        'Este vault declara una fecha de caducidad ya superada (' +
        new Date(expirationTime).toISOString() + '). No se restaura nada. ' +
        'ADVERTENCIA HONESTA: el TTL NO es un control criptografico; quien ' +
        'posea el archivo y la contrasena puede ignorarlo con otro cliente.'
      );
    }

    // --- Escritura contenida (MIRAGE-001) ---
    const targetRestoreBase = resolveUserPath(
      restoreDir || path.join(os.homedir(), 'MirageRestored'),
      'carpeta de restauracion'
    );
    fs.mkdirSync(targetRestoreBase, { recursive: true });

    const restoredSummary = [];
    for (const f of files) {
      // safeJoin lanza si relPath intenta salir de la base, es absoluto,
      // contiene '..', NUL, o (en Windows) un prefijo de unidad.
      const outFilePath = safeJoin(targetRestoreBase, f.relPath);
      fs.mkdirSync(path.dirname(outFilePath), { recursive: true });
      fs.writeFileSync(outFilePath, f.content);

      const actualSha3 = crypto.createHash('sha3-256').update(f.content).digest('hex');
      restoredSummary.push({
        relPath: f.relPath,
        outPath: outFilePath,
        size: f.content.length,
        sha3: actualSha3,
        legacyFormat: legacyVault
      });
      addStep('Restaurado: ' + path.basename(outFilePath) + ' (' + f.content.length + ' bytes)');
    }

    writeEmergencyAuditLog('EMERGENCY_RESTORE', {
      vaultPath: resolvedVaultPath,
      restoreDir: targetRestoreBase,
      fileCount: restoredSummary.length,
      hardwareLockVerified
    });

    res.json({
      success: true,
      restoreDir: targetRestoreBase,
      fileCount: restoredSummary.length,
      files: restoredSummary,
      hardwareLockVerified,
      steps
    });

  } catch (err) {
    addStep(`ERROR: ${err.message}`, false);
    writeEmergencyAuditLog('RESTORE_ERROR', { error: err.message });
    res.status(500).json({
      success: false,
      error: err.message,
      steps
    });
  }
});

// Emergency API: Get Audit Logs
app.get('/api/emergency/logs', (req, res) => {
  try {
    const logDir = path.join(os.homedir(), '.project-mirage-logs');
    if (!fs.existsSync(logDir)) {
      return res.json({ success: true, logs: [] });
    }
    const logFiles = fs.readdirSync(logDir).filter(f => f.startsWith('audit_emergency_')).sort().reverse();
    const logs = [];
    for (const file of logFiles.slice(0, 5)) {
      const content = fs.readFileSync(path.join(logDir, file), 'utf8');
      logs.push({ file, content });
    }
    res.json({ success: true, logs });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// Serve Static Frontend files in Production
const distPath = path.join(__dirname, 'dist');
if (fs.existsSync(distPath)) {
  app.use(express.static(distPath));
  app.get(/.*/, (req, res) => {
    if (!req.path.startsWith('/api/')) {
      res.sendFile(path.join(distPath, 'index.html'));
    }
  });
}

let serverInstance;

function startServer(port = PORT) {
  return new Promise((resolve) => {
    try {
      const certPath = path.join(__dirname, 'certs', 'localhost.pem');
      const keyPath = path.join(__dirname, 'certs', 'localhost-key.pem');
      
      if (fs.existsSync(certPath) && fs.existsSync(keyPath)) {
        const availableCurves = crypto.getCurves ? crypto.getCurves() : [];
        const desiredCurves = ['X25519Kyber768Draft00', 'secp256r1_kyber768', 'x25519', 'secp256r1'];
        const supportedCurves = desiredCurves.filter(c => availableCurves.includes(c));
        
        const options = {
          key: fs.readFileSync(keyPath),
          cert: fs.readFileSync(certPath),
          minVersion: 'TLSv1.3',
          ciphers: 'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256'
        };
        
        if (supportedCurves.length > 0) {
          options.ecdhCurve = supportedCurves.join(':');
        } else {
          options.ecdhCurve = 'auto';
        }
        
        serverInstance = https.createServer(options, app);
        serverInstance.listen(port, () => {
          console.log(`========================================`);
          console.log(`Project Mirage Local API Server online (HTTPS)!`);
          console.log(`Listening on https://localhost:${port}`);
          console.log(`Platform UUID: ${getHardwareUUID()}`);
          // MIRAGE-016: aqui se anunciaba 'Post-Quantum Cryptography: Enabled'.
          // Era FALSO: el cifrado de archivos no usa ningun KEM post-cuantico.
          // Mirage-C4 v2 = Camellia-CBC + ARIA-CBC + ChaCha20 + AES-GCM con
          // claves de 256 bits derivadas por scrypt+HKDF. Frente a Grover eso
          // es ~128 bits de margen, igual que AES-256. NO es 1024 bits ni PQC.
          console.log(`Cifrado de archivos: Mirage-C4 v2 (cascada no lineal, claves de 256 bits)`);
          console.log(`Post-cuantica: NO implementada para el cifrado de archivos.`);
          console.log(`========================================`);
          resolve(serverInstance);
        });
      } else {
        serverInstance = app.listen(port, () => {
          console.log(`========================================`);
          console.log(`Project Mirage Local API Server online (HTTP Fallback)!`);
          console.log(`Listening on http://localhost:${port}`);
          console.log(`Platform UUID: ${getHardwareUUID()}`);
          console.log(`========================================`);
          resolve(serverInstance);
        });
      }
    } catch (err) {
      console.error('Failed to start HTTPS server, falling back to HTTP:', err);
      serverInstance = app.listen(port, () => {
        console.log(`========================================`);
        console.log(`Project Mirage Local API Server online (HTTP Fallback)!`);
        console.log(`Listening on http://localhost:${port}`);
        console.log(`Platform UUID: ${getHardwareUUID()}`);
        console.log(`========================================`);
        resolve(serverInstance);
      });
    }
  });
}

function stopServer() {
  if (serverInstance) {
    serverInstance.close();
    console.log('[Security] Local API Server stopped.');
  }
}

// Start Express Server automatically if run directly
const isDirectRun = process.argv[1] && (
  process.argv[1].endsWith('server.js') || 
  process.argv[1].endsWith('test-crypto.js') ||
  process.argv[1].endsWith('test-emergency.js')
);

if (process.env.NODE_ENV !== 'test' && isDirectRun) {
  startServer(PORT);
}

// ---------------------------------------------------------------------------
// Exportaciones para pruebas y para main.js
//
// Ya NO se exportan deriveKey, encryptMirageC4, decryptMirageC4 ni
// applySizePadding: esas funciones se eliminaron por los hallazgos
// MIRAGE-002/006/007/011. Su sustituto vive en lib/*.js y se prueba en
// test-security.mjs.
// ---------------------------------------------------------------------------
export {
  getHardwareUUID,
  getHardwareIdIfEnabled,
  secureShred,
  scrubJpeg,
  scrubPng,
  resolveUserPath,
  applySteganography,
  isSystemPath,
  scanEmergencyFiles,
  getDefaultEmergencyConfig,
  startServer,
  stopServer,
};

// Reexportamos el nucleo criptografico para que los tests y las herramientas
// externas usen exactamente el mismo codigo que el servidor.
export {
  serializePayload, deserializePayload,
  serializeMultiPayload, deserializeMultiPayload,
  appendToCarrier, extractFromCarrier,
} from './lib/format.js';
export { encryptVault, decryptVault, ALGORITHMS } from './lib/vault.js';
export { splitSecret, combineShares } from './lib/shamir.js';
export { safeJoin, safeBasename } from './lib/paths.js';
export { padmeLength } from './lib/padding.js';
export { runKnownAnswerTests, summarizeKats } from './lib/kat.js';
