/**
 * lib/paths.js — Contención de rutas de salida.
 *
 * Corrige MIRAGE-001 (path traversal en restauración, severidad CRÍTICA).
 *
 * Problema original: el `filename` (payload simple) y el `relPath` (vault
 * multi-archivo) venían de DENTRO del payload cifrado y se pasaban directamente
 * a `path.join(destino, rel)` seguido de `fs.mkdirSync(..., {recursive:true})` y
 * `fs.writeFileSync`. Un `.wraith` con `relPath = "../../../.bashrc"` provocaba
 * escritura arbitraria de archivos con los privilegios del usuario.
 *
 * Que el AEAD autentique el payload NO protege aquí: el tag solo prueba que
 * quien cifró eligió esa ruta. En el modelo de amenaza real ("recibo un archivo
 * cifrado de un tercero") el que cifró ES el atacante.
 *
 * Defensa en capas:
 *   1. Rechazo de rutas absolutas (POSIX, Windows con letra, y UNC).
 *   2. Rechazo de bytes NUL y caracteres de control.
 *   3. Rechazo de nombres reservados de Windows (CON, PRN, NUL, COM1..LPT9).
 *   4. Normalización y eliminación de todo componente `..`.
 *   5. Comprobación final de contención con path.resolve + separador explícito
 *      (evita el bypass clásico "/tmp/restore-evil" vs "/tmp/restore").
 */

import path from 'path';
import { OpaqueError, PolicyError } from './errors.js';

/** Nombres de dispositivo reservados en Windows (case-insensitive, con o sin extensión). */
const WINDOWS_RESERVED = new Set([
  'con', 'prn', 'aux', 'nul',
  'com1', 'com2', 'com3', 'com4', 'com5', 'com6', 'com7', 'com8', 'com9',
  'lpt1', 'lpt2', 'lpt3', 'lpt4', 'lpt5', 'lpt6', 'lpt7', 'lpt8', 'lpt9',
]);

/** Longitud máxima razonable para una ruta relativa dentro del archivo. */
const MAX_REL_PATH_LENGTH = 1024;

/**
 * Indica si una ruta relativa (proveniente del payload) es aceptable.
 * @returns {{ok: boolean, reason?: string}}
 */
export function validateRelPath(rel) {
  if (typeof rel !== 'string' || rel.length === 0) {
    return { ok: false, reason: 'ruta vacía o no es string' };
  }
  if (rel.length > MAX_REL_PATH_LENGTH) {
    return { ok: false, reason: `ruta demasiado larga (${rel.length})` };
  }
  // NUL y caracteres de control: truncan rutas en syscalls y engañan validadores.
  if (/[\u0000-\u001f\u007f]/.test(rel)) {
    return { ok: false, reason: 'contiene bytes NUL o de control' };
  }
  // Rutas absolutas POSIX.
  if (rel.startsWith('/')) {
    return { ok: false, reason: 'ruta absoluta POSIX' };
  }
  // Rutas absolutas Windows con letra de unidad (C:\, C:/, y también "C:rel").
  if (/^[a-zA-Z]:/.test(rel)) {
    return { ok: false, reason: 'ruta absoluta Windows con letra de unidad' };
  }
  // Rutas UNC y namespaces Win32 (\\server\share, \\?\C:\...).
  if (rel.startsWith('\\\\') || rel.startsWith('//')) {
    return { ok: false, reason: 'ruta UNC o namespace Win32' };
  }
  // Componente de traversal explícito en cualquier posición.
  const parts = rel.split(/[/\\]+/);
  if (parts.some((p) => p === '..')) {
    return { ok: false, reason: 'contiene componente de traversal ".."' };
  }
  // Nombres de dispositivo reservados en Windows.
  for (const p of parts) {
    if (!p) continue;
    const base = p.split('.')[0].toLowerCase().trim();
    if (WINDOWS_RESERVED.has(base)) {
      return { ok: false, reason: `nombre reservado de Windows: ${p}` };
    }
  }
  return { ok: true };
}

/**
 * Une `base` con una ruta relativa NO CONFIABLE garantizando contención.
 * Lanza OpaqueError si la ruta es hostil (viene de datos del archivo, así que
 * el mensaje no debe distinguirse de otros fallos de parsing).
 *
 * @param {string} base Directorio destino, controlado por la aplicación.
 * @param {string} rel  Ruta relativa proveniente del payload descifrado.
 * @returns {string} Ruta absoluta garantizada dentro de `base`.
 */
export function safeJoin(base, rel) {
  const verdict = validateRelPath(rel);
  if (!verdict.ok) {
    throw new OpaqueError(`safeJoin rechazó la ruta: ${verdict.reason} (${JSON.stringify(rel)})`);
  }

  // Normalizamos y eliminamos cualquier resto de traversal que sobreviva
  // a la normalización (defensa redundante, intencional).
  const normalized = path.normalize(rel).replace(/^(?:\.\.(?:[/\\]|$))+/, '');
  const root = path.resolve(base);
  const target = path.resolve(root, normalized);

  // Contención estricta: `target` debe ser `root` o estar por debajo.
  // El separador explícito impide que "/tmp/restore-evil" pase como
  // hijo de "/tmp/restore".
  const rootWithSep = root.endsWith(path.sep) ? root : root + path.sep;
  if (target !== root && !target.startsWith(rootWithSep)) {
    throw new OpaqueError(`safeJoin: la ruta escapa del directorio destino (${target})`);
  }
  if (target === root) {
    throw new OpaqueError('safeJoin: la ruta resuelve al propio directorio destino');
  }

  return target;
}

/**
 * Saneado del nombre de archivo para el modo de payload simple.
 * Descarta cualquier componente de directorio y deja solo el basename.
 * Si el resultado no es utilizable, devuelve un nombre seguro por defecto.
 */
export function safeBasename(name, fallback = 'restored_file.bin') {
  if (typeof name !== 'string' || name.length === 0) return fallback;
  // Cortamos en el primer NUL (defensa contra truncamiento en syscalls).
  const cut = name.split('\u0000')[0];
  // Tomamos el basename considerando AMBOS separadores, porque un archivo
  // creado en Windows puede llegar a un lector POSIX y viceversa.
  const base = cut.split(/[/\\]+/).pop() || '';
  const cleaned = base.replace(/[\u0000-\u001f\u007f]/g, '').trim();
  if (!cleaned || cleaned === '.' || cleaned === '..') return fallback;
  const reserved = cleaned.split('.')[0].toLowerCase();
  if (WINDOWS_RESERVED.has(reserved)) return `_${cleaned}`;
  if (cleaned.length > 255) return cleaned.slice(-255);
  return cleaned;
}

/**
 * Valida una ruta suministrada por el USUARIO a través del API (no por el
 * archivo). Aquí sí usamos PolicyError: el usuario conoce su propia entrada,
 * no hay oráculo que proteger.
 */
export function requireUserPath(p, label) {
  if (typeof p !== 'string' || !p.trim()) {
    throw new PolicyError(`Path Error: se requiere ${label}.`);
  }
  if (/[\u0000]/.test(p)) {
    throw new PolicyError(`Path Error: ${label} contiene bytes inválidos.`);
  }
  return p;
}
