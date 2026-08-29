/**
 * lib/kdf.js — Derivación de claves con dominio de separación.
 *
 * Corrige:
 *   MIRAGE-007 (colisión de secretos por concatenación con separador)
 *   MIRAGE-006 (separación de claves por troceo, no por KDF)
 *   MIRAGE-015 (parcial: zeroization del material intermedio)
 *
 * --- MIRAGE-007 ---
 * El código original construía el material del KDF concatenando strings:
 *     combined = password
 *     if (df) combined += '__SECSEC__' + df
 *     if (hw) combined += '__HW__' + uuid
 * Eso es ambiguo. Verificado empíricamente en la auditoría:
 *     deriveKey('userpass12__SECSEC__second1234', salt, false, '')
 *       === deriveKey('userpass12', salt, false, 'second1234')
 * es decir, el segundo factor era bypasseable poniendo la cadena completa como
 * contraseña primaria. Clase clásica de bug de canonicalización.
 *
 * Solución: codificación inyectiva con longitudes explícitas (TLV). Cada campo
 * va precedido por su longitud en 4 bytes big-endian, así que ninguna
 * combinación de entradas distintas puede producir el mismo buffer.
 *
 * --- MIRAGE-006 ---
 * El original pedía 128 bytes a scrypt y los troceaba en 4 subclaves de 32.
 * No hay dominio de separación criptográfica: las 4 subclaves salen del mismo
 * bloque sin etiquetas distintas. Ahora scrypt produce UN pseudorandom key
 * (PRK) de 32 bytes y cada subclave se expande con HKDF-Expand usando un label
 * `info` único e inequívoco por capa y por propósito.
 *
 * Ventaja operativa adicional: scrypt (el paso caro, ~0.4 s y 128 MB) se
 * ejecuta UNA vez; añadir capas o material extra ya no cuesta nada.
 */

import crypto from 'crypto';
import { PolicyError } from './errors.js';

/** Parámetros scrypt. Se conservan los del proyecto original: son fuertes. */
export const SCRYPT_PARAMS = Object.freeze({
  N: 131072, // 2^17
  r: 8,
  p: 1,
  maxmem: 256 * 1024 * 1024, // 128 MB requeridos + margen
});

/** Longitud del PRK intermedio y de cada subclave derivada. */
const PRK_LEN = 32;
const SUBKEY_LEN = 32;

/** Etiqueta de versión: cambiarla invalida todas las claves derivadas. */
const KDF_VERSION_LABEL = 'mirage/kdf/v2';

/**
 * Codificación TLV inyectiva de un campo.
 * [len:4B BE][bytes]
 */
function encodeField(value) {
  const buf = Buffer.isBuffer(value)
    ? value
    : Buffer.from(value == null ? '' : String(value), 'utf8');
  const len = Buffer.alloc(4);
  len.writeUInt32BE(buf.length, 0);
  return Buffer.concat([len, buf]);
}

/**
 * Construye el material de entrada al KDF de forma NO AMBIGUA.
 *
 * Formato: version || TLV(password) || TLV(secondFactor) || TLV(hardwareId)
 * Los campos ausentes se codifican como longitud 0, nunca se omiten: así
 * "sin segundo factor" y "segundo factor vacío" son el mismo caso explícito,
 * y jamás colisionan con un valor presente.
 */
export function buildKdfMaterial({ password, secondFactor = '', hardwareId = '' }) {
  if (typeof password !== 'string' && !Buffer.isBuffer(password)) {
    throw new PolicyError('Key Derivation Error: password inválido.');
  }
  return Buffer.concat([
    encodeField(KDF_VERSION_LABEL),
    encodeField(password),
    encodeField(secondFactor || ''),
    encodeField(hardwareId || ''),
  ]);
}

/**
 * Deriva el PRK maestro con scrypt. Este es el único paso costoso.
 *
 * @param {object} opts
 * @param {string|Buffer} opts.password
 * @param {string} [opts.secondFactor]  Segundo secreto (2FA simétrico).
 * @param {string} [opts.hardwareId]    UUID de hardware, si el binding está activo.
 * @param {Buffer} opts.salt            Salt aleatorio de 16 bytes.
 * @returns {Buffer} PRK de 32 bytes.
 */
export function deriveMasterKey({ password, secondFactor = '', hardwareId = '', salt }) {
  if (!Buffer.isBuffer(salt) || salt.length < 16) {
    throw new PolicyError('Key Derivation Error: salt inválido (se requieren 16 bytes).');
  }
  const material = buildKdfMaterial({ password, secondFactor, hardwareId });
  try {
    return crypto.scryptSync(material, salt, PRK_LEN, SCRYPT_PARAMS);
  } finally {
    // MIRAGE-015: el material contiene la contraseña en claro. Lo borramos
    // aunque el string original de JS siga siendo irrecuperable (limitación
    // del runtime, documentada en el README).
    material.fill(0);
  }
}

/**
 * Expande una subclave con dominio de separación explícito (HKDF-Expand).
 *
 * @param {Buffer} prk    PRK devuelto por deriveMasterKey.
 * @param {Buffer} salt   Salt del archivo (se reutiliza como HKDF salt).
 * @param {string} label  Etiqueta única e inequívoca de propósito.
 * @param {number} [len]  Longitud en bytes.
 */
export function deriveSubkey(prk, salt, label, len = SUBKEY_LEN) {
  if (!Buffer.isBuffer(prk) || prk.length !== PRK_LEN) {
    throw new PolicyError('Key Derivation Error: PRK inválido.');
  }
  if (typeof label !== 'string' || !label.startsWith('mirage/')) {
    throw new PolicyError('Key Derivation Error: label de subclave inválido.');
  }
  const out = crypto.hkdfSync('sha256', prk, salt, Buffer.from(label, 'utf8'), len);
  return Buffer.from(out);
}

/**
 * Sobrescribe con ceros uno o más buffers de material sensible.
 * MIRAGE-015. No es una garantía fuerte en un runtime con GC, pero reduce la
 * ventana de exposición en heap, swap y core dumps.
 */
export function wipe(...buffers) {
  for (const b of buffers) {
    if (Buffer.isBuffer(b)) {
      try { b.fill(0); } catch { /* buffer ya liberado o de solo lectura */ }
    } else if (b && typeof b === 'object') {
      for (const v of Object.values(b)) {
        if (Buffer.isBuffer(v)) {
          try { v.fill(0); } catch { /* idem */ }
        }
      }
    }
  }
}

/**
 * Política de contraseñas con estimación de entropía.
 * MIRAGE-013 (parcial) y MIRAGE-016: el original exigía solo 10 caracteres sin
 * ninguna comprobación de calidad, mientras el README hablaba de resistencia
 * offline. Un scrypt fuerte no compensa una contraseña de baja entropía.
 *
 * Nota honesta: esta es una heurística, NO una medida real de entropía. Sirve
 * para rechazar lo evidentemente débil, no para certificar fortaleza.
 */
export const MIN_PASSWORD_LENGTH = 12;

export function assessPasswordStrength(password) {
  if (typeof password !== 'string') return { ok: false, reason: 'no es una cadena', bits: 0 };
  if (password.length < MIN_PASSWORD_LENGTH) {
    return {
      ok: false,
      reason: `debe tener al menos ${MIN_PASSWORD_LENGTH} caracteres`,
      bits: 0,
    };
  }
  let pool = 0;
  if (/[a-z]/.test(password)) pool += 26;
  if (/[A-Z]/.test(password)) pool += 26;
  if (/[0-9]/.test(password)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(password)) pool += 33;

  const unique = new Set(password).size;
  // Penalizamos la repetición: "aaaaaaaaaaaa" tiene 12 caracteres y 1 símbolo único.
  const effectiveLen = Math.min(password.length, unique * 2);
  const bits = Math.floor(effectiveLen * Math.log2(Math.max(pool, 2)));

  if (unique < 6) {
    return { ok: false, reason: 'demasiados caracteres repetidos', bits };
  }
  if (bits < 50) {
    return {
      ok: false,
      reason: `entropía estimada insuficiente (~${bits} bits); combine mayúsculas, minúsculas, dígitos y símbolos`,
      bits,
    };
  }
  return { ok: true, bits };
}

export function requirePasswordPolicy(password, label = 'La contraseña maestra') {
  const verdict = assessPasswordStrength(password);
  if (!verdict.ok) {
    throw new PolicyError(`Password Policy Error: ${label} ${verdict.reason}.`);
  }
  return verdict;
}
