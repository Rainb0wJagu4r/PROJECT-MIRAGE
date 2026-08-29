/**
 * lib/legacy.js — Lector de SOLO LECTURA del formato v1 de Project Mirage.
 *
 * ¿Por qué existe este módulo?
 * ---------------------------------------------------------------------------
 * El formato v1 tiene fallos de diseño reales, documentados en la auditoría:
 *
 *   MIRAGE-002  La cascada Camellia-CTR → ARIA-CTR → ChaCha20 → GCM colapsa
 *               matemáticamente en un único XOR con un keystream combinado.
 *               Confirmado empíricamente: C1^C2 == P1^P2.
 *   MIRAGE-003  Las longitudes se escriben como `double` (writeDoubleBE) y no
 *               se validan: un cipherLen manipulado produce offsets negativos.
 *   MIRAGE-005  El AAD no cubre índice de bloque, número de bloques ni cipherLen.
 *   MIRAGE-006  Las 4 subclaves se obtienen troceando 128 bytes de scrypt.
 *   MIRAGE-007  La derivación concatena secretos con separadores de texto
 *               (`__SECSEC__`, `__HW__`), lo que permite colisiones de clave.
 *
 * NINGUNO de esos fallos se puede arreglar manteniendo compatibilidad de
 * escritura, porque están en el propio formato en disco. Por eso:
 *
 *   - Este módulo SOLO DESCIFRA. No existe ninguna función de cifrado v1.
 *   - El objetivo es que nadie pierda sus datos: se lee el archivo antiguo y se
 *     recomienda migrarlo a v2 (ver `migrateNotice`).
 *   - Todo lo que se lee aquí se valida con los mismos límites estrictos que
 *     v2, de modo que un archivo v1 manipulado no puede provocar lecturas
 *     fuera de rango (esto SÍ se puede corregir sin romper compatibilidad).
 *
 * Es decir: seguimos pudiendo abrir un archivo v1 legítimo, pero ya no
 * confiamos ciegamente en sus campos de longitud.
 */

import crypto from 'crypto';
import { OpaqueError } from './errors.js';

/** Parámetros scrypt originales de v1. NO CAMBIAR: definen el formato antiguo. */
const V1_SCRYPT = Object.freeze({
  N: 131072,
  r: 8,
  p: 1,
  maxmem: 256 * 1024 * 1024,
});

export const V1_MODES = Object.freeze({
  AES_SINGLE: 0x01,
  AES_DUAL: 0x02,
  C4_SINGLE: 0x03,
  C4_DUAL: 0x04,
});

/**
 * Derivación de clave v1 (vulnerable por concatenación, MIRAGE-007).
 * Se reproduce EXACTAMENTE como estaba para poder abrir archivos antiguos.
 */
export function deriveKeyV1(password, salt, hardwareLockEnabled, doubleFactorPassword = '', keySize = 32, hardwareId = '') {
  let combined = password;
  if (doubleFactorPassword) combined += '__SECSEC__' + doubleFactorPassword;
  if (hardwareLockEnabled) combined += '__HW__' + hardwareId;
  return crypto.scryptSync(combined, salt, keySize, V1_SCRYPT);
}

/**
 * Cascada v1 inversa (Camellia-CTR → ARIA-CTR → ChaCha20 → AES-GCM).
 * Reproducción literal del algoritmo original, solo para descifrar.
 */
function decryptMirageC4V1(ciphertext, key128, ivs, tag, header, salt) {
  const kCam = key128.subarray(0, 32);
  const kAri = key128.subarray(32, 64);
  const kCha = key128.subarray(64, 96);
  const kAes = key128.subarray(96, 128);

  const aad = Buffer.concat([
    header || Buffer.alloc(0),
    salt || Buffer.alloc(0),
    ivs.ivCamellia,
    ivs.ivAria,
    ivs.ivChaCha,
    ivs.ivAes,
  ]);

  const d4 = crypto.createDecipheriv('aes-256-gcm', kAes, ivs.ivAes);
  d4.setAuthTag(tag);
  d4.setAAD(aad);
  let state = Buffer.concat([d4.update(ciphertext), d4.final()]);

  const d3 = crypto.createDecipheriv('chacha20', kCha, ivs.ivChaCha);
  state = Buffer.concat([d3.update(state), d3.final()]);

  const d2 = crypto.createDecipheriv('aria-256-ctr', kAri, ivs.ivAria);
  state = Buffer.concat([d2.update(state), d2.final()]);

  const d1 = crypto.createDecipheriv('camellia-256-ctr', kCam, ivs.ivCamellia);
  return Buffer.concat([d1.update(state), d1.final()]);
}

function decryptAesV1(ciphertext, key, iv, tag, header) {
  const d = crypto.createDecipheriv('aes-256-gcm', key, iv);
  d.setAuthTag(tag);
  if (header) d.setAAD(header);
  return Buffer.concat([d.update(ciphertext), d.final()]);
}

/**
 * Lee una longitud v1 (double BE) y la valida con los límites que v1 nunca
 * comprobó (MIRAGE-003). Un archivo legítimo pasa; uno manipulado se rechaza.
 */
function readV1Length(buf, offset, remainingAfter) {
  if (offset + 8 > buf.length) {
    throw new OpaqueError('legacy v1: campo de longitud fuera del búfer');
  }
  const raw = buf.readDoubleBE(offset);
  if (!Number.isFinite(raw) || !Number.isInteger(raw) || raw < 0) {
    throw new OpaqueError(`legacy v1: longitud no entera o negativa (${raw})`);
  }
  if (raw > remainingAfter) {
    throw new OpaqueError(`legacy v1: longitud ${raw} excede los ${remainingAfter} bytes disponibles`);
  }
  return raw;
}

/** Extrae el payload adjunto a un portador (trailer MIRGSTEG) validando la longitud. */
export function stripLegacySteg(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 12) return { buffer, isSteg: false };
  if (buffer.subarray(-8).toString('ascii') !== 'MIRGSTEG') return { buffer, isSteg: false };

  const payloadLen = buffer.readUInt32BE(buffer.length - 12);
  const available = buffer.length - 12;
  // MIRAGE-003: v1 no validaba esto y producía offsets negativos.
  if (payloadLen === 0 || payloadLen > available) {
    throw new OpaqueError(`legacy steg: payloadLen ${payloadLen} inválido (disponible ${available})`);
  }
  return {
    buffer: buffer.subarray(available - payloadLen, available),
    isSteg: true,
  };
}

/** Deserializador de payload v1, con validación estricta de longitudes. */
export function deserializePayloadV1(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 18) {
    throw new OpaqueError('legacy v1: payload demasiado corto');
  }
  const expirationTime = buffer.readDoubleBE(0);
  const filenameLen = buffer.readUInt16BE(8);
  if (10 + filenameLen + 8 > buffer.length) {
    throw new OpaqueError('legacy v1: filenameLen fuera de rango');
  }
  const filename = buffer.toString('utf8', 10, 10 + filenameLen);
  const sizeOffset = 10 + filenameLen;
  const fileSize = buffer.readDoubleBE(sizeOffset);
  const dataStart = sizeOffset + 8;
  if (!Number.isFinite(fileSize) || !Number.isInteger(fileSize) || fileSize < 0
      || dataStart + fileSize > buffer.length) {
    throw new OpaqueError('legacy v1: fileSize fuera de rango');
  }
  return {
    expirationTime: Number.isFinite(expirationTime) ? expirationTime : 0,
    filename,
    fileData: buffer.subarray(dataStart, dataStart + fileSize),
  };
}

/**
 * Descifra un archivo v1 completo.
 *
 * A diferencia del server.js original, aquí se prueban AMBOS estados del
 * hardware-lock también para el bloque señuelo (MIRAGE-004): en v1 el flag no
 * está en el archivo, así que probar los dos estados es la ÚNICA forma de
 * abrirlo. Es una limitación heredada del formato, no una decisión nueva.
 *
 * @returns {{payload: Buffer, mode: number, isDuress: boolean, hardwareLockUsed: boolean}}
 */
export function decryptLegacyV1(buffer, { password, secondFactor = '', hardwareId = '' }) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 8) {
    throw new OpaqueError('legacy v1: archivo demasiado corto');
  }
  if (buffer.subarray(0, 6).toString('binary') !== 'MIRAGE') {
    throw new OpaqueError('legacy v1: magic incorrecto');
  }
  const version = buffer[6];
  const mode = buffer[7];
  if (version !== 1) {
    throw new OpaqueError(`legacy v1: versión no soportada (${version})`);
  }
  const header = buffer.subarray(0, 8);

  const tryAes = (salt, iv, tag, ct, hw) => {
    try {
      const key = deriveKeyV1(password, salt, hw, secondFactor, 32, hardwareId);
      try { return decryptAesV1(ct, key, iv, tag, header); } finally { key.fill(0); }
    } catch { return null; }
  };
  const tryC4 = (salt, ivs, tag, ct, hw) => {
    try {
      const key = deriveKeyV1(password, salt, hw, secondFactor, 128, hardwareId);
      try { return decryptMirageC4V1(ct, key, ivs, tag, header, salt); } finally { key.fill(0); }
    } catch { return null; }
  };

  // Si no hay hardwareId disponible, no tiene sentido probar el estado hw=true.
  const hwStates = hardwareId ? [true, false] : [false];

  const parseAesBlock = (off) => {
    if (off + 16 + 12 + 16 + 8 > buffer.length) {
      throw new OpaqueError('legacy v1: cabecera de bloque AES truncada');
    }
    const salt = buffer.subarray(off, off + 16); off += 16;
    const iv = buffer.subarray(off, off + 12); off += 12;
    const tag = buffer.subarray(off, off + 16); off += 16;
    const len = readV1Length(buffer, off, buffer.length - (off + 8)); off += 8;
    return { salt, iv, tag, ciphertext: buffer.subarray(off, off + len), nextOffset: off + len };
  };

  const parseC4Block = (off) => {
    if (off + 16 + 16 + 16 + 16 + 12 + 16 + 8 > buffer.length) {
      throw new OpaqueError('legacy v1: cabecera de bloque C4 truncada');
    }
    const salt = buffer.subarray(off, off + 16); off += 16;
    const ivCamellia = buffer.subarray(off, off + 16); off += 16;
    const ivAria = buffer.subarray(off, off + 16); off += 16;
    const ivChaCha = buffer.subarray(off, off + 16); off += 16;
    const ivAes = buffer.subarray(off, off + 12); off += 12;
    const tag = buffer.subarray(off, off + 16); off += 16;
    const len = readV1Length(buffer, off, buffer.length - (off + 8)); off += 8;
    return {
      salt,
      ivs: { ivCamellia, ivAria, ivChaCha, ivAes },
      tag,
      ciphertext: buffer.subarray(off, off + len),
      nextOffset: off + len,
    };
  };

  let payload = null;
  let isDuress = false;
  let hardwareLockUsed = false;

  if (mode === V1_MODES.AES_SINGLE) {
    const b = parseAesBlock(8);
    for (const hw of hwStates) {
      payload = tryAes(b.salt, b.iv, b.tag, b.ciphertext, hw);
      if (payload) { hardwareLockUsed = hw; break; }
    }
  } else if (mode === V1_MODES.AES_DUAL) {
    const b1 = parseAesBlock(8);
    const b2 = parseAesBlock(b1.nextOffset);
    for (const hw of hwStates) {
      payload = tryAes(b1.salt, b1.iv, b1.tag, b1.ciphertext, hw);
      if (payload) { hardwareLockUsed = hw; break; }
    }
    if (!payload) {
      // MIRAGE-004: probamos también hw=true en el señuelo. El server v1 solo
      // probaba hw=false, lo que hacía el modo duress inservible con hw-lock.
      for (const hw of hwStates) {
        payload = tryAes(b2.salt, b2.iv, b2.tag, b2.ciphertext, hw);
        if (payload) { hardwareLockUsed = hw; isDuress = true; break; }
      }
    }
  } else if (mode === V1_MODES.C4_SINGLE) {
    const b = parseC4Block(8);
    for (const hw of hwStates) {
      payload = tryC4(b.salt, b.ivs, b.tag, b.ciphertext, hw);
      if (payload) { hardwareLockUsed = hw; break; }
    }
  } else if (mode === V1_MODES.C4_DUAL) {
    const b1 = parseC4Block(8);
    const b2 = parseC4Block(b1.nextOffset);
    for (const hw of hwStates) {
      payload = tryC4(b1.salt, b1.ivs, b1.tag, b1.ciphertext, hw);
      if (payload) { hardwareLockUsed = hw; break; }
    }
    if (!payload) {
      for (const hw of hwStates) {
        payload = tryC4(b2.salt, b2.ivs, b2.tag, b2.ciphertext, hw);
        if (payload) { hardwareLockUsed = hw; isDuress = true; break; }
      }
    }
  } else {
    throw new OpaqueError(`legacy v1: modo desconocido (${mode})`);
  }

  if (!payload) {
    throw new OpaqueError('legacy v1: autenticación fallida en todos los bloques');
  }
  return { payload, mode, isDuress, hardwareLockUsed };
}

/** Aviso que la API devuelve al abrir un archivo v1. */
export const migrateNotice =
  'Este archivo usa el formato v1, cuyo cifrado en cascada es demostrablemente '
  + 'equivalente a un solo cifrado de flujo (hallazgo MIRAGE-002) y cuya derivación '
  + 'de clave admite colisiones (MIRAGE-007). Se ha descifrado para que no pierdas '
  + 'los datos, pero deberías volver a cifrarlo con el formato v2.';

/** Detecta si un búfer es un archivo v1 (tras quitar un posible portador). */
export function isLegacyV1(buffer) {
  return Buffer.isBuffer(buffer)
    && buffer.length >= 8
    && buffer.subarray(0, 6).toString('binary') === 'MIRAGE'
    && buffer[6] === 1;
}
