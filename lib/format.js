/**
 * lib/format.js — Serializador y parser del formato de archivo Mirage v2.
 *
 * CORRIGE:
 *   MIRAGE-003  Todas las longitudes son enteros sin signo de 64 bits
 *               (BigUInt64BE) y CADA una se valida contra el tamaño real del
 *               búfer ANTES de hacer cualquier subarray. En v1 se usaban
 *               `double` sin validar, lo que producía offsets negativos
 *               (verificado: offset -4294966965) que `subarray` silenciaba.
 *   MIRAGE-005  El envelope declara mode, flags, blockIndex y blockCount, y
 *               todos ellos entran en el AAD de cada bloque (ver cascade.js).
 *   MIRAGE-013  Un bit de `flags` indica si se usó hardware-lock, de modo que
 *               al descifrar se deriva la clave UNA vez en lugar de probar dos
 *               estados (v1 ejecutaba scrypt 2 veces: ~870 ms y 2x128 MB).
 *
 * ESTRUCTURA DEL ARCHIVO v2
 * ---------------------------------------------------------------------------
 *   Cabecera fija (12 bytes):
 *     [0..3]   magic  = "MIRG"            (4 B ASCII)
 *     [4]      version = 2                (1 B)
 *     [5]      mode                       (1 B) ver MODES
 *     [6]      flags                      (1 B) ver FLAGS
 *     [7]      blockCount                 (1 B) 1 o 2
 *     [8]      kdfId                      (1 B) 1 = scrypt(N=2^17,r=8,p=1)+HKDF
 *     [9]      cipherId                   (1 B) 1 = cascada C4 v2, 2 = AES-GCM
 *     [10..11] reserved = 0x0000          (2 B) alineación / uso futuro
 *
 *   Por cada bloque i (i = 0..blockCount-1):
 *     salt            16 B
 *     ivCamellia      16 B
 *     nonceChaCha     12 B
 *     ivAria          16 B
 *     ivAes           12 B
 *     tag             16 B
 *     cipherLen        8 B   (BigUInt64BE)
 *     ciphertext   cipherLen B
 *
 *   Nota: los IVs de Camellia/ChaCha/ARIA se escriben incluso en modo AES-GCM
 *   simple. Cuestan 44 bytes y hacen que el tamaño de la cabecera NO revele
 *   qué algoritmo se usó. Es una decisión deliberada de uniformidad; los
 *   campos no usados se rellenan con bytes aleatorios, no con ceros, para que
 *   no sean distinguibles.
 *
 *   Payload interno (ya cifrado, se define aquí porque es parte del formato):
 *     [0..7]    expirationTime   BigUInt64BE (ms epoch, 0 = sin TTL)
 *     [8..9]    filenameLen      UInt16BE
 *     [10..]    filename         UTF-8
 *     [+0..7]   fileSize         BigUInt64BE
 *     [+8..]    contenido
 */

import crypto from 'crypto';
import { OpaqueError } from './errors.js';
import { SIZES } from './cascade.js';

export const MAGIC = 'MIRG';
export const VERSION = 2;

export const MODES = Object.freeze({
  SINGLE: 0x11, // un bloque
  DURESS: 0x12, // dos bloques: [0] real, [1] señuelo
  VAULT: 0x13,  // un bloque cuyo payload es un multi-archivo (MIRG_VAULT)
});

export const FLAGS = Object.freeze({
  HARDWARE_LOCK: 0x01,
  SECOND_FACTOR: 0x02,
  BUCKET_PADDING: 0x04,
});

export const CIPHER_IDS = Object.freeze({
  CASCADE_C4_V2: 1,
  AES_GCM: 2,
});

export const KDF_IDS = Object.freeze({
  SCRYPT_HKDF_V2: 1,
});

export const HEADER_LEN = 12;
const LEN_FIELD = 8;
const BLOCK_META_LEN =
  SIZES.SALT + SIZES.IV_CAMELLIA + SIZES.NONCE_CHACHA + SIZES.IV_ARIA
  + SIZES.IV_AES + SIZES.TAG + LEN_FIELD; // = 96

/** Límite superior defensivo: 8 GiB por bloque. */
const MAX_CIPHER_LEN = 8n * 1024n * 1024n * 1024n;

/** Límite defensivo para el nombre de archivo dentro del payload. */
const MAX_FILENAME_LEN = 4096;

export const FORMAT_CONSTANTS = Object.freeze({
  MAGIC, VERSION, HEADER_LEN, BLOCK_META_LEN, MAX_CIPHER_LEN, MAX_FILENAME_LEN,
});

// ---------------------------------------------------------------------------
// Lectura segura de primitivas
// ---------------------------------------------------------------------------

/**
 * Lee un uint64 BE y lo devuelve como Number, verificando ANTES de nada que
 * quepa en el búfer y que el valor sea representable y esté acotado.
 * Nunca devuelve un valor que provoque un subarray fuera de rango.
 */
function readLength(buf, offset, availableAfter) {
  if (offset < 0 || offset + LEN_FIELD > buf.length) {
    throw new OpaqueError(`format: campo de longitud en offset ${offset} fuera del búfer (${buf.length})`);
  }
  const raw = buf.readBigUInt64BE(offset);
  if (raw > MAX_CIPHER_LEN) {
    throw new OpaqueError(`format: longitud declarada ${raw} supera el máximo permitido`);
  }
  if (raw > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new OpaqueError('format: longitud no representable de forma exacta');
  }
  const len = Number(raw);
  if (len > availableAfter) {
    throw new OpaqueError(`format: longitud declarada ${len} excede los ${availableAfter} bytes disponibles`);
  }
  return len;
}

/** subarray con comprobación explícita de límites. */
function slice(buf, offset, len, label) {
  if (offset < 0 || len < 0 || offset + len > buf.length) {
    throw new OpaqueError(`format: campo "${label}" [${offset},${offset + len}) fuera del búfer (${buf.length})`);
  }
  return buf.subarray(offset, offset + len);
}

// ---------------------------------------------------------------------------
// Payload interno
// ---------------------------------------------------------------------------

/**
 * Serializa el payload de un archivo. Todas las longitudes son enteros.
 * @param {string} filename
 * @param {Buffer} fileBuffer
 * @param {number} expirationTime ms epoch, 0 = sin TTL
 */
export function serializePayload(filename, fileBuffer, expirationTime = 0) {
  const nameBuf = Buffer.from(String(filename), 'utf8');
  if (nameBuf.length === 0) {
    throw new OpaqueError('format: nombre de archivo vacío');
  }
  if (nameBuf.length > MAX_FILENAME_LEN) {
    throw new OpaqueError(`format: nombre de archivo demasiado largo (${nameBuf.length} B)`);
  }
  const exp = Math.max(0, Math.floor(Number(expirationTime) || 0));

  const head = Buffer.alloc(8 + 2 + nameBuf.length + 8);
  head.writeBigUInt64BE(BigInt(exp), 0);
  head.writeUInt16BE(nameBuf.length, 8);
  nameBuf.copy(head, 10);
  head.writeBigUInt64BE(BigInt(fileBuffer.length), 10 + nameBuf.length);

  return Buffer.concat([head, fileBuffer]);
}

/**
 * Deserializa el payload validando cada campo antes de usarlo.
 * Lanza siempre OpaqueError: el mensaje público es idéntico para todos los
 * fallos, de modo que no hay oráculo de parsing (MIRAGE-008).
 */
export function deserializePayload(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length < 18) {
    throw new OpaqueError(`format: payload demasiado corto (${buffer?.length ?? 'n/a'} B, mínimo 18)`);
  }

  const expRaw = buffer.readBigUInt64BE(0);
  if (expRaw > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new OpaqueError('format: expirationTime no representable');
  }
  const expirationTime = Number(expRaw);

  const nameLen = buffer.readUInt16BE(8);
  if (nameLen === 0) {
    throw new OpaqueError('format: filenameLen = 0');
  }
  if (nameLen > MAX_FILENAME_LEN) {
    throw new OpaqueError(`format: filenameLen ${nameLen} supera el máximo`);
  }
  // Debe caber el nombre Y el campo fileSize de 8 bytes que le sigue.
  if (10 + nameLen + 8 > buffer.length) {
    throw new OpaqueError(`format: filenameLen ${nameLen} no cabe en el payload`);
  }

  const nameBuf = slice(buffer, 10, nameLen, 'filename');
  if (nameBuf.includes(0x00)) {
    throw new OpaqueError('format: el nombre de archivo contiene un byte NUL');
  }
  const filename = nameBuf.toString('utf8');

  const sizeOffset = 10 + nameLen;
  const dataStart = sizeOffset + LEN_FIELD;
  const fileSize = readLength(buffer, sizeOffset, buffer.length - dataStart);
  const fileData = slice(buffer, dataStart, fileSize, 'fileData');

  return { expirationTime, filename, fileData };
}

// ---------------------------------------------------------------------------
// Envelope v2
// ---------------------------------------------------------------------------

/** Construye la cabecera fija de 12 bytes. */
export function buildHeader({ mode, flags = 0, blockCount, cipherId, kdfId = KDF_IDS.SCRYPT_HKDF_V2 }) {
  if (!Object.values(MODES).includes(mode)) {
    throw new OpaqueError(`format: modo inválido (0x${mode.toString(16)})`);
  }
  if (blockCount !== 1 && blockCount !== 2) {
    throw new OpaqueError(`format: blockCount inválido (${blockCount})`);
  }
  if (!Object.values(CIPHER_IDS).includes(cipherId)) {
    throw new OpaqueError(`format: cipherId inválido (${cipherId})`);
  }
  const h = Buffer.alloc(HEADER_LEN, 0);
  Buffer.from(MAGIC, 'ascii').copy(h, 0);
  h.writeUInt8(VERSION, 4);
  h.writeUInt8(mode, 5);
  h.writeUInt8(flags & 0xff, 6);
  h.writeUInt8(blockCount, 7);
  h.writeUInt8(kdfId, 8);
  h.writeUInt8(cipherId, 9);
  // [10..11] reservados a 0.
  return h;
}

/** Parsea y valida la cabecera. */
export function parseHeader(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length < HEADER_LEN) {
    throw new OpaqueError(`format: archivo demasiado corto para la cabecera (${buffer?.length ?? 'n/a'} B)`);
  }
  if (buffer.subarray(0, 4).toString('ascii') !== MAGIC) {
    throw new OpaqueError('format: magic incorrecto (no es un archivo Mirage v2)');
  }
  const version = buffer.readUInt8(4);
  if (version !== VERSION) {
    throw new OpaqueError(`format: versión no soportada (${version})`);
  }
  const mode = buffer.readUInt8(5);
  if (!Object.values(MODES).includes(mode)) {
    throw new OpaqueError(`format: modo desconocido (0x${mode.toString(16)})`);
  }
  const flags = buffer.readUInt8(6);
  const knownFlags = FLAGS.HARDWARE_LOCK | FLAGS.SECOND_FACTOR | FLAGS.BUCKET_PADDING;
  if (flags & ~knownFlags) {
    throw new OpaqueError(`format: flags desconocidos (0x${flags.toString(16)})`);
  }
  const blockCount = buffer.readUInt8(7);
  if (blockCount !== 1 && blockCount !== 2) {
    throw new OpaqueError(`format: blockCount inválido (${blockCount})`);
  }
  if (mode === MODES.DURESS && blockCount !== 2) {
    throw new OpaqueError('format: el modo duress exige exactamente 2 bloques');
  }
  if (mode !== MODES.DURESS && blockCount !== 1) {
    throw new OpaqueError(`format: el modo 0x${mode.toString(16)} exige exactamente 1 bloque`);
  }
  const kdfId = buffer.readUInt8(8);
  if (!Object.values(KDF_IDS).includes(kdfId)) {
    throw new OpaqueError(`format: kdfId desconocido (${kdfId})`);
  }
  const cipherId = buffer.readUInt8(9);
  if (!Object.values(CIPHER_IDS).includes(cipherId)) {
    throw new OpaqueError(`format: cipherId desconocido (${cipherId})`);
  }
  if (buffer.readUInt16BE(10) !== 0) {
    throw new OpaqueError('format: bytes reservados distintos de cero');
  }
  return { version, mode, flags, blockCount, kdfId, cipherId };
}

/**
 * Serializa un bloque completo.
 * @param {{salt:Buffer, ivs:object, tag:Buffer, ciphertext:Buffer}} block
 */
export function serializeBlock(block) {
  const { salt, ivs, tag, ciphertext } = block;
  const expect = (b, n, name) => {
    if (!Buffer.isBuffer(b) || b.length !== n) {
      throw new OpaqueError(`format: campo "${name}" debe medir ${n} B (mide ${b?.length ?? 'n/a'})`);
    }
    return b;
  };
  const lenBuf = Buffer.alloc(LEN_FIELD);
  lenBuf.writeBigUInt64BE(BigInt(ciphertext.length));

  return Buffer.concat([
    expect(salt, SIZES.SALT, 'salt'),
    expect(ivs.ivCamellia, SIZES.IV_CAMELLIA, 'ivCamellia'),
    expect(ivs.nonceChaCha, SIZES.NONCE_CHACHA, 'nonceChaCha'),
    expect(ivs.ivAria, SIZES.IV_ARIA, 'ivAria'),
    expect(ivs.ivAes, SIZES.IV_AES, 'ivAes'),
    expect(tag, SIZES.TAG, 'tag'),
    lenBuf,
    ciphertext,
  ]);
}

/**
 * Parsea un bloque en `offset`, validando cada campo.
 * @returns {{salt, ivs, tag, ciphertext, cipherLen, nextOffset}}
 */
export function parseBlock(buffer, offset, label = 'bloque') {
  if (offset + BLOCK_META_LEN > buffer.length) {
    throw new OpaqueError(
      `format: ${label}: faltan bytes para la metainformación `
      + `(necesita ${BLOCK_META_LEN}, hay ${buffer.length - offset})`
    );
  }
  let o = offset;
  const salt = slice(buffer, o, SIZES.SALT, `${label}.salt`); o += SIZES.SALT;
  const ivCamellia = slice(buffer, o, SIZES.IV_CAMELLIA, `${label}.ivCamellia`); o += SIZES.IV_CAMELLIA;
  const nonceChaCha = slice(buffer, o, SIZES.NONCE_CHACHA, `${label}.nonceChaCha`); o += SIZES.NONCE_CHACHA;
  const ivAria = slice(buffer, o, SIZES.IV_ARIA, `${label}.ivAria`); o += SIZES.IV_ARIA;
  const ivAes = slice(buffer, o, SIZES.IV_AES, `${label}.ivAes`); o += SIZES.IV_AES;
  const tag = slice(buffer, o, SIZES.TAG, `${label}.tag`); o += SIZES.TAG;

  // Disponible DESPUÉS de consumir el propio campo de longitud.
  const cipherLen = readLength(buffer, o, buffer.length - (o + LEN_FIELD));
  o += LEN_FIELD;

  const ciphertext = slice(buffer, o, cipherLen, `${label}.ciphertext`);
  return {
    salt,
    ivs: { ivCamellia, nonceChaCha, ivAria, ivAes },
    tag,
    ciphertext,
    cipherLen,
    nextOffset: o + cipherLen,
  };
}

/**
 * Ensambla el archivo completo.
 * @param {object} headerInfo  {mode, flags, blockCount, cipherId}
 * @param {Array}  blocks
 */
export function serializeEnvelope(headerInfo, blocks) {
  if (blocks.length !== headerInfo.blockCount) {
    throw new OpaqueError(
      `format: blockCount declarado (${headerInfo.blockCount}) != bloques dados (${blocks.length})`
    );
  }
  return Buffer.concat([buildHeader(headerInfo), ...blocks.map(serializeBlock)]);
}

/**
 * Parsea el archivo completo y verifica que no queden bytes sobrantes.
 *
 * La comprobación de bytes sobrantes es importante: sin ella se puede añadir
 * datos al final del archivo sin que nada lo detecte (los bloques individuales
 * seguirían autenticando). Con ella, cualquier append se rechaza.
 */
export function parseEnvelope(buffer) {
  const header = parseHeader(buffer);
  const blocks = [];
  let offset = HEADER_LEN;
  for (let i = 0; i < header.blockCount; i++) {
    const b = parseBlock(buffer, offset, `bloque ${i}`);
    blocks.push(b);
    offset = b.nextOffset;
  }
  if (offset !== buffer.length) {
    throw new OpaqueError(
      `format: ${buffer.length - offset} bytes sobrantes tras el último bloque `
      + '(archivo truncado, extendido o manipulado)'
    );
  }
  return { header, blocks, headerBuf: buffer.subarray(0, HEADER_LEN) };
}

// ---------------------------------------------------------------------------
// Encapsulado en portador (trailer)
// ---------------------------------------------------------------------------

const STEG_MAGIC = 'MIRGSTG2';
const STEG_TRAILER_LEN = 8 + 8; // uint64 payloadLen + magic

/** Adjunta el envelope al final de un portador, con longitud de 64 bits. */
export function appendToCarrier(carrierBuffer, envelope) {
  const lenBuf = Buffer.alloc(8);
  lenBuf.writeBigUInt64BE(BigInt(envelope.length));
  return Buffer.concat([carrierBuffer, envelope, lenBuf, Buffer.from(STEG_MAGIC, 'ascii')]);
}

/**
 * Extrae el envelope de un portador, validando la longitud (MIRAGE-003).
 * @returns {{buffer: Buffer, isSteg: boolean}}
 */
export function extractFromCarrier(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length < STEG_TRAILER_LEN) {
    return { buffer, isSteg: false };
  }
  if (buffer.subarray(-8).toString('ascii') !== STEG_MAGIC) {
    return { buffer, isSteg: false };
  }
  const available = buffer.length - STEG_TRAILER_LEN;
  const raw = buffer.readBigUInt64BE(buffer.length - STEG_TRAILER_LEN);
  if (raw === 0n || raw > BigInt(available)) {
    throw new OpaqueError(`steg: payloadLen ${raw} inválido (disponible ${available})`);
  }
  const len = Number(raw);
  return { buffer: buffer.subarray(available - len, available), isSteg: true };
}

// ---------------------------------------------------------------------------
// Multi-archivo (bóveda de emergencia)
// ---------------------------------------------------------------------------

const VAULT_MAGIC = 'MIRG_VLT2';

/**
 * Serializa varios archivos en un solo payload.
 * Cada entrada: [relPathLen uint16][relPath][size uint64][contenido]
 */
export function serializeMultiPayload(filesList, expirationTime = 0) {
  const chunks = [];
  const head = Buffer.alloc(VAULT_MAGIC.length + 8 + 4);
  let o = 0;
  Buffer.from(VAULT_MAGIC, 'ascii').copy(head, o); o += VAULT_MAGIC.length;
  head.writeBigUInt64BE(BigInt(Math.max(0, Math.floor(Number(expirationTime) || 0))), o); o += 8;
  head.writeUInt32BE(filesList.length, o);
  chunks.push(head);

  for (const f of filesList) {
    const relBuf = Buffer.from(f.relPath, 'utf8');
    if (relBuf.length === 0 || relBuf.length > MAX_FILENAME_LEN) {
      throw new OpaqueError(`format: relPath de longitud inválida (${relBuf.length})`);
    }
    const meta = Buffer.alloc(2 + relBuf.length + 8);
    meta.writeUInt16BE(relBuf.length, 0);
    relBuf.copy(meta, 2);
    meta.writeBigUInt64BE(BigInt(f.content.length), 2 + relBuf.length);
    chunks.push(meta, f.content);
  }
  return Buffer.concat(chunks);
}

/** Deserializa el payload multi-archivo con validación estricta. */
export function deserializeMultiPayload(buffer) {
  const minHead = VAULT_MAGIC.length + 8 + 4;
  if (!Buffer.isBuffer(buffer) || buffer.length < minHead) {
    throw new OpaqueError('format: payload de bóveda demasiado corto');
  }
  if (buffer.subarray(0, VAULT_MAGIC.length).toString('ascii') !== VAULT_MAGIC) {
    throw new OpaqueError('format: magic de bóveda incorrecto');
  }
  let o = VAULT_MAGIC.length;
  const expRaw = buffer.readBigUInt64BE(o); o += 8;
  if (expRaw > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new OpaqueError('format: expirationTime de bóveda no representable');
  }
  const count = buffer.readUInt32BE(o); o += 4;

  // Cota superior: cada entrada ocupa al menos 2+1+8 bytes.
  if (count > Math.floor((buffer.length - minHead) / 11) + 1) {
    throw new OpaqueError(`format: número de archivos declarado (${count}) imposible para el tamaño del payload`);
  }

  const files = [];
  for (let i = 0; i < count; i++) {
    if (o + 2 > buffer.length) {
      throw new OpaqueError(`format: bóveda truncada en la entrada ${i}`);
    }
    const relLen = buffer.readUInt16BE(o); o += 2;
    if (relLen === 0 || relLen > MAX_FILENAME_LEN) {
      throw new OpaqueError(`format: relPathLen inválido en la entrada ${i} (${relLen})`);
    }
    if (o + relLen + LEN_FIELD > buffer.length) {
      throw new OpaqueError(`format: bóveda truncada en el relPath de la entrada ${i}`);
    }
    const relBuf = slice(buffer, o, relLen, `vault[${i}].relPath`); o += relLen;
    if (relBuf.includes(0x00)) {
      throw new OpaqueError(`format: relPath con NUL en la entrada ${i}`);
    }
    const relPath = relBuf.toString('utf8');

    const size = readLength(buffer, o, buffer.length - (o + LEN_FIELD)); o += LEN_FIELD;
    const content = slice(buffer, o, size, `vault[${i}].content`); o += size;
    files.push({ relPath, content });
  }
  if (o !== buffer.length) {
    throw new OpaqueError(`format: ${buffer.length - o} bytes sobrantes en el payload de bóveda`);
  }
  return { expirationTime: Number(expRaw), files };
}

/** Detecta si un payload descifrado es una bóveda multi-archivo. */
export function isMultiPayload(buffer) {
  return Buffer.isBuffer(buffer)
    && buffer.length >= VAULT_MAGIC.length
    && buffer.subarray(0, VAULT_MAGIC.length).toString('ascii') === VAULT_MAGIC;
}

/**
 * Lee el TTL de un payload SIN devolver los datos.
 * Permite comprobar la expiración antes de escribir nada en disco (MIRAGE-010).
 */
export function peekExpiration(payload) {
  if (!Buffer.isBuffer(payload)) return 0;
  if (isMultiPayload(payload)) {
    if (payload.length < VAULT_MAGIC.length + 8) return 0;
    const raw = payload.readBigUInt64BE(VAULT_MAGIC.length);
    return raw > BigInt(Number.MAX_SAFE_INTEGER) ? 0 : Number(raw);
  }
  if (payload.length < 8) return 0;
  const raw = payload.readBigUInt64BE(0);
  return raw > BigInt(Number.MAX_SAFE_INTEGER) ? 0 : Number(raw);
}

/** Genera bytes aleatorios para los campos de IV no usados por el algoritmo. */
export function randomUnusedIvs() {
  return {
    ivCamellia: crypto.randomBytes(SIZES.IV_CAMELLIA),
    nonceChaCha: crypto.randomBytes(SIZES.NONCE_CHACHA),
    ivAria: crypto.randomBytes(SIZES.IV_ARIA),
    ivAes: crypto.randomBytes(SIZES.IV_AES),
  };
}
