/**
 * lib/vault.js — Orquestación de alto nivel: cifrar y descifrar un archivo
 * Mirage completo. Es la única capa que server.js necesita para el núcleo
 * criptográfico.
 *
 * Aquí se resuelven, de forma centralizada:
 *
 *   MIRAGE-004  El modo duress ya funciona con hardware-lock. El flag va en la
 *               cabecera, así que ambos bloques se derivan con el MISMO estado
 *               de hardware. En v1 el señuelo solo se probaba con hw=false, lo
 *               que hacía el modo inservible cuando el hw-lock estaba activo.
 *   MIRAGE-010  El TTL se comprueba ANTES de devolver los datos al llamante,
 *               leyendo la marca de expiración sin exponer el contenido.
 *               (Sigue siendo una limitación honesta: el descifrado ya ocurrió
 *               en RAM. El TTL es una política de uso, no un control criptográfico.)
 *   MIRAGE-013  scrypt se ejecuta UNA sola vez por intento, porque el flag de
 *               hardware-lock está en la cabecera en claro y autenticado en el AAD.
 *
 * Sobre el orden duress: se prueba primero el bloque real y luego el señuelo.
 * Ambos usan el mismo formato y el mismo tamaño de metainformación, así que un
 * observador del archivo no puede saber cuál es cuál.
 */

import crypto from 'crypto';
import { OpaqueError, PolicyError } from './errors.js';
import { deriveMasterKey, wipe, requirePasswordPolicy } from './kdf.js';
import {
  generateIvs, encryptCascade, decryptCascade, encryptSingle, decryptSingle,
} from './cascade.js';
import {
  MAGIC, VERSION, MODES, FLAGS, CIPHER_IDS,
  serializeEnvelope, parseEnvelope, peekExpiration,
} from './format.js';
import { applyBucketPadding, stripBucketPadding } from './padding.js';

/** Algoritmos aceptados en la API pública. */
export const ALGORITHMS = Object.freeze({
  CASCADE: 'mirage-c4',
  AES: 'aes-256-gcm',
});

function cipherIdFor(algorithm) {
  if (algorithm === ALGORITHMS.CASCADE) return CIPHER_IDS.CASCADE_C4_V2;
  if (algorithm === ALGORITHMS.AES) return CIPHER_IDS.AES_GCM;
  throw new PolicyError(`Algoritmo no soportado: ${algorithm}`);
}

/**
 * Cuántos bytes añade cada algoritmo por encima de su entrada.
 *
 * La cascada v2 pasa por dos capas CBC. Con una entrada múltiplo de 16, PKCS#7
 * añade un bloque completo de 16 bytes en cada una: 32 en total. AES-GCM no
 * añade nada (el tag va aparte, en su propio campo del formato).
 *
 * El padding por buckets usa este valor para que el tamaño FINAL caiga en el
 * bucket, de forma que el tamaño del archivo no revele ni el tamaño real del
 * original ni qué algoritmo se empleó.
 */
function cipherExpansion(cipherId) {
  return cipherId === CIPHER_IDS.CASCADE_C4_V2 ? 32 : 0;
}

function encryptWith(cipherId, plaintext, prk, salt, ivs, aadCtx) {
  return cipherId === CIPHER_IDS.CASCADE_C4_V2
    ? encryptCascade(plaintext, prk, salt, ivs, aadCtx)
    : encryptSingle(plaintext, prk, salt, ivs, aadCtx);
}

function decryptWith(cipherId, ciphertext, prk, salt, ivs, tag, aadCtx) {
  return cipherId === CIPHER_IDS.CASCADE_C4_V2
    ? decryptCascade(ciphertext, prk, salt, ivs, tag, aadCtx)
    : decryptSingle(ciphertext, prk, salt, ivs, tag, aadCtx);
}

/**
 * Cifra un payload (ya serializado) y devuelve el archivo completo.
 *
 * @param {object} opts
 * @param {Buffer} opts.payload           payload principal serializado
 * @param {Buffer} [opts.decoyPayload]    payload señuelo (activa modo duress)
 * @param {string} opts.password
 * @param {string} [opts.secondFactor]
 * @param {string} [opts.duressPassword]
 * @param {string} [opts.hardwareId]      '' = sin hardware-lock
 * @param {string} [opts.algorithm]
 * @param {boolean} [opts.bucketPadding]
 * @param {boolean} [opts.isVault]
 * @returns {{envelope: Buffer, flags: number, mode: number}}
 */
export function encryptVault({
  payload,
  decoyPayload = null,
  password,
  secondFactor = '',
  duressPassword = '',
  hardwareId = '',
  algorithm = ALGORITHMS.CASCADE,
  bucketPadding = true,
  isVault = false,
}) {
  requirePasswordPolicy(password, 'La contraseña maestra');
  if (secondFactor) requirePasswordPolicy(secondFactor, 'El secreto secundario');
  if (decoyPayload) {
    if (!duressPassword) {
      throw new PolicyError('El modo duress requiere una contraseña señuelo.');
    }
    requirePasswordPolicy(duressPassword, 'La contraseña señuelo');
    if (duressPassword === password) {
      throw new PolicyError('La contraseña señuelo debe ser distinta de la principal.');
    }
    if (secondFactor && duressPassword === secondFactor) {
      throw new PolicyError('La contraseña señuelo debe ser distinta del secreto secundario.');
    }
  }

  const cipherId = cipherIdFor(algorithm);
  const mode = decoyPayload ? MODES.DURESS : (isVault ? MODES.VAULT : MODES.SINGLE);
  const blockCount = decoyPayload ? 2 : 1;

  let flags = 0;
  if (hardwareId) flags |= FLAGS.HARDWARE_LOCK;
  if (secondFactor) flags |= FLAGS.SECOND_FACTOR;
  if (bucketPadding) flags |= FLAGS.BUCKET_PADDING;

  // El padding se aplica al payload, DENTRO del cifrado, para que el tamaño
  // real quede oculto tanto al observador del archivo como al del ciphertext.
  //
  // applyBucketPadding SIEMPRE añade el prefijo de longitud de 8 bytes, incluso
  // con bucketPadding=false (en ese caso el relleno mide 0). Así el formato del
  // payload interno es uno solo y el descifrado no depende del flag para saber
  // dónde empiezan los datos: eliminar esa dependencia evitó un desalineamiento
  // de 8 bytes que sí se produjo durante el desarrollo.
  const expansion = cipherExpansion(cipherId);
  const inputs = [applyBucketPadding(payload, bucketPadding, expansion)];
  if (decoyPayload) {
    inputs.push(applyBucketPadding(decoyPayload, bucketPadding, expansion));
  }
  const passwords = [password, duressPassword];
  // El señuelo NO usa el segundo factor: quien coacciona solo obtiene una
  // contraseña, y debe poder abrir el señuelo con ella sola.
  const factors = [secondFactor, ''];

  const blocks = [];
  try {
    for (let i = 0; i < blockCount; i++) {
      const salt = crypto.randomBytes(16);
      const ivs = generateIvs();
      const prk = deriveMasterKey({
        password: passwords[i],
        secondFactor: factors[i],
        hardwareId,
        salt,
      });
      try {
        const aadCtx = {
          magic: MAGIC, version: VERSION, mode, flags, blockIndex: i, blockCount,
        };
        const { ciphertext, tag } = encryptWith(cipherId, inputs[i], prk, salt, ivs, aadCtx);
        blocks.push({ salt, ivs, tag, ciphertext });
      } finally {
        wipe(prk);
      }
    }
    return {
      envelope: serializeEnvelope({ mode, flags, blockCount, cipherId }, blocks),
      flags,
      mode,
    };
  } finally {
    wipe(...inputs);
  }
}

/**
 * Descifra un archivo v2 completo.
 *
 * @returns {{payload: Buffer, isDuress: boolean, hardwareLockUsed: boolean,
 *            algorithm: string, mode: number, expirationTime: number}}
 * @throws {OpaqueError} si la autenticación falla (mensaje indistinguible)
 * @throws {PolicyError} si el archivo ha expirado o falta el hardware correcto
 */
export function decryptVault(envelope, { password, secondFactor = '', hardwareId = '' }) {
  const { header, blocks } = parseEnvelope(envelope);
  const needsHw = Boolean(header.flags & FLAGS.HARDWARE_LOCK);
  const usesSecondFactor = Boolean(header.flags & FLAGS.SECOND_FACTOR);
  const hasPadding = Boolean(header.flags & FLAGS.BUCKET_PADDING);

  // MIRAGE-013: el flag está en la cabecera, así que derivamos UNA vez.
  if (needsHw && !hardwareId) {
    throw new PolicyError(
      'Este archivo está vinculado a un equipo concreto (hardware-lock) y no se '
      + 'ha podido obtener el identificador de este equipo.'
    );
  }
  const effectiveHwId = needsHw ? hardwareId : '';

  if (usesSecondFactor && !secondFactor) {
    throw new PolicyError('Este archivo requiere un secreto secundario además de la contraseña.');
  }

  const cipherId = header.cipherId;
  let payload = null;
  let isDuress = false;

  // Bloque 0: payload real (contraseña + segundo factor).
  payload = tryBlock(blocks[0], 0, {
    password, secondFactor, hardwareId: effectiveHwId, header, cipherId,
  });

  // Bloque 1 (solo duress): payload señuelo, sin segundo factor.
  if (!payload && header.blockCount === 2) {
    payload = tryBlock(blocks[1], 1, {
      password, secondFactor: '', hardwareId: effectiveHwId, header, cipherId,
    });
    if (payload) isDuress = true;
  }

  if (!payload) {
    throw new OpaqueError('vault: ningún bloque autenticó con las credenciales dadas');
  }

  // El prefijo de longitud está presente siempre (ver encryptVault), así que
  // se retira siempre. El flag solo documenta si además hubo relleno.
  void hasPadding;
  const inner = stripBucketPadding(payload);

  // MIRAGE-010: comprobamos el TTL antes de devolver nada al llamante.
  const expirationTime = peekExpiration(inner);
  if (expirationTime > 0 && Date.now() > expirationTime) {
    wipe(payload, inner);
    throw new PolicyError(
      `El archivo declara haber expirado el ${new Date(expirationTime).toISOString()}. `
      + 'Aviso honesto: el TTL es una política de uso aplicada por esta aplicación, '
      + 'NO un control criptográfico. Los datos ya se descifraron en memoria y quien '
      + 'controle el proceso o tenga la contraseña puede recuperarlos.'
    );
  }

  return {
    payload: inner,
    isDuress,
    hardwareLockUsed: needsHw,
    algorithm: cipherId === CIPHER_IDS.CASCADE_C4_V2 ? ALGORITHMS.CASCADE : ALGORITHMS.AES,
    mode: header.mode,
    expirationTime,
  };
}

function tryBlock(block, blockIndex, { password, secondFactor, hardwareId, header, cipherId }) {
  const prk = deriveMasterKey({ password, secondFactor, hardwareId, salt: block.salt });
  try {
    const aadCtx = {
      magic: MAGIC,
      version: VERSION,
      mode: header.mode,
      flags: header.flags,
      blockIndex,
      blockCount: header.blockCount,
    };
    return decryptWith(cipherId, block.ciphertext, prk, block.salt, block.ivs, block.tag, aadCtx);
  } catch {
    // Fallo indistinguible: no se filtra si fue el tag, el padding o la clave.
    return null;
  } finally {
    wipe(prk);
  }
}
