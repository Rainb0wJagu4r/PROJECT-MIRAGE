/**
 * lib/cascade.js — Mirage-C4 v2: cascada NO conmutativa.
 *
 * Corrige:
 *   MIRAGE-002 (el cascade v1 colapsaba a un único XOR)  ← hallazgo principal
 *   MIRAGE-005 (bloques no vinculados al envelope: splice/reordenamiento)
 *   MIRAGE-006 (subclaves por HKDF con dominio de separación)
 *   MIRAGE-015 (zeroization del material de clave)
 *   parte de MIRAGE-011 (el padding de bloque desacopla longitudes)
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * POR QUÉ v1 ERA LINEAL
 * ─────────────────────────────────────────────────────────────────────────────
 * v1 aplicaba: Camellia-CTR → ARIA-CTR → ChaCha20 → AES-GCM.
 * Los cuatro son stream ciphers (GCM es AES-CTR + GMAC). Con IVs fijos, cada
 * capa es P ⊕ KS_i, y la composición se colapsa:
 *
 *     C = P ⊕ KS_cam ⊕ KS_aria ⊕ KS_cha ⊕ KS_aes = P ⊕ KS_combinado
 *
 * Verificado ejecutando el código original:
 *     C1 ⊕ C2 == P1 ⊕ P2                      → true
 *     KS = C1 ⊕ P1 descifraba cualquier otro C → true
 *
 * Es decir: las 4 capas daban la seguridad de UNA, y el claim de "4x256-bit"
 * era falso. Además, cualquier reutilización de (clave, IVs) filtraba el XOR de
 * los plaintexts.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * CÓMO v2 ROMPE LA LINEALIDAD
 * ─────────────────────────────────────────────────────────────────────────────
 * Se intercalan modos de CIFRADO POR BLOQUES (CBC), que no conmutan con XOR:
 *
 *   Capa 1: Camellia-256-CBC   (bloque, PKCS#7)   ← no lineal
 *   Capa 2: ChaCha20           (stream)
 *   Capa 3: ARIA-256-CBC       (bloque, PKCS#7)   ← no lineal
 *   Capa 4: AES-256-GCM        (AEAD, autentica)
 *
 * Ahora C = GCM(ARIA_CBC(ChaCha(Camellia_CBC(P)))) y, como CBC introduce
 * difusión dependiente del bloque anterior:
 *
 *     C1 ⊕ C2 ≠ P1 ⊕ P2      (test 1 de test-security.mjs lo verifica)
 *
 * La composición es genuinamente anidada: romper la construcción exige
 * atravesar Camellia Y ARIA Y AES, no solo el más débil de un XOR.
 *
 * HONESTIDAD SOBRE EL BENEFICIO REAL: esta cascada aporta defensa en
 * profundidad frente a un fallo criptoanalítico futuro en UNO de los cifrados.
 * NO multiplica el tamaño de clave: la seguridad NO es 1024 bits. Sigue siendo
 * del orden de 256 bits (~128 frente a Grover), igual que AES-256 bien usado.
 * El coste es ~4x CPU. Si no se necesita esa redundancia, AES-256-GCM a secas
 * es una elección igualmente válida y más simple (modo 'aes-256-gcm').
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * NONCE DE ChaCha20 (MIRAGE-M)
 * ─────────────────────────────────────────────────────────────────────────────
 * OpenSSL espera 16 bytes = contador LE de 4B || nonce de 12B. v1 pasaba
 * randomBytes(16), así que randomizaba también el contador: el espacio de nonce
 * efectivo era 12B y el keystream útil quedaba recortado antes del wrap. v2
 * almacena un nonce de 12 bytes y fija el contador a 0 explícitamente.
 */

import crypto from 'crypto';
import { OpaqueError } from './errors.js';
import { deriveSubkey, wipe } from './kdf.js';

/** Tamaños del formato v2 (en bytes). */
export const SIZES = Object.freeze({
  SALT: 16,
  IV_CAMELLIA: 16, // bloque de 128 bits para CBC
  NONCE_CHACHA: 12, // nonce real; el contador se fija a 0
  IV_ARIA: 16, // bloque de 128 bits para CBC
  IV_AES: 12, // nonce recomendado para GCM
  TAG: 16,
});

/** Etiquetas HKDF: únicas, versionadas e inequívocas (MIRAGE-006). */
const LABELS = Object.freeze({
  camellia: 'mirage/c4/v2/layer1/camellia-256-cbc',
  chacha: 'mirage/c4/v2/layer2/chacha20',
  aria: 'mirage/c4/v2/layer3/aria-256-cbc',
  aes: 'mirage/c4/v2/layer4/aes-256-gcm',
  single: 'mirage/aead/v2/aes-256-gcm',
});

/** Genera el conjunto de IVs/nonces aleatorios para un bloque v2. */
export function generateIvs() {
  return {
    ivCamellia: crypto.randomBytes(SIZES.IV_CAMELLIA),
    nonceChaCha: crypto.randomBytes(SIZES.NONCE_CHACHA),
    ivAria: crypto.randomBytes(SIZES.IV_ARIA),
    ivAes: crypto.randomBytes(SIZES.IV_AES),
  };
}

/** Construye el IV de 16B de ChaCha20 con contador explícito a cero. */
function chachaIv(nonce12) {
  if (!Buffer.isBuffer(nonce12) || nonce12.length !== SIZES.NONCE_CHACHA) {
    throw new OpaqueError('cascade: nonce de ChaCha20 inválido');
  }
  return Buffer.concat([Buffer.alloc(4, 0), nonce12]); // counter = 0
}

/**
 * Construye el AAD que vincula el bloque a TODO su contexto (MIRAGE-005).
 *
 * v1 usaba AAD = header || salt || IVs, lo que autenticaba cada bloque de forma
 * aislada. Verificado en la auditoría: un bloque de OTRO archivo validaba sin
 * error dentro del mismo envelope, y el campo cipherLen no estaba cubierto.
 *
 * v2 incluye además: versión, modo, índice de bloque, número total de bloques y
 * la longitud del ciphertext. Así, reordenar bloques, sustituir uno por el de
 * otro archivo o alterar cipherLen invalida el tag.
 */
export function buildAad({
  magic, version, mode, flags = 0, blockIndex, blockCount, salt, ivs, cipherLen,
}) {
  const fixed = Buffer.alloc(4 + 1 + 1 + 1 + 1 + 1 + 8);
  let o = 0;
  Buffer.from(magic, 'ascii').copy(fixed, o); o += 4;
  fixed.writeUInt8(version, o); o += 1;
  fixed.writeUInt8(mode, o); o += 1;
  // flags incluye el bit de hardware-lock y el de padding: alterarlos invalida el tag.
  fixed.writeUInt8(flags, o); o += 1;
  fixed.writeUInt8(blockIndex, o); o += 1;
  fixed.writeUInt8(blockCount, o); o += 1;
  // Longitud como entero sin signo de 64 bits (v1 usaba un double: ver MIRAGE-003).
  fixed.writeBigUInt64BE(BigInt(cipherLen), o);

  return Buffer.concat([
    fixed,
    salt,
    ivs.ivCamellia,
    ivs.nonceChaCha,
    ivs.ivAria,
    ivs.ivAes,
  ]);
}

/**
 * Cifra con la cascada no conmutativa v2.
 *
 * @param {Buffer} plaintext
 * @param {Buffer} prk    PRK de 32B (de deriveMasterKey).
 * @param {Buffer} salt
 * @param {object} ivs    De generateIvs().
 * @param {object} aadCtx {magic, version, mode, blockIndex, blockCount}
 * @returns {{ciphertext: Buffer, tag: Buffer}}
 */
export function encryptCascade(plaintext, prk, salt, ivs, aadCtx) {
  const kCam = deriveSubkey(prk, salt, LABELS.camellia);
  const kCha = deriveSubkey(prk, salt, LABELS.chacha);
  const kAri = deriveSubkey(prk, salt, LABELS.aria);
  const kAes = deriveSubkey(prk, salt, LABELS.aes);

  let s1 = null, s2 = null, s3 = null;
  try {
    // Capa 1: Camellia-256-CBC (no lineal, PKCS#7 automático)
    const c1 = crypto.createCipheriv('camellia-256-cbc', kCam, ivs.ivCamellia);
    s1 = Buffer.concat([c1.update(plaintext), c1.final()]);

    // Capa 2: ChaCha20 (stream, contador explícito a 0)
    const c2 = crypto.createCipheriv('chacha20', kCha, chachaIv(ivs.nonceChaCha));
    s2 = Buffer.concat([c2.update(s1), c2.final()]);

    // Capa 3: ARIA-256-CBC (no lineal, PKCS#7 automático)
    const c3 = crypto.createCipheriv('aria-256-cbc', kAri, ivs.ivAria);
    s3 = Buffer.concat([c3.update(s2), c3.final()]);

    // La longitud final ya es conocida: GCM no la altera. Así podemos
    // incluirla en el AAD (MIRAGE-005).
    const aad = buildAad({ ...aadCtx, salt, ivs, cipherLen: s3.length });

    // Capa 4: AES-256-GCM (AEAD; autentica ciphertext + todo el contexto)
    const c4 = crypto.createCipheriv('aes-256-gcm', kAes, ivs.ivAes);
    c4.setAAD(aad);
    const ciphertext = Buffer.concat([c4.update(s3), c4.final()]);
    const tag = c4.getAuthTag();

    return { ciphertext, tag };
  } finally {
    // MIRAGE-015: borramos subclaves y estados intermedios (contienen datos
    // parcialmente cifrados del plaintext).
    wipe(kCam, kCha, kAri, kAes, s1, s2, s3);
  }
}

/**
 * Descifra la cascada v2. Verifica el tag GCM ANTES de invertir cualquier capa
 * interior: si la autenticación falla, no se procesa un solo byte de plaintext.
 *
 * @returns {Buffer} plaintext
 * @throws {OpaqueError} en cualquier fallo (mensaje indistinguible, MIRAGE-008)
 */
export function decryptCascade(ciphertext, prk, salt, ivs, tag, aadCtx) {
  const kCam = deriveSubkey(prk, salt, LABELS.camellia);
  const kCha = deriveSubkey(prk, salt, LABELS.chacha);
  const kAri = deriveSubkey(prk, salt, LABELS.aria);
  const kAes = deriveSubkey(prk, salt, LABELS.aes);

  let s3 = null, s2 = null;
  try {
    const aad = buildAad({ ...aadCtx, salt, ivs, cipherLen: ciphertext.length });

    // Capa 4 inversa: AES-256-GCM. decipher.final() lanza si el tag no cuadra.
    const d4 = crypto.createDecipheriv('aes-256-gcm', kAes, ivs.ivAes);
    d4.setAuthTag(tag);
    d4.setAAD(aad);
    s3 = Buffer.concat([d4.update(ciphertext), d4.final()]); // ← punto de autenticación

    // A partir de aquí los datos están autenticados.
    const d3 = crypto.createDecipheriv('aria-256-cbc', kAri, ivs.ivAria);
    s2 = Buffer.concat([d3.update(s3), d3.final()]);

    const d2 = crypto.createDecipheriv('chacha20', kCha, chachaIv(ivs.nonceChaCha));
    const s1 = Buffer.concat([d2.update(s2), d2.final()]);

    const d1 = crypto.createDecipheriv('camellia-256-cbc', kCam, ivs.ivCamellia);
    return Buffer.concat([d1.update(s1), d1.final()]);
  } catch (err) {
    throw new OpaqueError(`cascade v2: fallo de descifrado/autenticación (${err.message})`);
  } finally {
    wipe(kCam, kCha, kAri, kAes, s3, s2);
  }
}

/**
 * Modo simple: AES-256-GCM único, con el mismo AAD reforzado.
 * Es una alternativa perfectamente válida y más rápida a la cascada.
 */
export function encryptSingle(plaintext, prk, salt, ivs, aadCtx) {
  const key = deriveSubkey(prk, salt, LABELS.single);
  try {
    const aad = buildAad({ ...aadCtx, salt, ivs, cipherLen: plaintext.length });
    const c = crypto.createCipheriv('aes-256-gcm', key, ivs.ivAes);
    c.setAAD(aad);
    const ciphertext = Buffer.concat([c.update(plaintext), c.final()]);
    return { ciphertext, tag: c.getAuthTag() };
  } finally {
    wipe(key);
  }
}

export function decryptSingle(ciphertext, prk, salt, ivs, tag, aadCtx) {
  const key = deriveSubkey(prk, salt, LABELS.single);
  try {
    const aad = buildAad({ ...aadCtx, salt, ivs, cipherLen: ciphertext.length });
    const d = crypto.createDecipheriv('aes-256-gcm', key, ivs.ivAes);
    d.setAuthTag(tag);
    d.setAAD(aad);
    return Buffer.concat([d.update(ciphertext), d.final()]);
  } catch (err) {
    throw new OpaqueError(`aead v2: fallo de descifrado/autenticación (${err.message})`);
  } finally {
    wipe(key);
  }
}
