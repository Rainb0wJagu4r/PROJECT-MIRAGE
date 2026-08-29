/**
 * lib/padding.js — Ocultación de longitud por buckets (esquema Padmé).
 *
 * Corrige MIRAGE-011 (obfuscación de tamaño insuficiente + tamaño exacto público).
 *
 * Problema original:
 *   1. `applySizePadding` añadía padding ADITIVO aleatorio (3 KB..4.5 MB). Como
 *      es aditivo y no cuantizado, el tamaño original sigue correlacionado con
 *      el final. Medido en la auditoría: p50 ≈ 137 KB, y un archivo de 1 KB vs
 *      uno de 50 MB seguían trivialmente distinguibles (1.37 MB vs 50.3 MB).
 *   2. El padding se añadía DESPUÉS de serializar pero su longitud quedaba
 *      implícita, así que al descifrar no se podía distinguir del contenido.
 *      Funcionaba solo porque `deserializePayload` leía un `fileSize` explícito.
 *   3. Peor: el envelope escribía `cipherLen` en claro y los cifrados de flujo
 *      preservan longitud, así que el tamaño exacto del payload era PÚBLICO.
 *      Verificado en los 3 .wraith reales aportados (p. ej. 244757336 bytes).
 *
 * Solución: PADMÉ (Nikitin et al., PETS 2019 — el esquema usado por Signal y
 * PURBs). Cuantiza la longitud a un conjunto reducido de valores permitidos con
 * un desperdicio acotado (≤ ~12%, muy inferior al de potencias de 2 que puede
 * llegar al 100%). La longitud real viaja DENTRO del payload autenticado.
 *
 * Formato del bloque con padding (todo se cifra después):
 *   [realLen: 8B BE uint64][datos reales][relleno aleatorio]
 *
 * Propiedad clave: dos archivos cuyos tamaños caen en el mismo bucket producen
 * ciphertexts de longitud IDÉNTICA, así que la longitud deja de identificarlos.
 */

import crypto from 'crypto';
import { OpaqueError } from './errors.js';

/** Prefijo de longitud real: uint64 big-endian. */
const LEN_PREFIX = 8;

/** Suelo de bucket: nada por debajo de 4 KiB, para que los archivos diminutos no destaquen. */
const MIN_BUCKET = 4096;

/**
 * Calcula la longitud padded según Padmé.
 *
 * Idea: para L, sean E = floor(log2(L)) y S = floor(log2(E)) + 1. Se conservan
 * los S bits más significativos del exponente y se pone a cero el resto de la
 * mantisa, redondeando hacia arriba. El desperdicio queda acotado
 * (asintóticamente ≤ ~12%) y el número de longitudes distintas posibles es
 * mucho menor que L.
 *
 * @param {number} L Longitud real en bytes (≥ 0).
 * @returns {number} Longitud objetivo, siempre ≥ L.
 */
export function padmeLength(L) {
  if (!Number.isSafeInteger(L) || L < 0) {
    throw new OpaqueError(`padme: longitud inválida (${L})`);
  }
  if (L <= MIN_BUCKET) return MIN_BUCKET;

  const E = Math.floor(Math.log2(L));
  const S = Math.floor(Math.log2(E)) + 1;
  const z = Math.max(0, E - S);
  // Máscara que pone a cero los z bits inferiores.
  const mask = 2 ** z - 1;
  const padded = (L + mask) & ~mask;
  // Nunca devolvemos menos que L (defensa contra errores de redondeo en float).
  return Math.max(padded, L);
}

/**
 * Aplica padding por buckets. La longitud real se guarda en un prefijo que
 * quedará cubierto por el AEAD, así que no puede alterarse sin invalidar el tag.
 *
 * IMPORTANTE — parámetro `expansion`:
 * el bucket debe aplicarse al tamaño FINAL del archivo, no al del payload. La
 * cascada v2 tiene dos capas CBC que añaden relleno PKCS#7 (16 bytes cada una
 * cuando la entrada ya es múltiplo de 16, es decir 32 en total), mientras que
 * AES-GCM no añade nada. Si ignoramos esa diferencia, el tamaño del archivo
 * delata qué algoritmo se usó y, peor aún, dos archivos con el mismo bucket
 * pero distinto algoritmo tienen tamaños distintos.
 *
 * Pasando `expansion` descontamos ese crecimiento de antemano, de modo que el
 * ciphertext resultante cae EXACTAMENTE en el bucket.
 *
 * @param {Buffer} buffer Datos a proteger.
 * @param {boolean} [enabled=true] Si es false, solo añade el prefijo (sin relleno).
 * @param {number} [expansion=0] Bytes que añadirá el cifrado por encima de la entrada.
 * @returns {Buffer}
 */
export function applyBucketPadding(buffer, enabled = true, expansion = 0) {
  if (!Buffer.isBuffer(buffer)) throw new OpaqueError('padding: entrada no es Buffer');
  if (!Number.isSafeInteger(expansion) || expansion < 0) {
    throw new OpaqueError(`padding: expansion inválida (${expansion})`);
  }

  const realLen = buffer.length;
  const prefix = Buffer.alloc(LEN_PREFIX);
  prefix.writeBigUInt64BE(BigInt(realLen), 0);

  if (!enabled) return Buffer.concat([prefix, buffer]);

  // Bucket del tamaño final observable (ya con el crecimiento del cifrado).
  const finalTarget = padmeLength(realLen + LEN_PREFIX + expansion);
  const padLen = finalTarget - expansion - realLen - LEN_PREFIX;
  // Relleno con CSPRNG: indistinguible del ciphertext, sin patrones explotables.
  const filler = padLen > 0 ? crypto.randomBytes(padLen) : Buffer.alloc(0);
  return Buffer.concat([prefix, buffer, filler]);
}

/**
 * Retira el padding leyendo la longitud real del prefijo autenticado.
 * Solo debe llamarse DESPUÉS de que el AEAD haya verificado el tag.
 *
 * @param {Buffer} padded
 * @returns {Buffer} Datos originales.
 */
export function stripBucketPadding(padded) {
  if (!Buffer.isBuffer(padded) || padded.length < LEN_PREFIX) {
    throw new OpaqueError('padding: bloque demasiado corto para contener el prefijo');
  }
  const realLenBig = padded.readBigUInt64BE(0);
  // Validación estricta: la longitud declarada debe caber en lo que hay.
  if (realLenBig > BigInt(padded.length - LEN_PREFIX)) {
    throw new OpaqueError(
      `padding: longitud declarada (${realLenBig}) excede el bloque (${padded.length - LEN_PREFIX})`
    );
  }
  if (realLenBig > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new OpaqueError('padding: longitud declarada fuera de rango seguro');
  }
  const realLen = Number(realLenBig);
  return padded.subarray(LEN_PREFIX, LEN_PREFIX + realLen);
}

/**
 * Utilidad de introspección para tests y documentación: enumera los buckets
 * distintos que produce Padmé en un rango. Permite comprobar que el número de
 * longitudes observables es pequeño (a diferencia del padding aditivo v1).
 */
export function enumerateBuckets(from, to, step) {
  const set = new Set();
  for (let L = from; L <= to; L += step) set.add(padmeLength(L));
  return [...set].sort((a, b) => a - b);
}
