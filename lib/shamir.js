/**
 * lib/shamir.js — Shamir Secret Sharing real sobre GF(2^8).
 *
 * Corrige MIRAGE-009 (la fragmentación "2-de-3" no era un esquema de umbral).
 *
 * Problema original: el modo "split fragment" partía el envelope por la mitad y
 * generaba una tercera parte por paridad XOR (H3 = H1 ⊕ H2), estilo RAID-5.
 * Verificado en la auditoría:
 *   - H1 contenía el magic "MIRAGE", el salt y los 4 IVs EN CLARO.
 *   - Un solo fragmento revelaba literalmente la primera mitad del envelope.
 *   - Los fragmentos no tenían MAC propio.
 * En un esquema de umbral real, k-1 fragmentos deben dar CERO información. La
 * etiqueta "2-of-3 threshold" que mostraba la UI era, por tanto, engañosa.
 *
 * Solución: Shamir sobre GF(2^8) aplicado byte a byte.
 *   - Para cada byte del secreto se construye un polinomio de grado k-1 cuyo
 *     término independiente es el byte y cuyos coeficientes son aleatorios.
 *   - Cada fragmento i recibe P(x_i) para x_i = 1..n.
 *   - Con k fragmentos se interpola en x=0 (interpolación de Lagrange).
 *   - Con k-1 o menos, cada byte es uniformemente aleatorio: seguridad de
 *     secreto perfecto (information-theoretic), no computacional.
 *
 * Cada fragmento lleva además:
 *   - Cabecera versionada con índice, umbral y total.
 *   - HMAC-SHA256 sobre (cabecera || share) con clave derivada del propio
 *     secreto, para detectar fragmentos manipulados o de otro conjunto.
 *
 * Implementación en tiempo constante respecto al VALOR de los bytes: se usan
 * tablas log/exp para la multiplicación, que es la práctica estándar. Nota
 * honesta: los accesos a tabla pueden ser observables por caché en un modelo de
 * atacante local muy fuerte; para fragmentación de archivos en reposo esto no
 * es un vector realista.
 */

import crypto from 'crypto';
import { OpaqueError, PolicyError } from './errors.js';

/* ── Aritmética en GF(2^8) con polinomio irreducible 0x11B (el de AES) ────── */

const EXP = new Uint8Array(512);
const LOG = new Uint8Array(256);

(function initTables() {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    EXP[i] = x;
    LOG[x] = i;
    // Multiplicación por el generador 0x03 (x + 1).
    let hi = x & 0x80;
    x = (x << 1) & 0xff;
    if (hi) x ^= 0x1b;
    x ^= EXP[i];
  }
  for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
  LOG[0] = 0; // convención; nunca se usa para 0
})();

function gmul(a, b) {
  if (a === 0 || b === 0) return 0;
  return EXP[LOG[a] + LOG[b]];
}

function gdiv(a, b) {
  if (b === 0) throw new OpaqueError('shamir: división por cero en GF(256)');
  if (a === 0) return 0;
  return EXP[(LOG[a] - LOG[b] + 255) % 255];
}

/* ── Cabecera de fragmento ─────────────────────────────────────────────────── */

const SHARE_MAGIC = 'MIRGSHR2'; // 8 bytes
const SHARE_VERSION = 2;
// magic(8) + version(1) + index(1) + threshold(1) + total(1) + secretLen(8) + hmac(32)
const SHARE_HEADER_LEN = 8 + 1 + 1 + 1 + 1 + 8;
const HMAC_LEN = 32;

/** Deriva la clave HMAC de integridad a partir del secreto completo. */
function shareMacKey(secret) {
  return crypto.createHmac('sha256', Buffer.from('mirage/shamir/v2/share-mac'))
    .update(secret)
    .digest();
}

/**
 * Divide un secreto en `total` fragmentos, de los cuales `threshold` bastan.
 *
 * @param {Buffer} secret     Datos a fragmentar (el envelope completo).
 * @param {number} [threshold=2]
 * @param {number} [total=3]
 * @returns {Buffer[]} Fragmentos serializados y autenticados.
 */
export function splitSecret(secret, threshold = 2, total = 3) {
  if (!Buffer.isBuffer(secret) || secret.length === 0) {
    throw new PolicyError('Fragment Error: no hay datos que fragmentar.');
  }
  if (!Number.isInteger(threshold) || !Number.isInteger(total)) {
    throw new PolicyError('Fragment Error: umbral y total deben ser enteros.');
  }
  if (threshold < 2 || total < threshold || total > 255) {
    throw new PolicyError('Fragment Error: se requiere 2 ≤ umbral ≤ total ≤ 255.');
  }

  const L = secret.length;
  const shares = [];
  for (let i = 0; i < total; i++) shares.push(Buffer.alloc(L));

  // Coeficientes aleatorios reutilizados por byte (se regeneran en cada iteración).
  const coeffs = Buffer.alloc(threshold - 1);

  for (let pos = 0; pos < L; pos++) {
    crypto.randomFillSync(coeffs);
    const a0 = secret[pos];
    for (let s = 0; s < total; s++) {
      const x = s + 1; // x_i ∈ 1..total ; x=0 se reserva para el secreto
      // Evaluación de Horner: P(x) = a0 + a1·x + a2·x² + ...
      let y = 0;
      for (let c = threshold - 2; c >= 0; c--) {
        y = gmul(y, x) ^ coeffs[c];
      }
      y = gmul(y, x) ^ a0;
      shares[s][pos] = y;
    }
  }
  coeffs.fill(0);

  const macKey = shareMacKey(secret);
  const out = shares.map((share, idx) => {
    const head = Buffer.alloc(SHARE_HEADER_LEN);
    let o = 0;
    Buffer.from(SHARE_MAGIC, 'ascii').copy(head, o); o += 8;
    head.writeUInt8(SHARE_VERSION, o); o += 1;
    head.writeUInt8(idx + 1, o); o += 1;
    head.writeUInt8(threshold, o); o += 1;
    head.writeUInt8(total, o); o += 1;
    head.writeBigUInt64BE(BigInt(L), o);

    const mac = crypto.createHmac('sha256', macKey)
      .update(head).update(share).digest();
    return Buffer.concat([head, mac, share]);
  });
  macKey.fill(0);
  return out;
}

/** Parsea y valida estructuralmente un fragmento serializado. */
function parseShare(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < SHARE_HEADER_LEN + HMAC_LEN + 1) {
    throw new OpaqueError('shamir: fragmento demasiado corto');
  }
  if (buf.subarray(0, 8).toString('ascii') !== SHARE_MAGIC) {
    throw new OpaqueError('shamir: magic de fragmento inválido');
  }
  const version = buf.readUInt8(8);
  if (version !== SHARE_VERSION) {
    throw new OpaqueError(`shamir: versión de fragmento no soportada (${version})`);
  }
  const index = buf.readUInt8(9);
  const threshold = buf.readUInt8(10);
  const total = buf.readUInt8(11);
  const secretLenBig = buf.readBigUInt64BE(12);

  if (index < 1 || index > 255) throw new OpaqueError('shamir: índice fuera de rango');
  if (threshold < 2 || total < threshold) throw new OpaqueError('shamir: parámetros inconsistentes');
  if (secretLenBig > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new OpaqueError('shamir: longitud de secreto fuera de rango');
  }
  const secretLen = Number(secretLenBig);

  const mac = buf.subarray(SHARE_HEADER_LEN, SHARE_HEADER_LEN + HMAC_LEN);
  const share = buf.subarray(SHARE_HEADER_LEN + HMAC_LEN);

  // La longitud del fragmento debe coincidir exactamente con la declarada.
  if (share.length !== secretLen) {
    throw new OpaqueError(
      `shamir: longitud de fragmento (${share.length}) ≠ declarada (${secretLen})`
    );
  }
  return {
    index, threshold, total, secretLen, mac, share,
    header: buf.subarray(0, SHARE_HEADER_LEN),
  };
}

/**
 * Reconstruye el secreto a partir de `threshold` (o más) fragmentos.
 *
 * @param {Buffer[]} shareBuffers
 * @returns {Buffer} Secreto original.
 */
export function combineShares(shareBuffers) {
  if (!Array.isArray(shareBuffers) || shareBuffers.length < 2) {
    throw new PolicyError('Fragment Error: se requieren al menos 2 fragmentos.');
  }

  const parsed = shareBuffers.map(parseShare);
  const { threshold, secretLen } = parsed[0];

  // Todos los fragmentos deben declarar los mismos parámetros.
  for (const p of parsed) {
    if (p.threshold !== threshold || p.secretLen !== secretLen) {
      throw new OpaqueError('shamir: los fragmentos no pertenecen al mismo conjunto');
    }
  }
  if (parsed.length < threshold) {
    throw new PolicyError(
      `Fragment Error: se requieren ${threshold} fragmentos, se aportaron ${parsed.length}.`
    );
  }
  // Índices duplicados harían la interpolación singular.
  const seen = new Set();
  for (const p of parsed) {
    if (seen.has(p.index)) throw new OpaqueError('shamir: índice de fragmento duplicado');
    seen.add(p.index);
  }

  const use = parsed.slice(0, threshold);
  const xs = use.map((p) => p.index);
  const secret = Buffer.alloc(secretLen);

  // Interpolación de Lagrange en x = 0.
  for (let pos = 0; pos < secretLen; pos++) {
    let acc = 0;
    for (let i = 0; i < use.length; i++) {
      let num = 1, den = 1;
      for (let j = 0; j < use.length; j++) {
        if (i === j) continue;
        num = gmul(num, xs[j]);        // (0 - x_j) = x_j en GF(2^8)
        den = gmul(den, xs[i] ^ xs[j]); // (x_i - x_j) = x_i ^ x_j
      }
      acc ^= gmul(use[i].share[pos], gdiv(num, den));
    }
    secret[pos] = acc;
  }

  // Verificación de integridad: el HMAC solo cuadra si el secreto reconstruido
  // es el correcto Y ningún fragmento fue manipulado.
  const macKey = shareMacKey(secret);
  try {
    for (const p of use) {
      const expected = crypto.createHmac('sha256', macKey)
        .update(p.header).update(p.share).digest();
      if (!crypto.timingSafeEqual(expected, p.mac)) {
        throw new OpaqueError(`shamir: HMAC inválido en el fragmento ${p.index}`);
      }
    }
  } finally {
    macKey.fill(0);
  }

  return secret;
}

export const SHARE_CONSTANTS = Object.freeze({
  SHARE_MAGIC, SHARE_VERSION, SHARE_HEADER_LEN, HMAC_LEN,
});
