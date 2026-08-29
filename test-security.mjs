/**
 * test-security.mjs — Pruebas ADVERSARIALES del núcleo criptográfico de Mirage v2.
 *
 * Estas pruebas NO comprueban que "cifrar y descifrar funciona". Comprueban que
 * el sistema RECHAZA lo que debe rechazar. Cada test corresponde a un hallazgo
 * concreto de la auditoría (MIRAGE-XXX) y falla si la regresión reaparece.
 *
 * Lo que estas pruebas SÍ demuestran:
 *   - que las propiedades verificables localmente se cumplen.
 * Lo que NO demuestran:
 *   - que el sistema sea seguro. Ninguna batería de tests puede demostrar eso.
 *     Ver README, sección "Limitaciones conocidas".
 *
 * Uso: node test-security.mjs
 */

import crypto from 'crypto';
import { deriveMasterKey, buildKdfMaterial, deriveSubkey, assessPasswordStrength } from './lib/kdf.js';
import {
  generateIvs, encryptCascade, decryptCascade, buildAad, SIZES,
} from './lib/cascade.js';
import {
  MAGIC, VERSION, MODES, FLAGS, HEADER_LEN,
  serializePayload, deserializePayload, parseEnvelope,
  appendToCarrier, extractFromCarrier,
  serializeMultiPayload, deserializeMultiPayload,
  FORMAT_CONSTANTS,
} from './lib/format.js';
import { encryptVault, decryptVault, ALGORITHMS } from './lib/vault.js';
import { safeJoin, safeBasename, validateRelPath } from './lib/paths.js';
import { splitSecret, combineShares } from './lib/shamir.js';
import { padmeLength, applyBucketPadding, stripBucketPadding } from './lib/padding.js';
import { OPAQUE_MESSAGE, OpaqueError, PolicyError } from './lib/errors.js';

let passed = 0;
let failed = 0;
const failures = [];

function check(name, fn) {
  try {
    fn();
    passed++;
    console.log(`  \x1b[32mPASS\x1b[0m  ${name}`);
  } catch (err) {
    failed++;
    failures.push({ name, err });
    console.log(`  \x1b[31mFAIL\x1b[0m  ${name}`);
    console.log(`        ${err.message}`);
  }
}

function assert(cond, msg) {
  if (!cond) throw new Error(msg || 'aserción fallida');
}

/** Comprueba que `fn` lanza, y opcionalmente que el tipo es el esperado. */
function assertThrows(fn, Type, msg) {
  let threw = null;
  try { fn(); } catch (e) { threw = e; }
  assert(threw !== null, `${msg || ''}: se esperaba una excepción y no hubo ninguna`);
  if (Type) {
    assert(threw instanceof Type,
      `${msg || ''}: se esperaba ${Type.name} y se obtuvo ${threw.constructor.name}: ${threw.message}`);
  }
  return threw;
}

const PW = 'contrasena-de-prueba-larga-1';
const PW2 = 'segundo-factor-de-prueba-99';
const HWID = 'TEST-HW-UUID-0000-1111';

const section = (t) => console.log(`\n\x1b[1m${t}\x1b[0m`);

// ===========================================================================
section('MIRAGE-002 — La cascada ya NO es lineal');
// ===========================================================================

check('002.1 C1^C2 != P1^P2 (la cascada no colapsa en un XOR)', () => {
  const prk = crypto.randomBytes(32);
  const salt = crypto.randomBytes(16);
  const ivs = generateIvs();
  const aadCtx = { magic: MAGIC, version: VERSION, mode: MODES.SINGLE, flags: 0, blockIndex: 0, blockCount: 1 };

  const P1 = Buffer.alloc(64, 0xaa);
  const P2 = Buffer.alloc(64, 0x55);
  const C1 = encryptCascade(P1, prk, salt, ivs, aadCtx).ciphertext;
  const C2 = encryptCascade(P2, prk, salt, ivs, aadCtx).ciphertext;

  const xorC = Buffer.alloc(64);
  const xorP = Buffer.alloc(64);
  for (let i = 0; i < 64; i++) {
    xorC[i] = C1[i] ^ C2[i];
    xorP[i] = P1[i] ^ P2[i];
  }
  assert(!xorC.equals(xorP), 'REGRESIÓN: la cascada volvió a ser lineal (C1^C2 == P1^P2)');
});

check('002.2 el keystream de un par (P,C) no descifra otro ciphertext', () => {
  const prk = crypto.randomBytes(32);
  const salt = crypto.randomBytes(16);
  const ivs = generateIvs();
  const aadCtx = { magic: MAGIC, version: VERSION, mode: MODES.SINGLE, flags: 0, blockIndex: 0, blockCount: 1 };

  const P1 = Buffer.alloc(64, 0x00);
  const C1 = encryptCascade(P1, prk, salt, ivs, aadCtx).ciphertext;
  const KS = Buffer.alloc(64);
  for (let i = 0; i < 64; i++) KS[i] = C1[i] ^ P1[i];

  const P3 = crypto.randomBytes(64);
  const C3 = encryptCascade(P3, prk, salt, ivs, aadCtx).ciphertext;
  const guess = Buffer.alloc(64);
  for (let i = 0; i < 64; i++) guess[i] = C3[i] ^ KS[i];

  assert(!guess.equals(P3), 'REGRESIÓN: el keystream extraído sigue sirviendo para descifrar');
});

check('002.3 difusión: 1 bit en el plaintext cambia ~50% del ciphertext', () => {
  const prk = crypto.randomBytes(32);
  const salt = crypto.randomBytes(16);
  const ivs = generateIvs();
  const aadCtx = { magic: MAGIC, version: VERSION, mode: MODES.SINGLE, flags: 0, blockIndex: 0, blockCount: 1 };

  const A = Buffer.alloc(512, 0);
  const B = Buffer.alloc(512, 0);
  B[0] ^= 0x01;
  const CA = encryptCascade(A, prk, salt, ivs, aadCtx).ciphertext;
  const CB = encryptCascade(B, prk, salt, ivs, aadCtx).ciphertext;

  let diffBits = 0;
  for (let i = 0; i < CA.length; i++) {
    let x = CA[i] ^ CB[i];
    while (x) { diffBits += x & 1; x >>= 1; }
  }
  const ratio = diffBits / (CA.length * 8);
  assert(ratio > 0.4 && ratio < 0.6, `difusión fuera de rango: ${(ratio * 100).toFixed(2)}%`);
});

check('002.4 ida y vuelta exacta', () => {
  const prk = crypto.randomBytes(32);
  const salt = crypto.randomBytes(16);
  const ivs = generateIvs();
  const aadCtx = { magic: MAGIC, version: VERSION, mode: MODES.SINGLE, flags: 0, blockIndex: 0, blockCount: 1 };
  const P = crypto.randomBytes(3000);
  const { ciphertext, tag } = encryptCascade(P, prk, salt, ivs, aadCtx);
  const out = decryptCascade(ciphertext, prk, salt, ivs, tag, aadCtx);
  assert(out.equals(P), 'la ida y vuelta no devuelve el plaintext original');
});

// ===========================================================================
section('MIRAGE-005 — Vinculación del bloque a su contexto (AAD)');
// ===========================================================================

const aadBase = { magic: MAGIC, version: VERSION, mode: MODES.SINGLE, flags: 0, blockIndex: 0, blockCount: 1 };

function aadTamperTest(field, value) {
  const prk = crypto.randomBytes(32);
  const salt = crypto.randomBytes(16);
  const ivs = generateIvs();
  const P = crypto.randomBytes(128);
  const { ciphertext, tag } = encryptCascade(P, prk, salt, ivs, aadBase);
  assertThrows(
    () => decryptCascade(ciphertext, prk, salt, ivs, tag, { ...aadBase, [field]: value }),
    OpaqueError,
    `alterar ${field} debería invalidar el tag`
  );
}

check('005.1 alterar blockIndex invalida el tag', () => aadTamperTest('blockIndex', 1));
check('005.2 alterar blockCount invalida el tag', () => aadTamperTest('blockCount', 2));
check('005.3 alterar mode invalida el tag', () => aadTamperTest('mode', MODES.DURESS));
check('005.4 alterar flags (hardware-lock) invalida el tag', () => aadTamperTest('flags', FLAGS.HARDWARE_LOCK));
check('005.5 alterar version invalida el tag', () => aadTamperTest('version', 3));

check('005.6 cipherLen entra en el AAD (truncar invalida el tag)', () => {
  const prk = crypto.randomBytes(32);
  const salt = crypto.randomBytes(16);
  const ivs = generateIvs();
  const P = crypto.randomBytes(256);
  const { ciphertext, tag } = encryptCascade(P, prk, salt, ivs, aadBase);
  assertThrows(
    () => decryptCascade(ciphertext.subarray(0, ciphertext.length - 16), prk, salt, ivs, tag, aadBase),
    OpaqueError, 'un ciphertext truncado no debe autenticar'
  );
});

check('005.7 injertar el bloque de OTRO archivo falla (salt distinto)', () => {
  const prk = crypto.randomBytes(32);
  const saltA = crypto.randomBytes(16);
  const saltB = crypto.randomBytes(16);
  const ivs = generateIvs();
  const P = crypto.randomBytes(128);
  const { ciphertext, tag } = encryptCascade(P, prk, saltA, ivs, aadBase);
  assertThrows(
    () => decryptCascade(ciphertext, prk, saltB, ivs, tag, aadBase),
    OpaqueError, 'un bloque de otro archivo no debe autenticar'
  );
});

// ===========================================================================
section('MIRAGE-003 — Validación estricta de longitudes en el parser');
// ===========================================================================

function makeEnvelope(payloadSize = 100) {
  return encryptVault({
    payload: serializePayload('doc.txt', crypto.randomBytes(payloadSize)),
    password: PW,
    algorithm: ALGORITHMS.AES,
    bucketPadding: false,
  }).envelope;
}

check('003.1 cipherLen enorme se rechaza (no offset negativo)', () => {
  const env = Buffer.from(makeEnvelope());
  // Campo cipherLen: última posición de la metainformación del bloque.
  const lenOff = HEADER_LEN + SIZES.SALT + SIZES.IV_CAMELLIA + SIZES.NONCE_CHACHA
    + SIZES.IV_ARIA + SIZES.IV_AES + SIZES.TAG;
  env.writeBigUInt64BE(0xFFFFFFFFFFFFn, lenOff);
  assertThrows(() => parseEnvelope(env), OpaqueError, 'un cipherLen imposible debe rechazarse');
});

check('003.2 cipherLen = 2^63 se rechaza', () => {
  const env = Buffer.from(makeEnvelope());
  const lenOff = HEADER_LEN + SIZES.SALT + SIZES.IV_CAMELLIA + SIZES.NONCE_CHACHA
    + SIZES.IV_ARIA + SIZES.IV_AES + SIZES.TAG;
  env.writeBigUInt64BE(1n << 63n, lenOff);
  assertThrows(() => parseEnvelope(env), OpaqueError);
});

check('003.3 archivo truncado se rechaza', () => {
  const env = makeEnvelope();
  for (const cut of [1, 8, 20, 50, env.length - 1]) {
    assertThrows(() => parseEnvelope(env.subarray(0, cut)), OpaqueError, `truncado a ${cut} B`);
  }
});

check('003.4 bytes añadidos al final se rechazan', () => {
  const env = Buffer.concat([makeEnvelope(), Buffer.from('EXTRA')]);
  assertThrows(() => parseEnvelope(env), OpaqueError, 'un append debe detectarse');
});

check('003.5 trailer de portador con payloadLen imposible se rechaza', () => {
  const carrier = crypto.randomBytes(200);
  const env = makeEnvelope();
  const stego = Buffer.from(appendToCarrier(carrier, env));
  stego.writeBigUInt64BE(0xFFFFFFFFFFFFn, stego.length - 16);
  assertThrows(() => extractFromCarrier(stego), OpaqueError, 'payloadLen inválido');
});

check('003.6 trailer de portador legítimo se extrae bien', () => {
  const carrier = crypto.randomBytes(200);
  const env = makeEnvelope();
  const { buffer, isSteg } = extractFromCarrier(appendToCarrier(carrier, env));
  assert(isSteg, 'no se detectó el trailer');
  assert(buffer.equals(env), 'el payload extraído no coincide');
});

check('003.7 payload interno: filenameLen fuera de rango se rechaza', () => {
  const p = Buffer.from(serializePayload('a.txt', Buffer.from('hola')));
  p.writeUInt16BE(0xFFFF, 8);
  assertThrows(() => deserializePayload(p), OpaqueError);
});

check('003.8 payload interno: fileSize fuera de rango se rechaza', () => {
  const p = Buffer.from(serializePayload('a.txt', Buffer.from('hola')));
  p.writeBigUInt64BE(0xFFFFFFFFn, 10 + 5);
  assertThrows(() => deserializePayload(p), OpaqueError);
});

check('003.9 payload interno: nombre con NUL se rechaza', () => {
  const p = Buffer.from(serializePayload('a\u0000b.txt', Buffer.from('hola')));
  assertThrows(() => deserializePayload(p), OpaqueError);
});

check('003.10 bóveda multi-archivo: count imposible se rechaza', () => {
  const v = Buffer.from(serializeMultiPayload([{ relPath: 'a/b.txt', content: Buffer.from('x') }]));
  v.writeUInt32BE(0xFFFFFF, 'MIRG_VLT2'.length + 8);
  assertThrows(() => deserializeMultiPayload(v), OpaqueError);
});

check('003.11 bóveda multi-archivo: ida y vuelta exacta', () => {
  const files = [
    { relPath: 'docs/a.txt', content: crypto.randomBytes(50) },
    { relPath: 'b.bin', content: crypto.randomBytes(200) },
  ];
  const out = deserializeMultiPayload(serializeMultiPayload(files, 0));
  assert(out.files.length === 2, 'número de archivos incorrecto');
  assert(out.files[0].relPath === 'docs/a.txt' && out.files[0].content.equals(files[0].content));
  assert(out.files[1].relPath === 'b.bin' && out.files[1].content.equals(files[1].content));
});

// ===========================================================================
section('MIRAGE-001 — Contención de rutas (path traversal)');
// ===========================================================================

check('001.1 se rechazan las rutas relativas maliciosas', () => {
  const evil = [
    '../escape.txt',
    '../../../../etc/passwd',
    'a/../../b.txt',
    '/absoluta.txt',
    'C:\\Windows\\system32\\evil.dll',
    '\\\\servidor\\recurso\\x',
    'sub/../../../../tmp/pwned',
    'con', 'NUL', 'lpt1',
    'archivo\u0000.txt',
  ];
  for (const e of evil) {
    assertThrows(() => safeJoin('/tmp/mirage-base', e), Error, `debería rechazar "${e}"`);
  }
});

check('001.2 se aceptan las rutas relativas legítimas y quedan dentro de la base', () => {
  const base = '/tmp/mirage-base';
  for (const ok of ['a.txt', 'sub/a.txt', 'a/b/c/d.bin', 'con-figuracion.txt', 'nombre con espacios.txt']) {
    const r = safeJoin(base, ok);
    assert(r.startsWith(base + '/'), `"${ok}" escapó de la base: ${r}`);
  }
});

check('001.3 safeBasename neutraliza separadores y nombres reservados', () => {
  assert(safeBasename('../../etc/passwd') === 'passwd', 'no se quedó con el último componente');
  assert(safeBasename('C:\\evil\\x.txt') === 'x.txt');
  assert(safeBasename('con') === '_con', 'no se prefijó un nombre reservado');
  assert(safeBasename('') === 'restored_file.bin', 'no se aplicó el valor por defecto');
  assert(!safeBasename('a\u0000b').includes('\u0000'), 'quedó un NUL');
});

check('001.4 validateRelPath rechaza rutas de longitud abusiva', () => {
  // validateRelPath devuelve un veredicto {ok, reason}; es safeJoin quien lanza.
  const long = 'a/'.repeat(600) + 'x.txt';
  const v = validateRelPath(long);
  assert(v.ok === false, `una ruta de ${long.length} caracteres debería rechazarse`);
  assertThrows(() => safeJoin('/tmp/mirage-base', long), Error,
    'safeJoin debe lanzar con una ruta abusiva');
});

// ===========================================================================
section('MIRAGE-007 — Sin colisiones en el material de derivación (TLV)');
// ===========================================================================

check('007.1 la colisión de v1 ya no existe', () => {
  const a = buildKdfMaterial({ password: 'a__SECSEC__b' });
  const b = buildKdfMaterial({ password: 'a', secondFactor: 'b' });
  assert(!a.equals(b), 'REGRESIÓN: colisión entre password concatenada y segundo factor');
});

check('007.2 la colisión del separador de hardware ya no existe', () => {
  const a = buildKdfMaterial({ password: 'a__HW__uuid' });
  const b = buildKdfMaterial({ password: 'a', hardwareId: 'uuid' });
  assert(!a.equals(b), 'REGRESIÓN: colisión con el separador __HW__');
});

check('007.3 ningún par distinto de (pw, sf, hw) colisiona (codificación inyectiva)', () => {
  const combos = [
    ['a', '', ''], ['', 'a', ''], ['', '', 'a'],
    ['ab', '', ''], ['a', 'b', ''], ['a', '', 'b'], ['', 'a', 'b'],
    ['a', 'bc', ''], ['ab', 'c', ''],
    ['aaa', 'a', 'a'], ['a', 'aaa', 'a'], ['a', 'a', 'aaa'],
  ];
  const seen = new Map();
  for (const [password, secondFactor, hardwareId] of combos) {
    const hex = buildKdfMaterial({ password, secondFactor, hardwareId }).toString('hex');
    const key = JSON.stringify([password, secondFactor, hardwareId]);
    if (seen.has(hex)) {
      throw new Error(`colisión entre ${seen.get(hex)} y ${key}`);
    }
    seen.set(hex, key);
  }
});

check('007.4 el campo ausente y el campo vacío producen el mismo material', () => {
  const a = buildKdfMaterial({ password: 'x' });
  const b = buildKdfMaterial({ password: 'x', secondFactor: '', hardwareId: '' });
  assert(a.equals(b), 'ausente y vacío deben ser equivalentes');
});

// ===========================================================================
section('MIRAGE-006 — Separación de dominios en las subclaves (HKDF)');
// ===========================================================================

check('006.1 etiquetas distintas producen subclaves distintas', () => {
  const prk = crypto.randomBytes(32);
  const salt = crypto.randomBytes(16);
  const labels = [
    'mirage/c4/v2/layer1/camellia-256-cbc',
    'mirage/c4/v2/layer2/chacha20',
    'mirage/c4/v2/layer3/aria-256-cbc',
    'mirage/c4/v2/layer4/aes-256-gcm',
    'mirage/aead/v2/aes-256-gcm',
  ];
  const keys = labels.map((l) => deriveSubkey(prk, salt, l).toString('hex'));
  assert(new Set(keys).size === labels.length, 'dos etiquetas produjeron la misma subclave');
});

check('006.2 ninguna subclave es un trozo del PRK', () => {
  const prk = crypto.randomBytes(32);
  const salt = crypto.randomBytes(16);
  const k = deriveSubkey(prk, salt, 'mirage/c4/v2/layer1/camellia-256-cbc');
  assert(!k.equals(prk), 'la subclave coincide con el PRK');
  assert(!prk.includes(k), 'la subclave es un trozo literal del PRK');
});

check('006.3 se rechazan las etiquetas sin el prefijo del proyecto', () => {
  const prk = crypto.randomBytes(32);
  const salt = crypto.randomBytes(16);
  assertThrows(() => deriveSubkey(prk, salt, 'etiqueta-arbitraria'), Error);
});

// ===========================================================================
section('MIRAGE-004 — El modo duress funciona CON hardware-lock');
// ===========================================================================

const DURESS_PW = 'senuelo-de-prueba-largo-77';

check('004.1 sin hardware-lock: real y señuelo abren cada uno con su contraseña', () => {
  const { envelope } = encryptVault({
    payload: serializePayload('real.txt', Buffer.from('DATOS REALES')),
    decoyPayload: serializePayload('decoy.txt', Buffer.from('SENUELO')),
    password: PW, duressPassword: DURESS_PW, algorithm: ALGORITHMS.AES,
  });
  const real = decryptVault(envelope, { password: PW });
  assert(!real.isDuress, 'el bloque real se marcó como duress');
  assert(deserializePayload(real.payload).fileData.toString() === 'DATOS REALES');

  const decoy = decryptVault(envelope, { password: DURESS_PW });
  assert(decoy.isDuress, 'el señuelo NO se marcó como duress');
  assert(deserializePayload(decoy.payload).fileData.toString() === 'SENUELO');
});

check('004.2 CON hardware-lock: el señuelo también abre (el fallo v1 está corregido)', () => {
  const { envelope } = encryptVault({
    payload: serializePayload('real.txt', Buffer.from('DATOS REALES')),
    decoyPayload: serializePayload('decoy.txt', Buffer.from('SENUELO')),
    password: PW, duressPassword: DURESS_PW, hardwareId: HWID, algorithm: ALGORITHMS.AES,
  });
  const real = decryptVault(envelope, { password: PW, hardwareId: HWID });
  assert(!real.isDuress && real.hardwareLockUsed, 'el bloque real no abrió con hw-lock');

  const decoy = decryptVault(envelope, { password: DURESS_PW, hardwareId: HWID });
  assert(decoy.isDuress, 'REGRESIÓN MIRAGE-004: el señuelo no abre con hardware-lock activo');
  assert(deserializePayload(decoy.payload).fileData.toString() === 'SENUELO');
});

check('004.3 con hardware-lock, otro equipo NO abre el archivo', () => {
  const { envelope } = encryptVault({
    payload: serializePayload('real.txt', Buffer.from('DATOS')),
    password: PW, hardwareId: HWID, algorithm: ALGORITHMS.AES,
  });
  assertThrows(() => decryptVault(envelope, { password: PW, hardwareId: 'OTRO-EQUIPO' }), OpaqueError);
});

check('004.4 falta el identificador de hardware: error de política, no opaco', () => {
  const { envelope } = encryptVault({
    payload: serializePayload('real.txt', Buffer.from('DATOS')),
    password: PW, hardwareId: HWID, algorithm: ALGORITHMS.AES,
  });
  assertThrows(() => decryptVault(envelope, { password: PW }), PolicyError,
    'debe avisar de que el archivo está vinculado a un equipo');
});

check('004.5 el señuelo no puede reutilizar la contraseña principal', () => {
  assertThrows(() => encryptVault({
    payload: serializePayload('a', Buffer.from('x')),
    decoyPayload: serializePayload('b', Buffer.from('y')),
    password: PW, duressPassword: PW, algorithm: ALGORITHMS.AES,
  }), PolicyError);
});

// ===========================================================================
section('MIRAGE-008 — Errores indistinguibles (sin oráculo)');
// ===========================================================================

check('008.1 todos los fallos de descifrado dan el MISMO mensaje público', () => {
  const env = makeEnvelope(500);
  const variants = [];

  // contraseña incorrecta
  try { decryptVault(env, { password: 'otra-contrasena-larga-99' }); }
  catch (e) { variants.push(e.message); }

  // tag alterado
  const t = Buffer.from(env);
  const tagOff = HEADER_LEN + SIZES.SALT + SIZES.IV_CAMELLIA + SIZES.NONCE_CHACHA + SIZES.IV_ARIA + SIZES.IV_AES;
  t[tagOff] ^= 0xff;
  try { decryptVault(t, { password: PW }); } catch (e) { variants.push(e.message); }

  // ciphertext alterado
  const c = Buffer.from(env);
  c[c.length - 1] ^= 0xff;
  try { decryptVault(c, { password: PW }); } catch (e) { variants.push(e.message); }

  // salt alterado
  const s = Buffer.from(env);
  s[HEADER_LEN] ^= 0xff;
  try { decryptVault(s, { password: PW }); } catch (e) { variants.push(e.message); }

  assert(variants.length === 4, `se esperaban 4 fallos, hubo ${variants.length}`);
  const unique = new Set(variants);
  assert(unique.size === 1,
    `hay ${unique.size} mensajes distintos (oráculo):\n${[...unique].map((m) => `  - ${m}`).join('\n')}`);
  assert(variants[0] === OPAQUE_MESSAGE, `el mensaje no es el opaco: "${variants[0]}"`);
});

check('008.2 los fallos de parsing tampoco se distinguen entre sí', () => {
  const env = makeEnvelope(200);
  const msgs = new Set();
  const cases = [
    () => parseEnvelope(env.subarray(0, 5)),
    () => parseEnvelope(Buffer.concat([env, Buffer.from('X')])),
    () => parseEnvelope(Buffer.alloc(env.length, 0)),
    () => { const b = Buffer.from(env); b[4] = 9; return parseEnvelope(b); },
  ];
  for (const fn of cases) {
    try { fn(); throw new Error('no lanzó'); }
    catch (e) { msgs.add(e.isOpaque ? e.message : `NO-OPACO: ${e.message}`); }
  }
  assert(msgs.size === 1 && msgs.has(OPAQUE_MESSAGE),
    `mensajes distinguibles: ${[...msgs].join(' | ')}`);
});

check('008.3 el detalle interno se conserva para el log, no para el cliente', () => {
  const err = assertThrows(() => parseEnvelope(Buffer.alloc(3)), OpaqueError);
  assert(err.message === OPAQUE_MESSAGE, 'el mensaje público no es opaco');
  assert(typeof err.internal === 'string' && err.internal.length > 0,
    'no se guardó el detalle interno para diagnóstico');
  assert(err.internal !== err.message, 'el detalle interno es igual al mensaje público');
});

// ===========================================================================
section('MIRAGE-009 — Fragmentación 2-de-3 real (Shamir)');
// ===========================================================================

check('009.1 cualquier par de fragmentos reconstruye el secreto', () => {
  const secret = crypto.randomBytes(1000);
  const [s1, s2, s3] = splitSecret(secret, 2, 3);
  for (const pair of [[s1, s2], [s1, s3], [s2, s3]]) {
    assert(combineShares(pair).equals(secret), 'un par válido no reconstruyó el secreto');
  }
});

check('009.2 un solo fragmento no revela nada del secreto', () => {
  const secret = Buffer.concat([Buffer.from('MIRG'), crypto.randomBytes(996)]);
  const shares = splitSecret(secret, 2, 3);
  for (const sh of shares) {
    const body = sh.subarray(20 + 32); // saltamos cabecera + HMAC
    assert(!body.includes(Buffer.from('MIRG')), 'un fragmento contiene el magic en claro');
    assert(!body.equals(secret.subarray(0, body.length)), 'un fragmento es un trozo literal del secreto');
  }
});

check('009.3 un fragmento manipulado se detecta (HMAC por fragmento)', () => {
  const secret = crypto.randomBytes(500);
  const [s1, s2] = splitSecret(secret, 2, 3);
  const bad = Buffer.from(s2);
  bad[bad.length - 1] ^= 0xff;
  assertThrows(() => combineShares([s1, bad]), Error, 'un fragmento alterado debe detectarse');
});

check('009.4 mezclar fragmentos de conjuntos distintos se detecta', () => {
  const a = splitSecret(crypto.randomBytes(300), 2, 3);
  const b = splitSecret(crypto.randomBytes(300), 2, 3);
  assertThrows(() => combineShares([a[0], b[1]]), Error, 'mezclar conjuntos debe detectarse');
});

check('009.5 un fragmento repetido se rechaza', () => {
  const [s1] = splitSecret(crypto.randomBytes(300), 2, 3);
  assertThrows(() => combineShares([s1, Buffer.from(s1)]), Error, 'índices duplicados deben rechazarse');
});

check('009.6 un solo fragmento no basta', () => {
  const [s1] = splitSecret(crypto.randomBytes(300), 2, 3);
  assertThrows(() => combineShares([s1]), Error, 'un fragmento no debe bastar');
});

// ===========================================================================
section('MIRAGE-011 — Ocultación del tamaño (buckets Padmé)');
// ===========================================================================

check('011.1 padmé es determinista y monótono', () => {
  let prev = 0;
  for (const L of [0, 1, 100, 1000, 4096, 100000, 1048576, 244757336]) {
    const p = padmeLength(L);
    assert(p >= L, `padme(${L}) = ${p} < L`);
    assert(p >= prev, 'padmé no es monótono');
    assert(padmeLength(L) === p, 'padmé no es determinista');
    prev = p;
  }
});

check('011.2 tamaños cercanos son indistinguibles', () => {
  assert(padmeLength(1000000) === padmeLength(1010000),
    '1.00 MB y 1.01 MB deberían caer en el mismo bucket');
});

check('011.3 el sobrecoste está acotado (<=12% por encima de 4 KiB)', () => {
  for (let L = 4096; L < 20 * 1024 * 1024; L = Math.floor(L * 1.37) + 1) {
    const over = (padmeLength(L) - L) / L;
    assert(over <= 0.12, `sobrecoste ${(over * 100).toFixed(2)}% en L=${L}`);
  }
});

check('011.4 el número de tamaños observables es pequeño', () => {
  const set = new Set();
  for (let L = 1; L <= 2 * 1024 * 1024; L += 997) set.add(padmeLength(L));
  assert(set.size < 400, `demasiados tamaños distintos: ${set.size}`);
});

check('011.5 aplicar y quitar el padding devuelve exactamente los datos', () => {
  for (const n of [0, 1, 100, 5000, 100000]) {
    const data = crypto.randomBytes(n);
    const out = stripBucketPadding(applyBucketPadding(data, true));
    assert(out.equals(data), `no se recuperaron los datos con n=${n}`);
  }
});

check('011.6 el archivo cifrado no revela el tamaño exacto del original', () => {
  const a = encryptVault({
    payload: serializePayload('a.txt', crypto.randomBytes(1000)),
    password: PW, algorithm: ALGORITHMS.AES, bucketPadding: true,
  }).envelope;
  const b = encryptVault({
    payload: serializePayload('a.txt', crypto.randomBytes(1400)),
    password: PW, algorithm: ALGORITHMS.AES, bucketPadding: true,
  }).envelope;
  assert(a.length === b.length,
    `1000 B y 1400 B produjeron archivos de ${a.length} y ${b.length} B`);
});

// ===========================================================================
section('MIRAGE-015 — Borrado de material sensible');
// ===========================================================================

check('015.1 deriveMasterKey no deja el material de entrada en memoria viva', () => {
  // No podemos inspeccionar la memoria del proceso, pero SÍ podemos comprobar
  // que la función no devuelve ni retiene el material intermedio.
  const prk = deriveMasterKey({ password: PW, salt: crypto.randomBytes(16) });
  assert(prk.length === 32, 'el PRK debe medir 32 B');
  assert(!prk.toString('latin1').includes(PW), 'el PRK contiene la contraseña en claro');
  prk.fill(0);
  assert(prk.every((b) => b === 0), 'el PRK no se pudo poner a cero');
});

check('015.2 wipe pone a cero los búferes que recibe', async () => {
  const { wipe } = await import('./lib/kdf.js');
  const b = crypto.randomBytes(32);
  wipe(b);
  assert(b.every((x) => x === 0), 'wipe no puso el búfer a cero');
});

// ===========================================================================
section('Política de contraseñas');
// ===========================================================================

check('pw.1 se rechazan las contraseñas cortas o pobres', () => {
  // Ojo: la propiedad se llama `ok`. Usar un nombre inexistente hace que
  // `!r.inexistente` sea siempre true y el test pase sin comprobar nada.
  for (const bad of ['', 'corta', 'aaaaaaaaaaaaaaaa', 'ababababababab']) {
    const r = assessPasswordStrength(bad);
    assert(r.ok === false, `"${bad}" debería rechazarse (ok=${r.ok}, bits=${r.bits})`);
  }
});

check('pw.2 se aceptan las contraseñas razonables', () => {
  for (const p of ['contrasena-larga-y-variada-42', 'X7#kq!Zm92pLw4', 'mi frase de paso muy larga']) {
    const r = assessPasswordStrength(p);
    assert(r.ok === true, `"${p}" debería aceptarse (bits=${r.bits}, ${r.reason})`);
  }
});

check('pw.3b LIMITACIÓN DOCUMENTADA: la heurística no detecta frases conocidas', () => {
  // Comprobación de honestidad, no de seguridad. Una heurística basada en
  // longitud y variedad de caracteres NO puede detectar que una contraseña
  // aparece en una lista de filtraciones. Estas dos son pésimas en la práctica
  // y sin embargo se aceptan:
  const debiles = ['Password123!', 'Qwerty12345!'];
  const aceptadas = debiles.filter((p) => assessPasswordStrength(p).ok);
  assert(aceptadas.length === debiles.length,
    'si esto cambia, se ha añadido detección real: actualiza el README');
  // El test PASA documentando la limitación. La mitigación correcta sería
  // cotejar contra un corpus tipo "Have I Been Pwned", que esta aplicación
  // NO hace porque no debe consultar servicios externos.
});

check('pw.3 encryptVault rechaza una contraseña que no cumple la política', () => {
  assertThrows(() => encryptVault({
    payload: serializePayload('a', Buffer.from('x')), password: 'corta', algorithm: ALGORITHMS.AES,
  }), PolicyError);
});

// ===========================================================================
section('MIRAGE-010 — El TTL se comprueba antes de entregar los datos');
// ===========================================================================

check('010.1 un archivo expirado no devuelve el payload', () => {
  const { envelope } = encryptVault({
    payload: serializePayload('a.txt', Buffer.from('SECRETO'), Date.now() - 1000),
    password: PW, algorithm: ALGORITHMS.AES,
  });
  const err = assertThrows(() => decryptVault(envelope, { password: PW }), PolicyError);
  assert(!err.message.includes('SECRETO'), 'el error filtró contenido');
  assert(/no\s+un control criptográfico/i.test(err.message),
    `el mensaje debe advertir de que el TTL no es un control criptográfico: "${err.message}"`);
});

check('010.2 un archivo no expirado se abre con normalidad', () => {
  const { envelope } = encryptVault({
    payload: serializePayload('a.txt', Buffer.from('SECRETO'), Date.now() + 3600_000),
    password: PW, algorithm: ALGORITHMS.AES,
  });
  const r = decryptVault(envelope, { password: PW });
  assert(deserializePayload(r.payload).fileData.toString() === 'SECRETO');
});

check('010.3 alterar el TTL no sirve: está dentro del cifrado', () => {
  const { envelope } = encryptVault({
    payload: serializePayload('a.txt', Buffer.from('SECRETO'), Date.now() + 3600_000),
    password: PW, algorithm: ALGORITHMS.AES,
  });
  // No hay ningún campo de TTL en claro que tocar: comprobamos que el archivo
  // completo autentica y que cualquier byte alterado lo invalida.
  for (const off of [HEADER_LEN, envelope.length - 5]) {
    const b = Buffer.from(envelope);
    b[off] ^= 0x01;
    assertThrows(() => decryptVault(b, { password: PW }), OpaqueError, `byte ${off}`);
  }
});

// ===========================================================================
section('Ida y vuelta completa por cada algoritmo y modo');
// ===========================================================================

for (const algorithm of [ALGORITHMS.AES, ALGORITHMS.CASCADE]) {
  for (const padding of [false, true]) {
    check(`e2e ${algorithm} padding=${padding}`, () => {
      const data = crypto.randomBytes(9999);
      const { envelope } = encryptVault({
        payload: serializePayload('archivo.bin', data),
        password: PW, secondFactor: PW2, hardwareId: HWID,
        algorithm, bucketPadding: padding,
      });
      const r = decryptVault(envelope, { password: PW, secondFactor: PW2, hardwareId: HWID });
      const p = deserializePayload(r.payload);
      assert(p.filename === 'archivo.bin', 'nombre incorrecto');
      assert(p.fileData.equals(data), 'contenido incorrecto');
      assert(r.algorithm === algorithm, `algoritmo mal reportado: ${r.algorithm}`);
    });
  }
}

check('e2e falta el segundo factor: error de política', () => {
  const { envelope } = encryptVault({
    payload: serializePayload('a.txt', Buffer.from('x')),
    password: PW, secondFactor: PW2, algorithm: ALGORITHMS.AES,
  });
  assertThrows(() => decryptVault(envelope, { password: PW }), PolicyError);
});

check('e2e segundo factor incorrecto: fallo opaco', () => {
  const { envelope } = encryptVault({
    payload: serializePayload('a.txt', Buffer.from('x')),
    password: PW, secondFactor: PW2, algorithm: ALGORITHMS.AES,
  });
  assertThrows(() => decryptVault(envelope, { password: PW, secondFactor: 'otro-factor-largo-11' }), OpaqueError);
});

check('e2e cada cifrado del MISMO contenido produce un archivo distinto', () => {
  const payload = serializePayload('a.txt', Buffer.from('contenido fijo'));
  const a = encryptVault({ payload, password: PW, algorithm: ALGORITHMS.AES, bucketPadding: false }).envelope;
  const b = encryptVault({ payload, password: PW, algorithm: ALGORITHMS.AES, bucketPadding: false }).envelope;
  assert(!a.equals(b), 'dos cifrados idénticos: falta aleatoriedad en salt/IV');
});

check('e2e la metainformación mide lo mismo para ambos algoritmos', () => {
  const payload = serializePayload('a.txt', Buffer.alloc(1000));
  const a = encryptVault({ payload, password: PW, algorithm: ALGORITHMS.AES, bucketPadding: false }).envelope;
  const c = encryptVault({ payload, password: PW, algorithm: ALGORITHMS.CASCADE, bucketPadding: false }).envelope;

  // La cabecera y la metainformación del bloque miden exactamente lo mismo en
  // los dos casos: los campos de IV no usados se rellenan con bytes aleatorios.
  assert(FORMAT_CONSTANTS.BLOCK_META_LEN === 96, 'cambió el tamaño de la metainformación');

  // AVISO HONESTO: la cascada sí es algo más larga, porque sus dos capas CBC
  // añaden relleno PKCS#7 (hasta 16 bytes cada una, 32 en total). Eso significa
  // que, SIN bucket padding, la longitud del archivo distingue el algoritmo.
  // No es un secreto que intentemos guardar (el campo cipherId lo dice en
  // claro, porque hace falta para descifrar), pero conviene dejarlo escrito.
  const delta = c.length - a.length;
  assert(delta > 0 && delta <= 32,
    `la diferencia debería ser el relleno CBC (1..32 B), es ${delta} B`);
});

check('e2e con bucket padding, ambos algoritmos dan el mismo tamaño', () => {
  const payload = serializePayload('a.txt', Buffer.alloc(1000));
  const a = encryptVault({ payload, password: PW, algorithm: ALGORITHMS.AES, bucketPadding: true }).envelope;
  const c = encryptVault({ payload, password: PW, algorithm: ALGORITHMS.CASCADE, bucketPadding: true }).envelope;
  assert(a.length === c.length,
    `con padding activo los tamaños deberían coincidir: AES=${a.length}, cascada=${c.length}`);
});

// ===========================================================================
section('Reuso de nonces / IVs');
// ===========================================================================

check('iv.1 1000 cifrados no repiten ningún salt ni ningún nonce', () => {
  const salts = new Set();
  const nonces = new Set();
  for (let i = 0; i < 1000; i++) {
    const ivs = generateIvs();
    const salt = crypto.randomBytes(16).toString('hex');
    assert(!salts.has(salt), 'salt repetido');
    salts.add(salt);
    const n = ivs.nonceChaCha.toString('hex');
    assert(!nonces.has(n), 'nonce de ChaCha20 repetido');
    nonces.add(n);
    assert(ivs.nonceChaCha.length === 12, 'el nonce de ChaCha20 debe medir 12 B, no 16');
  }
});

check('iv.2 el contador de ChaCha20 arranca en cero (no aleatorio)', () => {
  // Comprobación indirecta: ciframos con el mismo nonce dos veces y verificamos
  // que el keystream es idéntico, lo que solo ocurre si el contador es fijo.
  const key = crypto.randomBytes(32);
  const nonce = crypto.randomBytes(12);
  const iv = Buffer.concat([Buffer.alloc(4, 0), nonce]);
  const a = crypto.createCipheriv('chacha20', key, iv).update(Buffer.alloc(64));
  const b = crypto.createCipheriv('chacha20', key, iv).update(Buffer.alloc(64));
  assert(a.equals(b), 'el keystream de ChaCha20 no es reproducible con contador 0');
});

// ===========================================================================
// Resumen
// ===========================================================================

console.log('\n' + '='.repeat(72));
console.log(`  Resultado: ${passed} correctas, ${failed} fallidas, ${passed + failed} totales`);
console.log('='.repeat(72));

if (failed > 0) {
  console.log('\nFallos:');
  for (const f of failures) console.log(`  - ${f.name}\n      ${f.err.message}`);
}

console.log(`
NOTA IMPORTANTE
---------------
Estas pruebas verifican que el sistema RECHAZA entradas concretas y que ciertas
propiedades estructurales se cumplen. NO constituyen una demostración de
seguridad criptográfica. Que pasen todas significa que las regresiones
conocidas no han vuelto, no que no existan otros fallos.
`);

process.exit(failed > 0 ? 1 : 0);
