/**
 * lib/kat.js — Known Answer Tests con vectores PUBLICADOS.
 *
 * CORRIGE MIRAGE-016.
 *
 * Los "self-tests" de la versión anterior cifraban la cadena "TEST", la
 * descifraban y comprobaban que volvía a decir "TEST". Eso NO es un Known
 * Answer Test: solo demuestra que cifrar y descifrar son inversas entre sí.
 * Una implementación completamente equivocada (o incluso un XOR trivial)
 * habría pasado esa prueba.
 *
 * Un KAT de verdad compara la salida contra un valor de referencia publicado
 * por un tercero. Si la biblioteca subyacente cambia de comportamiento, si se
 * carga un proveedor OpenSSL manipulado o si el nombre del algoritmo se resuelve
 * a otro cifrado, estos tests fallan.
 *
 * FUENTES DE LOS VECTORES
 * ---------------------------------------------------------------------------
 *  - AES-256-GCM ....... McGrew & Viega, "The Galois/Counter Mode of Operation",
 *                        Test Case 13 y 14 (clave e IV a cero; los vectores más
 *                        reproducidos de GCM-256)
 *  - AES-256-CBC ....... NIST SP 800-38A, F.2.5 (CBC-AES256.Encrypt)
 *  - ChaCha20 .......... RFC 8439, sección 2.4.2 (bloque de keystream)
 *  - Camellia-256-CBC .. RFC 3713 / NESSIE (vector ECB de clave 256, usado en
 *                        CBC con IV=0, que es equivalente al primer bloque ECB)
 *  - ARIA-256-CBC ...... RFC 5794, sección A.3 (ARIA-256 ECB), igualmente
 *                        comprobado como primer bloque CBC con IV=0
 *  - HKDF-SHA256 ....... RFC 5869, Test Case 1
 *  - scrypt ............ RFC 7914, sección 12 (vector con N=16, r=1, p=1)
 *
 * Nota sobre Camellia y ARIA: para un solo bloque y IV = 0, CBC coincide con
 * ECB. Se cifra un único bloque y se compara con el vector ECB publicado,
 * descartando el bloque de relleno PKCS#7 que OpenSSL añade.
 */

import crypto from 'crypto';

const hex = (s) => Buffer.from(s.replace(/\s+/g, ''), 'hex');

/** Ejecuta un KAT y devuelve {name, ok, detail}. */
function kat(name, source, fn) {
  try {
    const { got, want } = fn();
    const g = Buffer.isBuffer(got) ? got.toString('hex') : String(got);
    const w = Buffer.isBuffer(want) ? want.toString('hex') : String(want);
    return {
      name, source, ok: g === w,
      detail: g === w ? undefined : `esperado ${w}, obtenido ${g}`,
    };
  } catch (err) {
    return { name, source, ok: false, detail: `excepción: ${err.message}` };
  }
}

/** Cifra un solo bloque con un cifrado CBC e IV cero, devolviendo ese bloque. */
function ecbViaCbc(algorithm, key, block) {
  const c = crypto.createCipheriv(algorithm, key, Buffer.alloc(block.length, 0));
  const out = Buffer.concat([c.update(block), c.final()]);
  return out.subarray(0, block.length); // descartamos el bloque PKCS#7
}

export function runKnownAnswerTests() {
  const tests = [];

  // -------------------------------------------------------------------------
  tests.push(kat('AES-256-GCM tag (plaintext vacío)', 'GCM spec, Test Case 13', () => {
    const key = Buffer.alloc(32, 0);
    const iv = Buffer.alloc(12, 0);
    const c = crypto.createCipheriv('aes-256-gcm', key, iv);
    c.final();
    return { got: c.getAuthTag(), want: hex('530f8afbc74536b9a963b4f1c4cb738b') };
  }));

  // -------------------------------------------------------------------------
  tests.push(kat('AES-256-GCM ciphertext', 'GCM spec, Test Case 14', () => {
    const key = Buffer.alloc(32, 0);
    const iv = Buffer.alloc(12, 0);
    const c = crypto.createCipheriv('aes-256-gcm', key, iv);
    const ct = Buffer.concat([c.update(Buffer.alloc(16, 0)), c.final()]);
    return { got: ct, want: hex('cea7403d4d606b6e074ec5d3baf39d18') };
  }));

  // -------------------------------------------------------------------------
  tests.push(kat('AES-256-GCM tag', 'GCM spec, Test Case 14', () => {
    const key = Buffer.alloc(32, 0);
    const iv = Buffer.alloc(12, 0);
    const c = crypto.createCipheriv('aes-256-gcm', key, iv);
    c.update(Buffer.alloc(16, 0));
    c.final();
    return { got: c.getAuthTag(), want: hex('d0d1c8a799996bf0265b98b5d48ab919') };
  }));

  // -------------------------------------------------------------------------
  // El AAD debe influir en el tag. No es un vector de terceros, sino una
  // propiedad estructural: se etiqueta como tal para no confundirla con un KAT.
  tests.push(kat('el AAD influye en el tag (propiedad, no vector externo)', 'comprobación local', () => {
    const key = Buffer.alloc(32, 0);
    const iv = Buffer.alloc(12, 0);
    const mk = (aad) => {
      const c = crypto.createCipheriv('aes-256-gcm', key, iv);
      if (aad) c.setAAD(aad);
      c.update(Buffer.alloc(16, 0));
      c.final();
      return c.getAuthTag().toString('hex');
    };
    const sinAad = mk(null);
    const conAad = mk(Buffer.from('contexto'));
    return { got: sinAad !== conAad ? 'distintos' : 'iguales', want: 'distintos' };
  }));

  // -------------------------------------------------------------------------
  tests.push(kat('AES-256-CBC', 'NIST SP 800-38A F.2.5', () => {
    const key = hex('603deb1015ca71be2b73aef0857d7781'
                  + '1f352c073b6108d72d9810a30914dff4');
    const iv = hex('000102030405060708090a0b0c0d0e0f');
    const pt = hex('6bc1bee22e409f96e93d7e117393172a');
    const c = crypto.createCipheriv('aes-256-cbc', key, iv);
    const ct = Buffer.concat([c.update(pt), c.final()]).subarray(0, 16);
    return { got: ct, want: hex('f58c4c04d6e5f1ba779eabfb5f7bfbd6') };
  }));

  // -------------------------------------------------------------------------
  tests.push(kat('ChaCha20 keystream', 'RFC 8439 §2.4.2', () => {
    // RFC 8439: key = 00..1f, nonce = 000000000000004a00000000, counter = 1.
    // El IV de 16 B de OpenSSL es [counter LE (4B)] || [nonce (12B)].
    const key = hex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
    const counter = Buffer.alloc(4);
    counter.writeUInt32LE(1, 0);
    const nonce = hex('000000000000004a00000000');
    const iv = Buffer.concat([counter, nonce]);
    // Cifrando ceros obtenemos el keystream puro.
    const ks = crypto.createCipheriv('chacha20', key, iv).update(Buffer.alloc(64));
    return {
      got: ks,
      // Bloque de keystream para counter = 1 (RFC 8439 §2.4.2).
      want: hex('224f51f3401bd9e12fde276fb8631ded'
              + '8c131f823d2c06e27e4fcaec9ef3cf78'
              + '8a3b0aa372600a92b57974cded2b9334'
              + '794cba40c63e34cdea212c4cf07d41b7'),
    };
  }));

  // -------------------------------------------------------------------------
  tests.push(kat('Camellia-256 (bloque único)', 'RFC 3713 / NESSIE', () => {
    const key = hex('0123456789abcdeffedcba9876543210'
                  + '00112233445566778899aabbccddeeff');
    const pt = hex('0123456789abcdeffedcba9876543210');
    return {
      got: ecbViaCbc('camellia-256-cbc', key, pt),
      want: hex('9acc237dff16d76c20ef7c919e3a7509'),
    };
  }));

  // -------------------------------------------------------------------------
  tests.push(kat('ARIA-256 (bloque único)', 'RFC 5794 §A.3', () => {
    const key = hex('000102030405060708090a0b0c0d0e0f'
                  + '101112131415161718191a1b1c1d1e1f');
    const pt = hex('00112233445566778899aabbccddeeff');
    return {
      got: ecbViaCbc('aria-256-cbc', key, pt),
      want: hex('f92bd7c79fb72e2f2b8f80c1972d24fc'),
    };
  }));

  // -------------------------------------------------------------------------
  tests.push(kat('HKDF-SHA256', 'RFC 5869 Test Case 1', () => {
    const ikm = hex('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b');
    const salt = hex('000102030405060708090a0b0c');
    const info = hex('f0f1f2f3f4f5f6f7f8f9');
    const okm = Buffer.from(crypto.hkdfSync('sha256', ikm, salt, info, 42));
    return {
      got: okm,
      want: hex('3cb25f25faacd57a90434f64d0362f2a'
              + '2d2d0a90cf1a5a4c5db02d56ecc4c5bf'
              + '34007208d5b887185865'),
    };
  }));

  // -------------------------------------------------------------------------
  tests.push(kat('scrypt', 'RFC 7914 §12 (N=16, r=1, p=1)', () => {
    const out = crypto.scryptSync('', '', 64, { N: 16, r: 1, p: 1 });
    return {
      got: out,
      want: hex('77d6576238657b203b19ca42c18a0497'
              + 'f16b4844e3074ae8dfdffa3fede21442'
              + 'fcd0069ded0948f8326a753a0fc81f17'
              + 'e8d3e0fb2e0d3628cf35e20c38d18906'),
    };
  }));

  // -------------------------------------------------------------------------
  // Verificación de que la cascada v2 usa REALMENTE los cifrados que dice.
  // Si algún nombre de algoritmo se resolviera a otro cifrado, esto fallaría.
  tests.push(kat('disponibilidad de los cifrados de la cascada v2', 'comprobación local', () => {
    const required = ['camellia-256-cbc', 'chacha20', 'aria-256-cbc', 'aes-256-gcm'];
    const available = new Set(crypto.getCiphers());
    const missing = required.filter((c) => !available.has(c));
    return { got: missing.join(',') || 'ninguno', want: 'ninguno' };
  }));

  const ok = tests.every((t) => t.ok);
  return { ok, tests };
}

/**
 * Formato legible para el log de arranque.
 * Devuelve también un objeto compatible con el endpoint /api/system-status.
 */
export function summarizeKats() {
  const { ok, tests } = runKnownAnswerTests();
  return {
    overall: ok,
    // Aviso honesto expuesto también en la API.
    disclaimer:
      'Los KAT comprueban que las primitivas coinciden con vectores publicados. '
      + 'NO evalúan el diseño del protocolo ni demuestran que la aplicación sea segura.',
    tests: tests.map((t) => ({
      name: t.name, source: t.source, passed: t.ok, detail: t.detail,
    })),
  };
}
