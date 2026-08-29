# Código y formato obsoletos

Este documento lista lo que se ha retirado en la ronda 3 de auditoría y por qué.
Se mantiene para que quien audite el proyecto sepa qué buscar y qué NO usar.

## Formato de archivo v1 (magic `MIRAGE`) — OBSOLETO, solo lectura

Los `.wraith` creados antes de la ronda 3 usan la cascada v1. **Se siguen
abriendo** mediante `lib/legacy.js`, pero **no se puede crear ninguno nuevo**:
no existe función de cifrado v1, a propósito.

Motivo: la cascada v1 componía Camellia-CTR, ARIA-CTR, ChaCha20 y el CTR
interno de GCM. Los cuatro son cifrados de flujo, así que toda la cascada se
reducía a `P xor KS`. Consecuencias verificadas empíricamente:

- Con dos archivos cifrados con la misma contraseña y salt: `C1^C2 == P1^P2`.
- El keystream recuperado de un par `(C1, P1)` conocido descifraba un tercer
  archivo distinto.
- SAC de plaintext = **0.001%** (ver `avalanche_results.json` en el historial):
  voltear un bit del plaintext cambiaba solo ese bit del ciphertext.

**Acción recomendada:** re-cifra tus archivos a v2. Al abrir un v1, la
aplicación lo avisa.

## `test-crypto.js` — RETIRADO

Importaba `deriveKey`, `encryptMirageC4`, `decryptMirageC4` y
`applySizePadding`, eliminadas en la ronda 3. Además:

- Sus "Known Answer Tests" solo comprobaban que cifrar y descifrar eran
  funciones inversas. Eso no prueba nada: dos funciones mal implementadas de
  forma simétrica pasan ese test.
- Contenía la afirmación `'Quantum-resistant cascading encryption test payload.'`,
  que era falsa.

**Sustituido por:**

| Antes | Ahora | Qué comprueba |
|---|---|---|
| `test-crypto.js` | `test-security.mjs` | 73 casos adversariales (`npm test`) |
| "KAT" de ida y vuelta | `lib/kat.js` | 11 vectores publicados (`npm run test:kat`) |

## Funciones eliminadas de `server.js`

| Función | Sustituida por | Hallazgo |
|---|---|---|
| `deriveKey` | `lib/kdf.js` (`deriveMasterKey` + `deriveSubkey`) | 006, 007 |
| `encryptMirageC4` / `decryptMirageC4` | `lib/cascade.js` (`encryptCascade` / `decryptCascade`) | 002, 005 |
| `applySizePadding` | `lib/padding.js` (Padmé) | 011 |
| KAT de ida y vuelta | `lib/kat.js` | 016 |

## Afirmaciones retiradas

- **"Post-Quantum Cryptography: Enabled"** — falso. El cifrado de archivos no
  usa ningún KEM post-cuántico.
- **"1024 bits" / clave de 128 bytes** — engañoso. La cascada usa 4 subclaves
  de 256 bits derivadas por HKDF. La seguridad es del orden de 256 bits
  (~128 frente a Grover), igual que AES-256 bien usado. Encadenar cifrados
  **no suma** tamaños de clave.
- **`upToDate: true`** en `/api/system-status` — estaba escrito a mano y no
  comprobaba nada.

## Qué aporta la cascada realmente

Defensa en profundidad frente a un fallo criptoanalítico futuro en **uno** de
los cuatro cifrados. No multiplica el tamaño de clave ni sustituye a usar
AES-256 correctamente.
