import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { encryptCascade, generateIvs } from './lib/cascade.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

function hammingDistance(buf1, buf2) {
  let distance = 0;
  const len = Math.min(buf1.length, buf2.length);
  for (let i = 0; i < len; i++) {
    let xor = buf1[i] ^ buf2[i];
    while (xor > 0) {
      if (xor & 1) distance++;
      xor >>= 1;
    }
  }
  distance += Math.abs(buf1.length - buf2.length) * 8;
  return distance;
}

function flipRandomBit(buf) {
  const newBuf = Buffer.from(buf);
  if (buf.length === 0) return newBuf;
  const byteIdx = Math.floor(Math.random() * buf.length);
  const bitIdx = Math.floor(Math.random() * 8);
  newBuf[byteIdx] ^= (1 << bitIdx);
  return newBuf;
}

function runAvalancheAnalysis(runs = 100) {
  console.log(`Running Avalanche effect analysis for Mirage-C4 (${runs} iterations)...`);
  
  // Setup baseline variables
  const payloadSize = 10000; // 10KB message (80,000 bits)
  const P = crypto.randomBytes(payloadSize);

  // NOTA (MIRAGE-016): antes se usaba una clave de 128 bytes y se describia
  // como "1024 bits". Eso era enganoso. La cascada v2 deriva 4 subclaves de
  // 256 bits por HKDF a partir de un PRK de 32 bytes. La seguridad NO es de
  // 1024 bits: es del orden de 256 (~128 frente a Grover), igual que AES-256.
  const K = crypto.randomBytes(32); // PRK de 256 bits
  const salt = crypto.randomBytes(16);
  const ivs = generateIvs();
  const aadCtx = {
    magic: 'MIRG', version: 2, mode: 0x11, flags: 0,
    blockIndex: 0, blockCount: 1
  };

  // 1. Baseline ciphertext
  const { ciphertext: C } = encryptCascade(P, K, salt, ivs, aadCtx);
  const totalBits = C.length * 8;
  
  let totalPlaintextDist = 0;
  let totalKeyDist = 0;
  
  // Run iterations
  for (let i = 0; i < runs; i++) {
    // A. Plaintext Avalanche (Plaintext SAC)
    // Flip 1 random bit in original plaintext P
    const P_prime = flipRandomBit(P);
    const { ciphertext: C_prime } = encryptCascade(P_prime, K, salt, ivs, aadCtx);
    totalPlaintextDist += hammingDistance(C, C_prime);
    
    // B. Key Avalanche (Key SAC)
    // Flip 1 random bit in key K
    const K_prime = flipRandomBit(K);
    const { ciphertext: C_double_prime } = encryptCascade(P, K_prime, salt, ivs, aadCtx);
    totalKeyDist += hammingDistance(C, C_double_prime);
  }
  
  const avgPlaintextSac = (totalPlaintextDist / (runs * totalBits)) * 100;
  const avgKeySac = (totalKeyDist / (runs * totalBits)) * 100;
  
  console.log(`Plaintext SAC (Strict Avalanche Criterion): ${avgPlaintextSac.toFixed(3)}%`);
  console.log(`Key SAC (Strict Avalanche Criterion): ${avgKeySac.toFixed(3)}%`);
  
  // ---------------------------------------------------------------------
  // INTERPRETACION HONESTA DE ESTAS CIFRAS (leer antes de citarlas)
  //
  // El SAC de plaintext delata la linealidad de la cascada. Medido sobre la
  // cascada v1 (todo cifrados de flujo) daba 0.001%: al voltear un bit del
  // plaintext solo cambiaba ESE bit del ciphertext, porque la composicion se
  // reducia a P xor KS. Esa cifra era la huella de MIRAGE-002.
  //
  // La cascada v2 (Camellia-CBC + ChaCha20 + ARIA-CBC + AES-GCM) da ~25%
  // sobre el ciphertext COMPLETO. No es 50% por una razon estructural, no por
  // un defecto: CBC propaga los cambios solo hacia ADELANTE, asi que un bit
  // volteado en la posicion i altera de i al final y deja intacto el prefijo.
  // Un bit al azar cae de media a la mitad del mensaje -> ~50% de los bits
  // afectados x ~50% de cambio = ~25%. Es el comportamiento esperado.
  //
  // El SAC de clave si debe ser ~50% (aqui: 50.0%), porque una subclave
  // distinta cambia el cifrado entero desde el primer bloque.
  //
  // LIMITE DE ESTA PRUEBA: el SAC es una propiedad ESTRUCTURAL, no una
  // demostracion de seguridad. La cascada v1 pasaba tests estadisticos
  // mientras era trivialmente rompible. Un SAC bueno no descarta fallos; un
  // SAC malo (como el 0.001%) si es prueba de que algo esta roto.
  // ---------------------------------------------------------------------
  const results = {
    plaintext_sac: parseFloat(avgPlaintextSac.toFixed(3)),
    key_sac: parseFloat(avgKeySac.toFixed(3)),
    cascade_version: 2,
    note: 'plaintext_sac ~25% es lo esperado con capas CBC (propagacion solo hacia adelante). En la cascada v1 daba 0.001%, huella de MIRAGE-002 (colapso a un solo XOR). El SAC es una propiedad estructural, NO evidencia de seguridad criptografica.'
  };
  
  const outputPath = path.join(__dirname, 'avalanche_results.json');
  fs.writeFileSync(outputPath, JSON.stringify(results, null, 2));
  console.log(`Results successfully saved to ${outputPath}`);
}

// Run the script
runAvalancheAnalysis(100);
