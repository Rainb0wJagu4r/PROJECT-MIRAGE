import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { encryptMirageC4 } from './server.js';

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
  const K = crypto.randomBytes(128); // 128-byte key (1024 bits)
  
  const ivs = {
    ivCamellia: crypto.randomBytes(16),
    ivAria: crypto.randomBytes(16),
    ivChaCha: crypto.randomBytes(16),
    ivAes: crypto.randomBytes(12)
  };
  const header = Buffer.from('MIRAGE\x01\x03', 'binary');
  
  // 1. Baseline ciphertext
  const { ciphertext: C } = encryptMirageC4(P, K, ivs, header);
  const totalBits = C.length * 8;
  
  let totalPlaintextDist = 0;
  let totalKeyDist = 0;
  
  // Run iterations
  for (let i = 0; i < runs; i++) {
    // A. Plaintext Avalanche (Plaintext SAC)
    // Flip 1 random bit in original plaintext P
    const P_prime = flipRandomBit(P);
    const { ciphertext: C_prime } = encryptMirageC4(P_prime, K, ivs, header);
    totalPlaintextDist += hammingDistance(C, C_prime);
    
    // B. Key Avalanche (Key SAC)
    // Flip 1 random bit in key K
    const K_prime = flipRandomBit(K);
    const { ciphertext: C_double_prime } = encryptMirageC4(P, K_prime, ivs, header);
    totalKeyDist += hammingDistance(C, C_double_prime);
  }
  
  const avgPlaintextSac = (totalPlaintextDist / (runs * totalBits)) * 100;
  const avgKeySac = (totalKeyDist / (runs * totalBits)) * 100;
  
  console.log(`Plaintext SAC (Strict Avalanche Criterion): ${avgPlaintextSac.toFixed(3)}%`);
  console.log(`Key SAC (Strict Avalanche Criterion): ${avgKeySac.toFixed(3)}%`);
  
  const results = {
    plaintext_sac: parseFloat(avgPlaintextSac.toFixed(3)),
    key_sac: parseFloat(avgKeySac.toFixed(3))
  };
  
  const outputPath = path.join(__dirname, 'avalanche_results.json');
  fs.writeFileSync(outputPath, JSON.stringify(results, null, 2));
  console.log(`Results successfully saved to ${outputPath}`);
}

// Run the script
runAvalancheAnalysis(100);
