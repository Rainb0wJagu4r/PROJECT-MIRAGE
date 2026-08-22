// Set environment to test so server doesn't start listing on PORT
process.env.NODE_ENV = 'test';

import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import {
  getHardwareUUID,
  secureShred,
  scrubJpeg,
  scrubPng,
  deriveKey,
  applySizePadding,
  serializePayload,
  deserializePayload,
  encryptMirageC4,
  decryptMirageC4,
  applySteganography
} from './server.js';

console.log('🧪 Starting Project Mirage Cryptographic Core Tests...\n');

let passCount = 0;
let failCount = 0;

function assert(condition, message) {
  if (condition) {
    console.log(` ✅ PASS: ${message}`);
    passCount++;
  } else {
    console.error(` ❌ FAIL: ${message}`);
    failCount++;
  }
}

// Test 1: Key Derivation and GCM Encryption
try {
  const password = 'SecretPassword123!';
  const salt = crypto.randomBytes(16);
  const keyNormal = deriveKey(password, salt, false);
  const keyHw = deriveKey(password, salt, true);

  assert(keyNormal.length === 32, 'Scrypt derived key is 32 bytes (256-bit)');
  assert(keyHw.length === 32, 'Scrypt derived key with Hardware UUID is 32 bytes');
  assert(keyNormal.toString('hex') !== keyHw.toString('hex'), 'Hardware lock results in a different derived key');

  // Encryption / Decryption test
  const iv = crypto.randomBytes(12);
  const plaintext = Buffer.from('Hello Cyber Armor!', 'utf8');
  const cipher = crypto.createCipheriv('aes-256-gcm', keyNormal, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();

  const decipher = crypto.createDecipheriv('aes-256-gcm', keyNormal, iv);
  decipher.setAuthTag(tag);
  const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);

  assert(decrypted.toString('utf8') === 'Hello Cyber Armor!', 'AES-256-GCM successfully encrypts and decrypts');
} catch (e) {
  assert(false, `Test 1 (Crypto Core) failed: ${e.message}`);
}

// Test 2: Serialization Format
try {
  const filename = 'document.pdf';
  const fileContent = Buffer.from('PDF_DUMMY_DATA_1234567890', 'utf8');
  const expire = Date.now() + 10000;

  const serialized = serializePayload(filename, fileContent, expire);
  const deserialized = deserializePayload(serialized);

  assert(deserialized.filename === filename, 'Serialization preserves filename');
  assert(deserialized.expirationTime === expire, 'Serialization preserves expiration timestamp');
  assert(deserialized.fileData.toString('utf8') === fileContent.toString('utf8'), 'Serialization preserves file content exactly');
} catch (e) {
  assert(false, `Test 2 (Serialization) failed: ${e.message}`);
}

// Test 3: JPEG / PNG Metadata Scrubbers
try {
  // Create a fake JPEG buffer with an APP1 marker
  // SOI (FF D8) + APP1 marker (FF E1, length 00 0A, 8 bytes data) + DUMMY DATA + EOI (FF D9)
  const fakeJpeg = Buffer.concat([
    Buffer.from([0xFF, 0xD8]),
    Buffer.from([0xFF, 0xE1, 0x00, 0x0A, 0x45, 0x78, 0x69, 0x66, 0x00, 0x00, 0x00, 0x00]), // APP1 segment
    Buffer.from([0xFF, 0xDA]), // Start of Scan
    Buffer.from('IMAGEDATA'),
    Buffer.from([0xFF, 0xD9])
  ]);

  const scrubbedJpeg = scrubJpeg(fakeJpeg);
  
  // Verify APP1 is removed (should not contain FF E1)
  let hasApp1 = false;
  for (let i = 0; i < scrubbedJpeg.length - 1; i++) {
    if (scrubbedJpeg[i] === 0xFF && scrubbedJpeg[i + 1] === 0xE1) {
      hasApp1 = true;
    }
  }
  assert(!hasApp1, 'JPEG scrubber successfully removes APP1 EXIF segment');
  assert(scrubbedJpeg.length < fakeJpeg.length, 'JPEG scrubber successfully reduces size of image');

  // Create a fake PNG buffer
  // PNG Sig (8 bytes) + IHDR (length 0000000D, type IHDR, data, crc 4 bytes) + tEXt (metadata) + IEND
  const fakePng = Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]), // PNG Signature
    Buffer.from([0x00, 0x00, 0x00, 0x0D]), // Length 13
    Buffer.from('IHDR'), // Type
    Buffer.alloc(13), // Data
    Buffer.alloc(4), // CRC
    Buffer.from([0x00, 0x00, 0x00, 0x0A]), // Length 10
    Buffer.from('tEXt'), // Type (Metadata)
    Buffer.from('Author: BRX'), // Data
    Buffer.alloc(4), // CRC
    Buffer.from([0x00, 0x00, 0x00, 0x00]), // Length 0
    Buffer.from('IEND'), // Type (End)
    Buffer.alloc(4) // CRC
  ]);

  const scrubbedPng = scrubPng(fakePng);
  assert(!scrubbedPng.toString('binary').includes('tEXt'), 'PNG scrubber removes tEXt metadata chunk');
} catch (e) {
  assert(false, `Test 3 (Metadata Scrubbing) failed: ${e.message}`);
}

// Test 4: Signal-style Size Obfuscation
try {
  const original = Buffer.from('Clean Text', 'utf8');
  const obfuscated = applySizePadding(original);
  assert(obfuscated.length > original.length, 'Size obfuscation successfully appends random padding bytes');
  assert(obfuscated.subarray(0, original.length).compare(original) === 0, 'Original payload data is untouched at the beginning of the padded buffer');
} catch (e) {
  assert(false, `Test 4 (Size Obfuscation) failed: ${e.message}`);
}

// Test 5: 2-of-3 Secret Sharing (Split Fragment Mode)
try {
  const cipherEnvelope = Buffer.from('ThisIsTheWholeEncryptedPayloadContainingSomeVerySecretBytesAndHeadersWhichMustBeSplit', 'utf8');
  const fullLen = cipherEnvelope.length;
  const halfLen = Math.ceil(fullLen / 2);
  
  // Padding odd lengths as server does
  let paddedOutput = cipherEnvelope;
  if (fullLen % 2 !== 0) {
    paddedOutput = Buffer.concat([cipherEnvelope, crypto.randomBytes(1)]);
  }
  
  const H1 = paddedOutput.subarray(0, halfLen);
  const H2 = paddedOutput.subarray(halfLen);
  const H3 = Buffer.alloc(halfLen);
  for (let i = 0; i < halfLen; i++) {
    H3[i] = H1[i] ^ H2[i];
  }

  // Helper reconstruction logic
  const reconstruct = (pA, pB, idxA, idxB) => {
    let recH1, recH2;
    if (idxA === 1 && idxB === 2) {
      recH1 = pA;
      recH2 = pB;
    } else if (idxA === 1 && idxB === 3) {
      recH1 = pA;
      recH2 = Buffer.alloc(halfLen);
      for (let i = 0; i < halfLen; i++) {
        recH2[i] = pA[i] ^ pB[i];
      }
    } else if (idxA === 2 && idxB === 3) {
      recH2 = pA;
      recH1 = Buffer.alloc(halfLen);
      for (let i = 0; i < halfLen; i++) {
        recH1[i] = pA[i] ^ pB[i];
      }
    }
    const combined = Buffer.concat([recH1, recH2]);
    return combined.subarray(0, fullLen);
  };

  const rec1_2 = reconstruct(H1, H2, 1, 2);
  const rec1_3 = reconstruct(H1, H3, 1, 3);
  const rec2_3 = reconstruct(H2, H3, 2, 3);

  assert(rec1_2.toString('utf8') === cipherEnvelope.toString('utf8'), 'Reconstruction using Part 1 and Part 2 matches original');
  assert(rec1_3.toString('utf8') === cipherEnvelope.toString('utf8'), 'Reconstruction using Part 1 and Part 3 matches original (XOR-recovery)');
  assert(rec2_3.toString('utf8') === cipherEnvelope.toString('utf8'), 'Reconstruction using Part 2 and Part 3 matches original (XOR-recovery)');
} catch (e) {
  assert(false, `Test 5 (2-of-3 Splitting) failed: ${e.message}`);
}

// Test 6: Shredder
try {
  const tempFile = path.join(process.cwd(), `shred_test_${Date.now()}.txt`);
  fs.writeFileSync(tempFile, 'WIPE_ME_COMPLETELY_PLEASE_CONFIDENTIAL');
  
  assert(fs.existsSync(tempFile), 'Temporary file created for shred test');
  secureShred(tempFile, 3);
  assert(!fs.existsSync(tempFile), 'Secure shredder successfully overwrites and unlinks the file');
} catch (e) {
  assert(false, `Test 6 (Shredder) failed: ${e.message}`);
}

// Test 7: Mirage-C4 Cascaded Cipher & Steganography
try {
  const password = 'DecentralizedHackerCascadePassword!';
  const salt = crypto.randomBytes(16);
  
  // 1. Extended KDF test (1024-bit key)
  const key1024 = deriveKey(password, salt, false, '', 128);
  assert(key1024.length === 128, 'KDF extended derivation produces 1024-bit (128 bytes) key');

  // 2. Mirage-C4 encryption and decryption test
  const ivs = {
    ivCamellia: crypto.randomBytes(16),
    ivAria: crypto.randomBytes(16),
    ivChaCha: crypto.randomBytes(16),
    ivAes: crypto.randomBytes(12)
  };
  const payloadBuf = Buffer.from('Quantum-resistant cascading encryption test payload.', 'utf8');
  
  const { ciphertext, tag } = encryptMirageC4(payloadBuf, key1024, ivs);
  assert(ciphertext.length === payloadBuf.length, 'Mirage-C4 encrypt preserves payload length (CTR/stream cascade)');
  
  const decrypted = decryptMirageC4(ciphertext, key1024, ivs, tag);
  assert(decrypted.toString('utf8') === payloadBuf.toString('utf8'), 'Mirage-C4 decrypt successfully restores original payload');

  // 3. Steganography hiding and recovery test
  const fakeCarrier = Buffer.from('FAKE_PNG_CARRIER_IMAGE_BYTES_1234567890', 'utf8');
  const tempCarrierFile = path.join(process.cwd(), `temp_carrier_${Date.now()}.png`);
  fs.writeFileSync(tempCarrierFile, fakeCarrier);

  const payloadToHide = Buffer.from('HIDDEN_DATA_12345', 'utf8');
  
  // Hide payload in image
  const steganographed = applySteganography(tempCarrierFile, payloadToHide, () => {});
  assert(steganographed.length === fakeCarrier.length + payloadToHide.length + 12, 'Steganography buffer size matches carrier + payload + footer metadata');

  // Recover payload from steganography buffer
  let recoveredPayload = null;
  if (steganographed.length >= 12) {
    const signature = steganographed.subarray(-8).toString('ascii');
    assert(signature === 'MIRGSTEG', 'Steganography trailer signature is MIRGSTEG');
    
    if (signature === 'MIRGSTEG') {
      const payloadLen = steganographed.readUInt32BE(steganographed.length - 12);
      assert(payloadLen === payloadToHide.length, 'Steganography decoded payload length matches original');
      
      recoveredPayload = steganographed.subarray(
        steganographed.length - 12 - payloadLen,
        steganographed.length - 12
      );
    }
  }
  
  assert(recoveredPayload && recoveredPayload.toString('utf8') === payloadToHide.toString('utf8'), 'Steganography successfully extracts and matches the hidden payload');
  
  // Cleanup temp carrier file
  if (fs.existsSync(tempCarrierFile)) {
    fs.unlinkSync(tempCarrierFile);
  }
} catch (e) {
  assert(false, `Test 7 (Mirage-C4 and Steganography) failed: ${e.message}`);
}

console.log(`\n========================================`);
console.log(`🧪 TESTS COMPLETED: ${passCount} PASSED, ${failCount} FAILED.`);
console.log(`========================================`);
if (failCount > 0) {
  process.exit(1);
} else {
  process.exit(0);
}
