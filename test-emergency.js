import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import os from 'os';
import {
  isSystemPath,
  serializeMultiPayload,
  deserializeMultiPayload,
  scanEmergencyFiles,
  deriveKey,
  encryptMirageC4,
  decryptMirageC4,
  getDefaultEmergencyConfig,
  stopServer
} from './server.js';

let passed = 0;
let failed = 0;

function assert(condition, message) {
  if (condition) {
    console.log(` ✅ PASS: ${message}`);
    passed++;
  } else {
    console.error(` ❌ FAIL: ${message}`);
    failed++;
  }
}

console.log('🛡️ Starting Emergency Defense & Nuclear Options Test Suite...\n');

// 1. Test System Path Blacklist (Anti-Ransomware & System Safety Guard)
assert(isSystemPath('C:\\Windows'), 'System directory C:\\Windows is blocked');
assert(isSystemPath('C:\\Windows\\System32\\cmd.exe'), 'System binary C:\\Windows\\System32 is blocked');
assert(isSystemPath('C:\\Program Files'), 'C:\\Program Files is blocked');
assert(isSystemPath('C:\\Program Files (x86)'), 'C:\\Program Files (x86) is blocked');
assert(isSystemPath('C:\\'), 'Root drive C:\\ is blocked');
assert(isSystemPath('/'), 'Unix root / is blocked');
assert(isSystemPath('/etc/passwd'), 'Unix /etc is blocked');
assert(isSystemPath('C:\\Users'), 'Root C:\\Users directory is blocked');
assert(!isSystemPath('C:\\Users\\NHK-DB\\Documents\\MyVault'), 'User personal subfolder is allowed');
assert(!isSystemPath(path.join(os.homedir(), 'Desktop', 'EmergencyFiles')), 'User desktop subfolder is allowed');

// 2. Test Multi-file Payload Serialization & Deserialization
const testDir = path.join(os.tmpdir(), 'mirage_emergency_test_' + Date.now());
fs.mkdirSync(testDir, { recursive: true });

const file1Content = Buffer.from('Top secret document #1 content with sensitive financial data.', 'utf8');
const file2Content = Buffer.from('Confidential report #2 containing infrastructure keys and security certificates.', 'utf8');
const file3Content = crypto.randomBytes(1024 * 64); // 64KB binary

const f1Sha3 = crypto.createHash('sha3-256').update(file1Content).digest('hex');
const f2Sha3 = crypto.createHash('sha3-256').update(file2Content).digest('hex');
const f3Sha3 = crypto.createHash('sha3-256').update(file3Content).digest('hex');

const filesToBundle = [
  { relPath: 'finance/secret1.txt', buffer: file1Content, sha3: f1Sha3 },
  { relPath: 'reports/security_audit.pdf', buffer: file2Content, sha3: f2Sha3 },
  { relPath: 'keys/vault.bin', buffer: file3Content, sha3: f3Sha3 }
];

const bundledPayload = serializeMultiPayload(filesToBundle, 0);
assert(bundledPayload.length > file1Content.length + file2Content.length + file3Content.length, 'Multi-payload bundle created with proper metadata overhead');

const deserialized = deserializeMultiPayload(bundledPayload);
assert(deserialized.isMulti === true, 'Deserialized payload recognized as Multi-Vault package');
assert(deserialized.files.length === 3, 'Deserialized exactly 3 packaged files');
assert(deserialized.files[0].relPath === 'finance/secret1.txt', 'Preserved relative directory structure for file 1');
assert(deserialized.files[0].fileData.equals(file1Content), 'File 1 content matches byte-for-byte');
assert(deserialized.files[1].relPath === 'reports/security_audit.pdf', 'Preserved relative directory structure for file 2');
assert(deserialized.files[1].fileData.equals(file2Content), 'File 2 content matches byte-for-byte');
assert(deserialized.files[2].relPath === 'keys/vault.bin', 'Preserved relative directory structure for file 3');
assert(deserialized.files[2].fileData.equals(file3Content), 'File 3 binary content matches byte-for-byte');

// 3. Test Full Mirage-C4 Encryption & Decryption on Multi-Vault Package
const masterPassword = 'EmergencyMasterPassword2026!#Strong';
const salt = crypto.randomBytes(16);
const header = Buffer.from('MIRAGE\x01\x03', 'binary');
const ivCamellia = crypto.randomBytes(16);
const ivAria = crypto.randomBytes(16);
const ivChaCha = crypto.randomBytes(16);
const ivAes = crypto.randomBytes(12);
const ivs = { ivCamellia, ivAria, ivChaCha, ivAes };

const key128Bytes = deriveKey(masterPassword, salt, false, '', 128);
const { ciphertext, tag } = encryptMirageC4(bundledPayload, key128Bytes, ivs, header, salt);
assert(ciphertext && ciphertext.length === bundledPayload.length, 'Mirage-C4 (4x256-bit Cascade) encrypted the entire Multi-Vault payload without truncation');

const decryptedPayload = decryptMirageC4(ciphertext, key128Bytes, ivs, tag, header, salt);
assert(decryptedPayload.equals(bundledPayload), 'Mirage-C4 decrypted the Multi-Vault payload perfectly');

const restoredVault = deserializeMultiPayload(decryptedPayload);
assert(restoredVault.files.length === 3, 'Restored vault contains all 3 files after C4 decryption');
assert(restoredVault.files[0].sha3 === f1Sha3, 'SHA3-256 checksum verified for File 1');
assert(restoredVault.files[1].sha3 === f2Sha3, 'SHA3-256 checksum verified for File 2');
assert(restoredVault.files[2].sha3 === f3Sha3, 'SHA3-256 checksum verified for File 3');

// 4. Test File Scanning and Exclusion Filter
const scanDir = path.join(testDir, 'scan_target');
fs.mkdirSync(path.join(scanDir, 'subfolder'), { recursive: true });
fs.mkdirSync(path.join(scanDir, '.git'), { recursive: true });
fs.mkdirSync(path.join(scanDir, 'node_modules'), { recursive: true });

fs.writeFileSync(path.join(scanDir, 'doc1.docx'), 'Document content');
fs.writeFileSync(path.join(scanDir, 'subfolder', 'data.csv'), '1,2,3,4,5');
fs.writeFileSync(path.join(scanDir, 'temp.tmp'), 'Temporary trash');
fs.writeFileSync(path.join(scanDir, '.git', 'HEAD'), 'ref: refs/heads/main');
fs.writeFileSync(path.join(scanDir, 'node_modules', 'dummy.js'), 'console.log("module")');

const scanResult = scanEmergencyFiles([scanDir], ['.git', 'node_modules', '.tmp']);
assert(scanResult.totalCount === 2, `Scanner identified exactly 2 files to protect (found: ${scanResult.totalCount})`);
assert(scanResult.excludedCount >= 3, `Scanner properly excluded excluded items (count: ${scanResult.excludedCount})`);
assert(scanResult.files.some(f => f.name === 'doc1.docx'), 'Included doc1.docx');
assert(scanResult.files.some(f => f.name === 'data.csv'), 'Included subfolder/data.csv');
assert(!scanResult.files.some(f => f.name === 'temp.tmp'), 'Excluded temp.tmp');
assert(!scanResult.files.some(f => f.name === 'HEAD'), 'Excluded .git/HEAD');

// 5. Test Default Configuration
const defaultConfig = getDefaultEmergencyConfig();
assert(defaultConfig.algorithm === 'mirage-c4', 'Default emergency algorithm is MIRAGE-C4');
assert(defaultConfig.backupEnabled === true, 'Safety backup is enabled by default');
assert(defaultConfig.shredOriginalEnabled === false, 'Secure shredder is disabled by default for safety');

// Clean up temporary test files
try {
  fs.rmSync(testDir, { recursive: true, force: true });
} catch (e) {}

stopServer();

console.log('\n========================================');
console.log(`🛡️ EMERGENCY DEFENSE TESTS: ${passed} PASSED, ${failed} FAILED.`);
console.log('========================================\n');

if (failed > 0) {
  process.exit(1);
}
