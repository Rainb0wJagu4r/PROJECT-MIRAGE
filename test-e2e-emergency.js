import http from 'http';
import fs from 'fs';
import path from 'path';
import os from 'os';
import crypto from 'crypto';
import { startServer, stopServer, API_TOKEN } from './server.js';

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

async function apiRequest(endpoint, method = 'GET', body = null) {
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : null;
    const req = http.request({
      hostname: '127.0.0.1',
      port: 3001,
      path: endpoint,
      method,
      headers: {
        'Content-Type': 'application/json',
        'X-API-Token': API_TOKEN,
        ...(data ? { 'Content-Length': Buffer.byteLength(data) } : {})
      }
    }, (res) => {
      let resData = '';
      res.on('data', chunk => { resData += chunk; });
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, data: JSON.parse(resData) });
        } catch (e) {
          resolve({ status: res.statusCode, text: resData });
        }
      });
    });

    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}

async function runE2ETests() {
  console.log('🧪 Starting End-to-End Emergency Defense API Tests...\n');
  
  // Start server
  await startServer(3001);

  const testVaultDir = path.join(os.tmpdir(), 'mirage_e2e_vault_' + Date.now());
  const testTargetDir = path.join(os.tmpdir(), 'mirage_e2e_targets_' + Date.now());
  const testRestoreDir = path.join(os.tmpdir(), 'mirage_e2e_restored_' + Date.now());
  const testBackupDir = path.join(os.tmpdir(), 'mirage_e2e_backups_' + Date.now());

  fs.mkdirSync(testVaultDir, { recursive: true });
  fs.mkdirSync(path.join(testTargetDir, 'secrets'), { recursive: true });
  fs.mkdirSync(testRestoreDir, { recursive: true });
  fs.mkdirSync(testBackupDir, { recursive: true });

  // Create sample target files
  const fileA = path.join(testTargetDir, 'secrets', 'passwords.txt');
  const fileB = path.join(testTargetDir, 'financial_ledger.csv');
  const fileC_excluded = path.join(testTargetDir, 'debug.log');

  const contentA = 'super_secret_token_12345_bank_access';
  const contentB = 'id,asset,value\n1,crypto,50000\n2,gold,20000';
  const contentC = '2026-08-26 DEBUG test message';

  fs.writeFileSync(fileA, contentA);
  fs.writeFileSync(fileB, contentB);
  fs.writeFileSync(fileC_excluded, contentC);

  const expectedSha3A = crypto.createHash('sha3-256').update(contentA).digest('hex');
  const expectedSha3B = crypto.createHash('sha3-256').update(contentB).digest('hex');

  // 1. Test GET /api/emergency/config
  const cfgRes = await apiRequest('/api/emergency/config');
  assert(cfgRes.status === 200 && cfgRes.data.success, 'GET /api/emergency/config returned success');
  assert(cfgRes.data.config.algorithm === 'mirage-c4', 'Config has default MIRAGE-C4 algorithm');

  // 2. Test POST /api/emergency/config
  const saveRes = await apiRequest('/api/emergency/config', 'POST', {
    config: {
      targetPaths: [testTargetDir],
      exclusions: ['.log', '.tmp'],
      algorithm: 'mirage-c4',
      outputPath: testVaultDir,
      backupEnabled: true,
      backupPath: testBackupDir,
      shredOriginalEnabled: false
    }
  });
  assert(saveRes.status === 200 && saveRes.data.success, 'POST /api/emergency/config saved successfully');

  // 3. Test POST /api/emergency/scan
  const scanRes = await apiRequest('/api/emergency/scan', 'POST', {
    targetPaths: [testTargetDir],
    exclusions: ['.log', '.tmp']
  });
  assert(scanRes.status === 200 && scanRes.data.success, 'POST /api/emergency/scan returned 200');
  assert(scanRes.data.totalCount === 2, `Scan found exactly 2 files (found ${scanRes.data.totalCount})`);
  assert(scanRes.data.excludedCount === 1, `Scan excluded 1 file matching .log filter`);

  // 4. Test POST /api/emergency/execute with MIRAGE-C4
  const execRes = await apiRequest('/api/emergency/execute', 'POST', {
    password: 'MasterEmergencyKey2026!#Strong',
    targetPaths: [testTargetDir],
    exclusions: ['.log', '.tmp'],
    algorithm: 'mirage-c4',
    outputPath: testVaultDir,
    backupEnabled: true,
    backupPath: testBackupDir,
    shredOriginalEnabled: false
  });
  assert(execRes.status === 200 && execRes.data.success, 'POST /api/emergency/execute completed with 200 OK');
  assert(execRes.data.vaultPath && fs.existsSync(execRes.data.vaultPath), 'Generated encrypted Emergency Vault file on disk');
  assert(execRes.data.backupPath && fs.existsSync(execRes.data.backupPath), 'Generated safety backup archive on disk');
  assert(execRes.data.vaultHash.length === 64, 'Generated 64-char SHA3-256 hash of the armored Vault');

  const generatedVaultPath = execRes.data.vaultPath;

  // 5. Test POST /api/emergency/restore
  const restoreRes = await apiRequest('/api/emergency/restore', 'POST', {
    vaultPath: generatedVaultPath,
    password: 'MasterEmergencyKey2026!#Strong',
    restoreDir: testRestoreDir
  });
  assert(restoreRes.status === 200 && restoreRes.data.success, 'POST /api/emergency/restore restored with 200 OK');
  assert(restoreRes.data.fileCount === 2, `Restored 2 files from vault (count: ${restoreRes.data.fileCount})`);
  
  const restoredFileA = path.join(testRestoreDir, 'secrets', 'passwords.txt');
  const restoredFileB = path.join(testRestoreDir, 'financial_ledger.csv');

  assert(fs.existsSync(restoredFileA), 'Restored file A exists in nested directory');
  assert(fs.existsSync(restoredFileB), 'Restored file B exists');
  assert(fs.readFileSync(restoredFileA, 'utf8') === contentA, 'Restored file A content matches perfectly');
  assert(fs.readFileSync(restoredFileB, 'utf8') === contentB, 'Restored file B content matches perfectly');

  // 6. Test GET /api/emergency/logs
  const logsRes = await apiRequest('/api/emergency/logs');
  assert(logsRes.status === 200 && logsRes.data.success, 'GET /api/emergency/logs returned audit logs');
  assert(logsRes.data.logs.length > 0, 'Audit log entries recorded');

  // Clean up
  try {
    fs.rmSync(testVaultDir, { recursive: true, force: true });
    fs.rmSync(testTargetDir, { recursive: true, force: true });
    fs.rmSync(testRestoreDir, { recursive: true, force: true });
    fs.rmSync(testBackupDir, { recursive: true, force: true });
  } catch (e) {}

  stopServer();

  console.log('\n========================================');
  console.log(`🧪 E2E EMERGENCY API TESTS: ${passed} PASSED, ${failed} FAILED.`);
  console.log('========================================\n');

  if (failed > 0) process.exit(1);
  process.exit(0);
}

runE2ETests().catch(err => {
  console.error('E2E Test Failure:', err);
  process.exit(1);
});
