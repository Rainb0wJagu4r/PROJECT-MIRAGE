import express from 'express';
import cors from 'cors';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import https from 'https';
import { execSync } from 'child_process';
import os from 'os';

const app = express();
const PORT = 3001;

// Generate runtime API token and write it to local JSON file
const API_TOKEN = crypto.randomBytes(32).toString('hex');
try {
  const tokenPath = path.join(process.cwd(), 'src', 'token.json');
  fs.writeFileSync(tokenPath, JSON.stringify({ token: API_TOKEN }, null, 2));
  console.log(`[Security] API Token generated and written to ${tokenPath}`);
} catch (err) {
  console.error('[Security] Failed to write API Token to disk:', err);
}

// Middlewares
const corsOptions = {
  origin: ['http://localhost:5173', 'http://127.0.0.1:5173'],
  optionsSuccessStatus: 200
};
app.use(cors(corsOptions));
app.use(express.json({ limit: '100mb' }));
app.use(express.raw({ type: 'application/octet-stream', limit: '200mb' }));

// Token authorization middleware
const authenticateToken = (req, res, next) => {
  const clientToken = req.headers['x-api-token'];
  if (!clientToken || clientToken !== API_TOKEN) {
    return res.status(401).json({ success: false, error: 'Unauthorized: Invalid or missing API Token.' });
  }
  next();
};
app.use('/api', authenticateToken);

// Helper to get platform UUID on macOS (with cross-platform fallback)
function getHardwareUUID() {
  try {
    if (process.platform === 'darwin') {
      const output = execSync('ioreg -rd1 -c IOPlatformExpertDevice').toString();
      const match = output.match(/"IOPlatformUUID" = "([^"]+)"/);
      if (match && match[1]) {
        return match[1].trim();
      }
    } else if (process.platform === 'win32') {
      const output = execSync('wmic csproduct get uuid').toString();
      const lines = output.split('\n');
      if (lines.length > 1) return lines[1].trim();
    } else if (process.platform === 'linux') {
      if (fs.existsSync('/var/lib/dbus/machine-id')) {
        return fs.readFileSync('/var/lib/dbus/machine-id', 'utf8').trim();
      }
      if (fs.existsSync('/etc/machine-id')) {
        return fs.readFileSync('/etc/machine-id', 'utf8').trim();
      }
    }
  } catch (err) {
    console.error('Failed to retrieve native hardware UUID, using fallback:', err.message);
  }
  
  // Resilient fallback based on host machine details
  const fallbackStr = os.hostname() + '-' + os.arch() + '-' + os.platform() + '-' + os.userInfo().username;
  return crypto.createHash('sha256').update(fallbackStr).digest('hex');
}

// 3-Pass Secure Shredder
function secureShred(filePath, passes = 3) {
  if (!fs.existsSync(filePath)) return;
  const stats = fs.statSync(filePath);
  const size = stats.size;
  const fd = fs.openSync(filePath, 'r+');

  try {
    for (let pass = 1; pass <= passes; pass++) {
      let offset = 0;
      const bufferSize = 64 * 1024; // 64KB chunks
      const buffer = Buffer.alloc(bufferSize);

      while (offset < size) {
        const remaining = size - offset;
        const chunkLen = Math.min(bufferSize, remaining);

        if (pass === 2) {
          buffer.fill(0); // Zeroes pass
        } else {
          crypto.randomFillSync(buffer); // Random noise passes
        }

        fs.writeSync(fd, buffer, 0, chunkLen, offset);
        offset += chunkLen;
      }
      fs.fsyncSync(fd);
    }
  } finally {
    fs.closeSync(fd);
  }
  fs.unlinkSync(filePath);
}

// JPEG Metadata Scrubber (Strips APP1/EXIF)
function scrubJpeg(buffer) {
  if (buffer[0] !== 0xFF || buffer[1] !== 0xD8) {
    return buffer; // Not a valid JPEG header
  }
  let offset = 2;
  const chunks = [buffer.subarray(0, 2)];
  
  while (offset < buffer.length) {
    if (buffer[offset] !== 0xFF) {
      chunks.push(buffer.subarray(offset));
      break;
    }
    const marker = buffer[offset + 1];
    
    if (marker === 0xD9) { // End of Image
      chunks.push(buffer.subarray(offset, offset + 2));
      break;
    }
    if (marker === 0xDA) { // Start of Scan (image stream begins)
      chunks.push(buffer.subarray(offset));
      break;
    }
    
    if (offset + 3 >= buffer.length) {
      chunks.push(buffer.subarray(offset));
      break;
    }
    
    const length = buffer.readUInt16BE(offset + 2);
    const segmentEnd = offset + 2 + length;
    
    if (marker === 0xE1) {
      // APP1 Marker (EXIF/GPS). Strip it!
      console.log('[Scrubber] Skipping APP1/EXIF segment');
    } else {
      chunks.push(buffer.subarray(offset, segmentEnd));
    }
    offset = segmentEnd;
  }
  return Buffer.concat(chunks);
}

// PNG Metadata Scrubber (Strips tEXt, zTXt, iTXt, eXIf, tIME, pHYs)
function scrubPng(buffer) {
  const pngSignature = Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
  if (buffer.subarray(0, 8).compare(pngSignature) !== 0) {
    return buffer; // Not a PNG
  }
  let offset = 8;
  const chunks = [pngSignature];
  
  while (offset < buffer.length) {
    if (offset + 8 > buffer.length) {
      chunks.push(buffer.subarray(offset));
      break;
    }
    const length = buffer.readUInt32BE(offset);
    const type = buffer.toString('ascii', offset + 4, offset + 8);
    const totalChunkLength = 12 + length;
    
    if (offset + totalChunkLength > buffer.length) {
      chunks.push(buffer.subarray(offset));
      break;
    }
    
    const isMetadata = ['tEXt', 'zTXt', 'iTXt', 'eXIf', 'tIME', 'pHYs'].includes(type);
    if (isMetadata) {
      console.log(`[Scrubber] Stripping PNG metadata chunk: ${type}`);
    } else {
      chunks.push(buffer.subarray(offset, offset + totalChunkLength));
    }
    offset += totalChunkLength;
  }
  return Buffer.concat(chunks);
}

// Scrypt Key Derivation Wrapper (Symmetric Double Factor + Hardware Pepper Lock)
function deriveKey(password, salt, hardwareLockEnabled, doubleFactorPassword = '') {
  let combinedPassword = password;
  
  if (doubleFactorPassword) {
    combinedPassword += '__2FA__' + doubleFactorPassword;
  }
  
  if (hardwareLockEnabled) {
    const hwUuid = getHardwareUUID();
    combinedPassword += '__HW__' + hwUuid;
  }
  
  // Scrypt key derivation (256-bit key)
  return crypto.scryptSync(combinedPassword, salt, 32, { N: 16384, r: 8, p: 1 });
}

// Signal-style exponential size obfuscation
function applySizePadding(buffer) {
  // Random padding between 4KB and 5MB using logarithmic spread
  const padSize = Math.min(
    5 * 1024 * 1024,
    Math.floor(Math.exp(crypto.randomInt(12, 85) / 10) * 1024)
  );
  const padding = crypto.randomBytes(padSize);
  return Buffer.concat([buffer, padding]);
}

// Serialization format for encrypted files:
// [Expiration Timestamp (8 bytes, double)] [Filename len (2 bytes)] [Filename (UTF-8)] [File size (8 bytes, double)] [File content]
function serializePayload(filename, fileBuffer, expirationTime = 0) {
  const filenameBuf = Buffer.from(filename, 'utf8');
  const headerBuf = Buffer.alloc(8 + 2 + filenameBuf.length + 8);
  
  headerBuf.writeDoubleBE(expirationTime, 0);
  headerBuf.writeUInt16BE(filenameBuf.length, 8);
  filenameBuf.copy(headerBuf, 10);
  headerBuf.writeDoubleBE(fileBuffer.length, 10 + filenameBuf.length);
  
  return Buffer.concat([headerBuf, fileBuffer]);
}

function deserializePayload(buffer) {
  const expirationTime = buffer.readDoubleBE(0);
  const filenameLen = buffer.readUInt16BE(8);
  const filename = buffer.toString('utf8', 10, 10 + filenameLen);
  const fileSize = buffer.readDoubleBE(10 + filenameLen);
  const fileData = buffer.subarray(10 + filenameLen + 8, 10 + filenameLen + 8 + fileSize);
  return { expirationTime, filename, fileData };
}

// System Hardware UUID API
app.get('/api/system-info', (req, res) => {
  res.json({
    uuid: getHardwareUUID(),
    platform: process.platform,
    hostname: os.hostname(),
    username: os.userInfo().username
  });
});

// File system autocomplete helper API for local UX
app.get('/api/autocomplete', (req, res) => {
  let queryPath = req.query.path || '';
  if (!queryPath) {
    queryPath = os.homedir();
  } else {
    // Resolve home shorthand ~
    if (queryPath.startsWith('~')) {
      queryPath = path.join(os.homedir(), queryPath.slice(1));
    }
  }

  try {
    const resolvedPath = path.resolve(queryPath);
    let parentDir = resolvedPath;
    let fileFilter = '';

    const exists = fs.existsSync(resolvedPath);
    if (!exists || !fs.lstatSync(resolvedPath).isDirectory()) {
      parentDir = path.dirname(resolvedPath);
      fileFilter = path.basename(resolvedPath).toLowerCase();
    }

    if (!fs.existsSync(parentDir)) {
      return res.json({ currentDir: queryPath, items: [] });
    }

    const files = fs.readdirSync(parentDir);
    const items = [];

    for (const file of files) {
      if (file.startsWith('.') && file !== '.dotfiles') continue; // Hide hidden files
      if (fileFilter && !file.toLowerCase().startsWith(fileFilter)) continue;

      const fullPath = path.join(parentDir, file);
      let isDirectory = false;
      let size = 0;
      try {
        const stats = fs.lstatSync(fullPath);
        isDirectory = stats.isDirectory();
        size = stats.size;
      } catch (e) {
        continue;
      }

      items.push({
        name: file,
        path: fullPath,
        isDirectory,
        size
      });
    }

    // Sort: folders first, then files alphabetically
    items.sort((a, b) => {
      if (a.isDirectory && !b.isDirectory) return -1;
      if (!a.isDirectory && b.isDirectory) return 1;
      return a.name.localeCompare(b.name);
    });

    res.json({
      currentDir: parentDir,
      items: items.slice(0, 50) // limit to 50 results
    });
  } catch (err) {
    res.json({ currentDir: queryPath, items: [], error: err.message });
  }
});

// File information and hashing API
app.get('/api/file-info', (req, res) => {
  let queryPath = req.query.path || '';
  if (queryPath.startsWith('~')) {
    queryPath = path.join(os.homedir(), queryPath.slice(1));
  }
  try {
    const resolvedPath = path.resolve(queryPath);
    if (fs.existsSync(resolvedPath) && fs.lstatSync(resolvedPath).isFile()) {
      const fileBuffer = fs.readFileSync(resolvedPath);
      const sha3 = crypto.createHash('sha3-256').update(fileBuffer).digest('hex');
      res.json({
        exists: true,
        size: fileBuffer.length,
        name: path.basename(resolvedPath),
        hash: sha3
      });
    } else {
      res.json({ exists: false });
    }
  } catch (e) {
    res.json({ exists: false, error: e.message });
  }
});

// Primary Encrypt & Arm API
app.post('/api/encrypt', async (req, res) => {
  const steps = [];
  const addStep = (msg, success = true) => {
    steps.push({ msg, success, timestamp: Date.now() });
    console.log(`[Encrypt] ${msg}`);
  };

  try {
    // We support uploading raw binary bytes (using express.raw middleware) or passing JSON with file paths
    let fileBuffer;
    let filename;
    let sourceFilePath = null;
    let settings = {};

    if (req.headers['content-type'] === 'application/octet-stream') {
      fileBuffer = req.body;
      filename = req.headers['x-file-name'] || 'untitled.bin';
      settings = JSON.parse(req.headers['x-settings'] || '{}');
      addStep(`Received uploaded file: ${filename} (${fileBuffer.length} bytes)`);
    } else {
      const body = req.body;
      sourceFilePath = body.filePath;
      if (!sourceFilePath) {
        throw new Error('No file provided (upload or local filePath required)');
      }
      // Resolve home shorthand ~
      if (sourceFilePath.startsWith('~')) {
        sourceFilePath = path.join(os.homedir(), sourceFilePath.slice(1));
      }
      
      if (!fs.existsSync(sourceFilePath)) {
        throw new Error(`File not found: ${sourceFilePath}`);
      }

      fileBuffer = fs.readFileSync(sourceFilePath);
      filename = path.basename(sourceFilePath);
      settings = body.settings || {};
      addStep(`Loaded file from path: ${sourceFilePath} (${fileBuffer.length} bytes)`);
    }

    const {
      password,
      doubleFactorPassword,
      hardwareLockEnabled,
      metadataScrubEnabled,
      sizeObfuscationEnabled,
      ttlEnabled,
      ttlValue, // in hours
      duressEnabled,
      duressPassword,
      duressDecoyPath,
      splitFragmentEnabled,
      shredOriginalEnabled,
      shredPasses = 3,
      outputPath
    } = settings;

    if (!password) {
      throw new Error('Key Generation Error: Password is required');
    }

    // Step 1: Metadata Scrubbing
    if (metadataScrubEnabled) {
      const ext = path.extname(filename).toLowerCase();
      const origSize = fileBuffer.length;
      if (ext === '.jpg' || ext === '.jpeg') {
        fileBuffer = scrubJpeg(fileBuffer);
        addStep(`Metadata Scrubbed: JPEG EXIF stripped (saved ${origSize - fileBuffer.length} bytes)`);
      } else if (ext === '.png') {
        fileBuffer = scrubPng(fileBuffer);
        addStep(`Metadata Scrubbed: PNG auxiliary chunks stripped (saved ${origSize - fileBuffer.length} bytes)`);
      } else {
        addStep(`Metadata Scrub: Skipped (File type ${ext || 'unknown'} has no EXIF container)`);
      }
    }

    // Step 2: Calculate Hash Input
    const sha3Input = crypto.createHash('sha3-256').update(fileBuffer).digest('hex');
    addStep(`Input SHA3-256: ${sha3Input}`);

    // Step 3: Prepare the payload envelope
    let expirationTime = 0;
    if (ttlEnabled && ttlValue) {
      expirationTime = Date.now() + parseFloat(ttlValue) * 60 * 60 * 1000;
      addStep(`Time-To-Live Set: File expires on ${new Date(expirationTime).toLocaleString()}`);
    }

    let payload = serializePayload(filename, fileBuffer, expirationTime);

    // Step 4: Size Obfuscation
    if (sizeObfuscationEnabled) {
      const prevLen = payload.length;
      payload = applySizePadding(payload);
      addStep(`Size Obfuscation applied: added ${payload.length - prevLen} bytes of OsRng random padding`);
    }

    // Helper function to encrypt a payload buffer
    const encryptPayload = (payloadBuf, keyPass, dfPass) => {
      const salt = crypto.randomBytes(16);
      const iv = crypto.randomBytes(12);
      const key = deriveKey(keyPass, salt, hardwareLockEnabled, dfPass);
      const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
      
      const ciphertext = Buffer.concat([cipher.update(payloadBuf), cipher.final()]);
      const tag = cipher.getAuthTag();

      return { salt, iv, tag, ciphertext };
    };

    // Step 5: Core Encryption
    let outputBuffer;
    
    if (duressEnabled) {
      addStep('Duress Mode active: Preparing secondary decoy block');
      if (!duressPassword) {
        throw new Error('Duress Mode Error: Decoy password required');
      }
      const hashedDuress = crypto.createHash('sha256').update(duressPassword).digest();
      const hashedPassword = crypto.createHash('sha256').update(password).digest();
      if (crypto.timingSafeEqual(hashedDuress, hashedPassword)) {
        throw new Error('Duress Mode Error: Decoy password must be different from primary password');
      }

      let decoyBuffer;
      let decoyFilename = 'decoy.txt';

      if (duressDecoyPath) {
        let resolvedDecoyPath = duressDecoyPath;
        if (resolvedDecoyPath.startsWith('~')) {
          resolvedDecoyPath = path.join(os.homedir(), resolvedDecoyPath.slice(1));
        }
        if (fs.existsSync(resolvedDecoyPath)) {
          decoyBuffer = fs.readFileSync(resolvedDecoyPath);
          decoyFilename = path.basename(resolvedDecoyPath);
          addStep(`Duress Decoy Loaded: ${resolvedDecoyPath} (${decoyBuffer.length} bytes)`);
        }
      }

      if (!decoyBuffer) {
        decoyBuffer = Buffer.from('WARNING: System compromised. Access Restricted.', 'utf8');
        addStep('Duress Decoy: Using default warning file payload');
      }

      const decoyPayload = serializePayload(decoyFilename, decoyBuffer, 0); // No TTL on decoy usually
      const block1 = encryptPayload(payload, password, doubleFactorPassword);
      const block2 = encryptPayload(decoyPayload, duressPassword, '');

      // Create Duress Binary Structure (Mode 0x02)
      const header = Buffer.from('MIRAGE\x01\x02', 'binary');
      
      const block1LenBuf = Buffer.alloc(8);
      block1LenBuf.writeDoubleBE(block1.ciphertext.length, 0);
      const block2LenBuf = Buffer.alloc(8);
      block2LenBuf.writeDoubleBE(block2.ciphertext.length, 0);

      outputBuffer = Buffer.concat([
        header,
        block1.salt, block1.iv, block1.tag, block1LenBuf, block1.ciphertext,
        block2.salt, block2.iv, block2.tag, block2LenBuf, block2.ciphertext
      ]);
      addStep('AES-256-GCM Dual-Block Envelope constructed');
    } else {
      // Standard Single Block (Mode 0x01)
      const block = encryptPayload(payload, password, doubleFactorPassword);
      const header = Buffer.from('MIRAGE\x01\x01', 'binary');
      
      const cipherLenBuf = Buffer.alloc(8);
      cipherLenBuf.writeDoubleBE(block.ciphertext.length, 0);

      outputBuffer = Buffer.concat([
        header,
        block.salt, block.iv, block.tag, cipherLenBuf, block.ciphertext
      ]);
      addStep('AES-256-GCM Single-Block Envelope constructed');
    }

    // Step 6: Output / Splitting
    let targetOutputPath = outputPath;
    const ext = splitFragmentEnabled ? '.part' : '.wraith';
    const defaultName = path.basename(filename, path.extname(filename)) + ext;

    if (!targetOutputPath) {
      const parent = sourceFilePath ? path.dirname(sourceFilePath) : os.homedir();
      targetOutputPath = path.join(parent, defaultName);
    } else {
      if (targetOutputPath.startsWith('~')) {
        targetOutputPath = path.join(os.homedir(), targetOutputPath.slice(1));
      }
      
      // Check if targetOutputPath is a directory
      let isDir = false;
      try {
        if (fs.existsSync(targetOutputPath) && fs.lstatSync(targetOutputPath).isDirectory()) {
          isDir = true;
        }
      } catch (e) {}
      
      if (isDir || targetOutputPath.endsWith('/') || targetOutputPath.endsWith('\\')) {
        targetOutputPath = path.join(targetOutputPath, defaultName);
      }
    }

    // Ensure output directories exist
    fs.mkdirSync(path.dirname(targetOutputPath), { recursive: true });

    if (splitFragmentEnabled) {
      addStep('Split Fragment mode active: Dividing cipher file into 3 parts (2-of-3 threshold)');
      // Split the output ciphertext envelope (outputBuffer) into 2 halves + 1 XOR parity
      const fullLen = outputBuffer.length;
      const halfLen = Math.ceil(fullLen / 2);
      
      // Make outputBuffer even length by padding if needed
      let paddedOutput = outputBuffer;
      if (fullLen % 2 !== 0) {
        paddedOutput = Buffer.concat([outputBuffer, crypto.randomBytes(1)]);
      }
      
      const H1 = paddedOutput.subarray(0, halfLen);
      const H2 = paddedOutput.subarray(halfLen);
      const H3 = Buffer.alloc(halfLen);
      
      for (let i = 0; i < halfLen; i++) {
        H3[i] = H1[i] ^ H2[i];
      }

      // Write parts
      const writePart = (partIdx, partBuffer) => {
        const partMagic = Buffer.from('MIRAGE_PART\x01', 'binary');
        const partIdxBuf = Buffer.from([partIdx]);
        
        const origLenBuf = Buffer.alloc(8);
        origLenBuf.writeDoubleBE(fullLen, 0);
        
        const partContent = Buffer.concat([
          partMagic,
          partIdxBuf,
          origLenBuf,
          partBuffer
        ]);
        
        const partPath = targetOutputPath + partIdx;
        fs.writeFileSync(partPath, partContent);
        addStep(`Saved Fragment ${partIdx} to: ${partPath}`);
      };

      writePart(1, H1);
      writePart(2, H2);
      writePart(3, H3);
    } else {
      fs.writeFileSync(targetOutputPath, outputBuffer);
      addStep(`Saved Encrypted File to: ${targetOutputPath}`);
    }

    // Calculate Hash Output
    const finalSha3 = crypto.createHash('sha3-256').update(outputBuffer).digest('hex');
    addStep(`Output SHA3-256 (.wraith): ${finalSha3}`);

    // Step 7: Secure Shredding of original file
    if (shredOriginalEnabled && sourceFilePath) {
      addStep(`Secure Shredder active: Overwriting file ${sourceFilePath} in ${shredPasses} passes...`);
      secureShred(sourceFilePath, parseInt(shredPasses));
      addStep(`Original File wiped securely from disk.`);
      
      // If duress file was local and shredded
      if (duressEnabled && duressDecoyPath && duressDecoyPath !== sourceFilePath) {
        // We typically do NOT shred the decoy unless specified. Let's keep it safe.
      }
    }

    res.json({
      success: true,
      outputPath: splitFragmentEnabled ? `${targetOutputPath}1, 2, 3` : targetOutputPath,
      inputHash: sha3Input,
      outputHash: finalSha3,
      steps
    });

  } catch (err) {
    addStep(err.message, false);
    res.status(500).json({
      success: false,
      error: err.message,
      steps
    });
  }
});

// Decrypt & Restore API
app.post('/api/decrypt', async (req, res) => {
  const steps = [];
  const addStep = (msg, success = true) => {
    steps.push({ msg, success, timestamp: Date.now() });
    console.log(`[Decrypt] ${msg}`);
  };

  try {
    const { filePath, partPaths, password, doubleFactorPassword, restorePath } = req.body;
    let encryptedBuffer;
    
    if (!password) {
      throw new Error('Key Verification Error: Password is required');
    }

    // Handle Split Fragment Mode reconstruction
    if (partPaths && partPaths.length > 0) {
      addStep(`Split Recombination: Reading ${partPaths.length} fragments...`);
      if (partPaths.length < 2) {
        throw new Error('Fragment Error: At least 2 split parts are required to recover the file');
      }

      // Load parts
      const parts = [];
      for (const pPath of partPaths) {
        let resolvedPath = pPath;
        if (resolvedPath.startsWith('~')) {
          resolvedPath = path.join(os.homedir(), resolvedPath.slice(1));
        }
        if (!fs.existsSync(resolvedPath)) {
          throw new Error(`Fragment file not found: ${resolvedPath}`);
        }
        const partBuffer = fs.readFileSync(resolvedPath);
        
        // Parse part header
        const magic = partBuffer.subarray(0, 12).toString('binary');
        if (magic !== 'MIRAGE_PART\x01') {
          throw new Error(`File is not a valid Project Mirage fragment: ${resolvedPath}`);
        }
        
        const index = partBuffer[12];
        const originalLength = partBuffer.readDoubleBE(13);
        const data = partBuffer.subarray(21);
        
        parts.push({ index, originalLength, data, path: resolvedPath });
        addStep(`Loaded Fragment Index ${index} (${data.length} bytes) from ${path.basename(resolvedPath)}`);
      }

      // Check lengths and matching files
      const expectedLen = parts[0].originalLength;
      const chunkLen = parts[0].data.length;
      
      for (const part of parts) {
        if (part.originalLength !== expectedLen || part.data.length !== chunkLen) {
          throw new Error('Fragment Error: Selected parts do not belong to the same split set');
        }
      }

      // Reconstruct ciphertext halves
      let H1, H2;
      const hasPart1 = parts.find(p => p.index === 1);
      const hasPart2 = parts.find(p => p.index === 2);
      const hasPart3 = parts.find(p => p.index === 3);

      if (hasPart1 && hasPart2) {
        addStep('Combining Fragment 1 and Fragment 2 directly');
        H1 = hasPart1.data;
        H2 = hasPart2.data;
      } else if (hasPart1 && hasPart3) {
        addStep('Reconstructing Fragment 2 using Fragment 1 XOR Fragment 3');
        H1 = hasPart1.data;
        H2 = Buffer.alloc(chunkLen);
        for (let i = 0; i < chunkLen; i++) {
          H2[i] = H1[i] ^ hasPart3.data[i];
        }
      } else if (hasPart2 && hasPart3) {
        addStep('Reconstructing Fragment 1 using Fragment 2 XOR Fragment 3');
        H2 = hasPart2.data;
        H1 = Buffer.alloc(chunkLen);
        for (let i = 0; i < chunkLen; i++) {
          H1[i] = H2[i] ^ hasPart3.data[i];
        }
      } else {
        throw new Error('Fragment Error: Invalid part combination indices');
      }

      const combined = Buffer.concat([H1, H2]);
      // Trim to original length
      encryptedBuffer = combined.subarray(0, expectedLen);
      addStep(`Ciphertext envelope successfully reconstructed (${encryptedBuffer.length} bytes)`);

    } else {
      // Standard single file load
      let resolvedPath = filePath;
      if (!resolvedPath) {
        throw new Error('No encrypted file path provided');
      }
      if (resolvedPath.startsWith('~')) {
        resolvedPath = path.join(os.homedir(), resolvedPath.slice(1));
      }
      if (!fs.existsSync(resolvedPath)) {
        throw new Error(`File not found: ${resolvedPath}`);
      }

      encryptedBuffer = fs.readFileSync(resolvedPath);
      addStep(`Loaded file: ${resolvedPath} (${encryptedBuffer.length} bytes)`);
    }

    // Step 2: Validate magic header
    const fileMagic = encryptedBuffer.subarray(0, 8).toString('binary');
    if (fileMagic.substring(0, 6) !== 'MIRAGE') {
      throw new Error('Header Error: File is not a valid Project Mirage archive');
    }

    const version = encryptedBuffer[6];
    const mode = encryptedBuffer[7];

    if (version !== 1) {
      throw new Error(`Header Error: Unsupported version (${version})`);
    }

    let payloadBuffer = null;
    let hardwareLockEnabled = false;

    // Helper decrypt block function
    const decryptBlock = (salt, iv, tag, ciphertext, isHwLock) => {
      // Try with HW Lock active first, then fallback
      try {
        const key = deriveKey(password, salt, isHwLock, doubleFactorPassword);
        const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
        decipher.setAuthTag(tag);
        return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
      } catch (e) {
        return null;
      }
    };

    if (mode === 0x01) {
      addStep('Parsing Single-Block Archive');
      const salt = encryptedBuffer.subarray(8, 24);
      const iv = encryptedBuffer.subarray(24, 36);
      const tag = encryptedBuffer.subarray(36, 52);
      const cipherLen = encryptedBuffer.readDoubleBE(52);
      const ciphertext = encryptedBuffer.subarray(60, 60 + cipherLen);

      // Try decrypting with hardware lock (both states to see which works)
      payloadBuffer = decryptBlock(salt, iv, tag, ciphertext, true);
      if (payloadBuffer) {
        hardwareLockEnabled = true;
        addStep('AES-256-GCM authentication successful (Hardware lock verified)');
      } else {
        payloadBuffer = decryptBlock(salt, iv, tag, ciphertext, false);
        if (payloadBuffer) {
          addStep('AES-256-GCM authentication successful');
        }
      }

    } else if (mode === 0x02) {
      addStep('Parsing Dual-Block (Duress Mode) Archive');
      // Read Block 1
      let offset = 8;
      const b1Salt = encryptedBuffer.subarray(offset, offset + 16); offset += 16;
      const b1Iv = encryptedBuffer.subarray(offset, offset + 12); offset += 12;
      const b1Tag = encryptedBuffer.subarray(offset, offset + 16); offset += 16;
      const b1Len = encryptedBuffer.readDoubleBE(offset); offset += 8;
      const b1Ciphertext = encryptedBuffer.subarray(offset, offset + b1Len); offset += b1Len;

      // Read Block 2
      const b2Salt = encryptedBuffer.subarray(offset, offset + 16); offset += 16;
      const b2Iv = encryptedBuffer.subarray(offset, offset + 12); offset += 12;
      const b2Tag = encryptedBuffer.subarray(offset, offset + 16); offset += 16;
      const b2Len = encryptedBuffer.readDoubleBE(offset); offset += 8;
      const b2Ciphertext = encryptedBuffer.subarray(offset, offset + b2Len);

      // Try Decrypting Block 1 (Real block)
      addStep('Testing decryption key against Primary Block...');
      payloadBuffer = decryptBlock(b1Salt, b1Iv, b1Tag, b1Ciphertext, true);
      if (payloadBuffer) {
        hardwareLockEnabled = true;
        addStep('Authenticated Primary Block successfully (Hardware Lock verified)');
      } else {
        payloadBuffer = decryptBlock(b1Salt, b1Iv, b1Tag, b1Ciphertext, false);
        if (payloadBuffer) {
          addStep('Authenticated Primary Block successfully');
        }
      }

      // If Block 1 failed, test Block 2 (Decoy block, standard encryption)
      if (!payloadBuffer) {
        addStep('Primary Block auth failed. Testing key against Decoy Block (Duress Trigger)...');
        payloadBuffer = decryptBlock(b2Salt, b2Iv, b2Tag, b2Ciphertext, false);
        if (payloadBuffer) {
          addStep('⚠️ DURESS TRIGGERED: Decoy block successfully authenticated');
        }
      }
    } else {
      throw new Error(`Header Error: Unsupported encryption mode code (${mode})`);
    }

    if (!payloadBuffer) {
      throw new Error('Authentication Failure: Invalid password or integrity compromised');
    }

    // Step 4: Deserialize Payload & Handle TTL
    const { expirationTime, filename, fileData } = deserializePayload(payloadBuffer);
    addStep(`Decoded Payload details: file = ${filename}, size = ${fileData.length} bytes`);

    if (expirationTime > 0) {
      const now = Date.now();
      if (now > expirationTime) {
        addStep(`⚠️ Ephemeral File Expired: Expiration date was ${new Date(expirationTime).toLocaleString()} (Auto-destructing file)`);
        
        // Auto-destruct: Shred the encrypted file if it exists!
        if (filePath && fs.existsSync(filePath)) {
          addStep(`Shredding expired file: ${filePath}`);
          secureShred(filePath, 3);
          addStep('Expired file erased securely.');
        }
        throw new Error('Security Timeout: This file has expired and is no longer available');
      } else {
        addStep(`TTL Check Passed: File is valid until ${new Date(expirationTime).toLocaleString()}`);
      }
    }

    // Step 5: Save File
    let targetRestorePath = restorePath;
    if (!targetRestorePath) {
      // Default to user's Downloads or same dir as source
      const parent = filePath ? path.dirname(filePath) : os.homedir();
      targetRestorePath = path.join(parent, filename);
    } else if (targetRestorePath.startsWith('~')) {
      targetRestorePath = path.join(os.homedir(), targetRestorePath.slice(1));
    }

    // Check if output is directory, if so join with name
    try {
      if (fs.existsSync(targetRestorePath) && fs.lstatSync(targetRestorePath).isDirectory()) {
        targetRestorePath = path.join(targetRestorePath, filename);
      }
    } catch (e) {}

    // Ensure parent directories exist
    fs.mkdirSync(path.dirname(targetRestorePath), { recursive: true });
    fs.writeFileSync(targetRestorePath, fileData);
    addStep(`Decrypted file successfully saved to: ${targetRestorePath}`);

    const outputHash = crypto.createHash('sha3-256').update(fileData).digest('hex');
    addStep(`Output SHA3-256 (Restored): ${outputHash}`);

    res.json({
      success: true,
      restorePath: targetRestorePath,
      filename,
      fileSize: fileData.length,
      outputHash,
      hardwareLockVerified: hardwareLockEnabled,
      steps
    });

  } catch (err) {
    addStep(err.message, false);
    res.status(500).json({
      success: false,
      error: err.message,
      steps
    });
  }
});

// Start Express Server
if (process.env.NODE_ENV !== 'test') {
  try {
    const certPath = path.join(process.cwd(), 'certs', 'localhost.pem');
    const keyPath = path.join(process.cwd(), 'certs', 'localhost-key.pem');
    
    if (fs.existsSync(certPath) && fs.existsSync(keyPath)) {
      const options = {
        key: fs.readFileSync(keyPath),
        cert: fs.readFileSync(certPath),
        // Enable Hybrid Post-Quantum Key Exchange if supported by Node/OpenSSL
        minVersion: 'TLSv1.3',
        ciphers: 'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256',
        ecdhCurve: 'X25519Kyber768Draft00:secp256r1_kyber768:x25519:secp256r1'
      };
      
      const server = https.createServer(options, app);
      server.listen(PORT, () => {
        console.log(`========================================`);
        console.log(`Project Mirage Local API Server online (HTTPS)!`);
        console.log(`Listening on https://localhost:${PORT}`);
        console.log(`Platform UUID: ${getHardwareUUID()}`);
        console.log(`========================================`);
      });
    } else {
      app.listen(PORT, () => {
        console.log(`========================================`);
        console.log(`Project Mirage Local API Server online (HTTP Fallback)!`);
        console.log(`Listening on http://localhost:${PORT}`);
        console.log(`Platform UUID: ${getHardwareUUID()}`);
        console.log(`========================================`);
      });
    }
  } catch (err) {
    console.error('Failed to start HTTPS server, falling back to HTTP:', err);
    app.listen(PORT, () => {
      console.log(`========================================`);
      console.log(`Project Mirage Local API Server online (HTTP Fallback)!`);
      console.log(`Listening on http://localhost:${PORT}`);
      console.log(`Platform UUID: ${getHardwareUUID()}`);
      console.log(`========================================`);
    });
  }
}

// Export helpers for testing
export {
  getHardwareUUID,
  secureShred,
  scrubJpeg,
  scrubPng,
  deriveKey,
  applySizePadding,
  serializePayload,
  deserializePayload
};

