import path from 'path';
import fs from 'fs';
import { execSync } from 'child_process';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/**
 * Registers .wraith file association and icon in Windows Registry (HKCU)
 * @param {boolean} quiet - Suppress non-error console output
 * @returns {boolean}
 */
export function registerWindowsIcon(quiet = false) {
  if (process.platform !== 'win32') {
    if (!quiet) console.log('ℹ️ Non-Windows operating system detected. File association registration skipped.');
    return false;
  }

  const psScriptPath = path.resolve(__dirname, 'register-windows-icon.ps1');
  const iconPath = path.resolve(__dirname, '..', 'resources', 'nobug.ico');

  if (!fs.existsSync(iconPath)) {
    if (!quiet) console.error(`❌ Icon file not found at: ${iconPath}`);
    return false;
  }

  try {
    const cmd = `powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "${psScriptPath}" -IconPath "${iconPath}"`;
    const output = execSync(cmd, {
      stdio: quiet ? 'ignore' : ['ignore', 'pipe', 'pipe']
    });

    if (!quiet && output) {
      console.log(output.toString().trim());
    }
    return true;
  } catch (error) {
    if (!quiet) {
      console.error('⚠️ Failed to register .wraith file icon in Windows Registry:', error.message);
    }
    return false;
  }
}

// If invoked directly from CLI (e.g. node scripts/register-windows-icon.js or npm run register:icon)
if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(__filename)) {
  registerWindowsIcon(false);
}
