import { exec, execSync } from 'child_process';
import dns from 'dns';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Ensure src/token.json exists so Vite can compile on fresh clones
const tokenPath = path.join(__dirname, '..', 'src', 'token.json');
if (!fs.existsSync(tokenPath)) {
  try {
    fs.mkdirSync(path.dirname(tokenPath), { recursive: true });
    fs.writeFileSync(tokenPath, JSON.stringify({ token: 'dev-placeholder-token' }, null, 2));
    console.log('🔑 Created token.json placeholder for dev compilation.');
  } catch (e) {
    console.error('Failed to create token.json placeholder:', e.message);
  }
}

console.log('🔍 Checking Project Mirage dependencies...');

// 1. Quick internet connectivity check to prevent blocking offline dev
dns.lookup('registry.npmjs.org', (err) => {
  if (err) {
    console.log('📶 Offline: skipping dependency update check.\n');
    process.exit(0);
  }

  // 2. Run npm outdated programmatically
  exec('npm outdated --json', (error, stdout) => {
    // Note: npm outdated exits with code 1 if there are outdated packages, which is normal.
    let outdated = {};
    try {
      if (stdout) {
        outdated = JSON.parse(stdout);
      }
    } catch (e) {
      console.error('⚠️ Failed to parse outdated packages output.');
      process.exit(0);
    }

    const keys = Object.keys(outdated);
    if (keys.length === 0) {
      console.log('✅ All package dependencies are up to date!\n');
      process.exit(0);
    }

    const safeUpdates = [];
    const majorUpdates = [];

    keys.forEach((pkg) => {
      const info = outdated[pkg];
      const currentMajor = info.current ? info.current.split('.')[0] : '0';
      const latestMajor = info.latest ? info.latest.split('.')[0] : '0';
      const isMajor = currentMajor !== latestMajor;

      if (isMajor) {
        majorUpdates.push({ pkg, ...info });
      } else {
        safeUpdates.push({ pkg, ...info });
      }
    });

    // 3. Perform automatic safe minor/patch updates
    if (safeUpdates.length > 0) {
      console.log(`\n✨ Safe minor/patch updates detected for ${safeUpdates.length} libraries.`);
      console.log('📦 Running auto-updater (npm update) to update them safely...');
      try {
        execSync('npm update', { stdio: 'inherit' });
        console.log('✅ Safe updates applied successfully!\n');
      } catch (updateError) {
        console.error('⚠️ Auto-update execution failed:', updateError.message);
      }
    }

    // 4. Report major updates that require manual action (since they are breaking)
    if (majorUpdates.length > 0) {
      console.log('\n📋 Major updates available (skipped to prevent breaking changes):');
      console.log('========================================');
      majorUpdates.forEach((item) => {
        console.log(`[ ] ${item.pkg.padEnd(20)} | Current: ${item.current.padEnd(8)} | Latest: ${item.latest.padEnd(8)} | (⚠️ MAJOR UPDATE)`);
      });
      console.log('========================================');
      console.log('👉 To install major updates manually, run:');
      console.log('   npm install <package-name>@latest\n');
    } else if (safeUpdates.length === 0) {
      console.log('✅ All package dependencies are up to date!\n');
    }

    process.exit(0);
  });
});
