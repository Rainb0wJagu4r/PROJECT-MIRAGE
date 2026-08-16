import { exec } from 'child_process';
import dns from 'dns';

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

    console.log('\n📋 Outdated Libraries Checklist:');
    console.log('========================================');
    
    keys.forEach((pkg) => {
      const info = outdated[pkg];
      const isMajor = info.current.split('.')[0] !== info.latest.split('.')[0];
      const typeLabel = isMajor ? '⚠️ MAJOR UPDATE' : '✨ minor/patch';
      console.log(`[ ] ${pkg.padEnd(20)} | Current: ${info.current.padEnd(8)} | Latest: ${info.latest.padEnd(8)} | (${typeLabel})`);
    });

    console.log('========================================');
    console.log('👉 To update packages to the wanted versions, run:');
    console.log('   npm update');
    console.log('👉 To upgrade packages to their latest versions, run:');
    console.log('   npm install <package-name>@latest\n');
    process.exit(0);
  });
});
