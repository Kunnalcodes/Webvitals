/**
 * WebVitals Dev Runner — Concurrently starts Backend & Frontend
 */
'use strict';

const { spawn } = require('child_process');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const isWin = process.platform === 'win32';
const npmCmd = isWin ? 'npm.cmd' : 'npm';
const npxCmd = isWin ? 'npx.cmd' : 'npx';

console.log('\x1b[36m%s\x1b[0m', '═══════════════════════════════════════════════════════════════════');
console.log('\x1b[36m%s\x1b[0m', ' 🛡️  WebVitals Web Security & SEO Intelligence Platform — Dev Server');
console.log('\x1b[36m%s\x1b[0m', '═══════════════════════════════════════════════════════════════════\n');

// 1. Backend process (Node.js native zero-dep server on Port 8888)
const backend = spawn('node', ['backend/index.js'], {
  cwd: ROOT,
  stdio: 'inherit',
  shell: isWin,
  env: { ...process.env, PORT: '8888', NODE_ENV: 'development' },
});

// 2. Frontend process (Vite on Port 5173)
const frontend = spawn(npmCmd, ['run', 'dev'], {
  cwd: path.join(ROOT, 'frontend'),
  stdio: 'inherit',
  shell: isWin,
  env: process.env,
});

function cleanup() {
  console.log('\n\x1b[33mShutting down WebVitals dev servers...\x1b[0m');
  try { backend.kill(); } catch {}
  try { frontend.kill(); } catch {}
  process.exit(0);
}

process.on('SIGINT', cleanup);
process.on('SIGTERM', cleanup);
process.on('exit', cleanup);
