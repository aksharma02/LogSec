const { spawn } = require('child_process');

console.log('================================================================');
console.log('🚀 Launching Next.js UI Server & BullMQ Worker Concurrently...');
console.log('================================================================');

// 1. Spawn Next.js UI Production Server (listening on Render's assigned port)
const port = process.env.PORT || '10000';
console.log(`[Orchestrator] Starting Next.js UI on port: ${port}`);
const uiProcess = spawn('npx', ['next', 'start', '-p', port], {
  stdio: 'inherit',
  shell: true,
});

// 2. Spawn BullMQ Log Ingestion Queue Worker
console.log('[Orchestrator] Starting BullMQ Log Ingestion Worker...');
const workerProcess = spawn('npx', ['tsx', 'lib/queue/worker.ts'], {
  stdio: 'inherit',
  shell: true,
});

// Graceful exit handlers
uiProcess.on('close', (code) => {
  console.log(`[Orchestrator] Next.js UI server exited with code ${code}`);
  workerProcess.kill();
  process.exit(code || 0);
});

workerProcess.on('close', (code) => {
  console.log(`[Orchestrator] BullMQ background worker exited with code ${code}`);
  uiProcess.kill();
  process.exit(code || 0);
});

// Capture termination signals from Render
process.on('SIGTERM', () => {
  console.log('[Orchestrator] Received SIGTERM. Shutting down child processes...');
  uiProcess.kill('SIGTERM');
  workerProcess.kill('SIGTERM');
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('[Orchestrator] Received SIGINT. Shutting down child processes...');
  uiProcess.kill('SIGINT');
  workerProcess.kill('SIGINT');
  process.exit(0);
});
