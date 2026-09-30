#!/usr/bin/env node
console.log('[ChaosTarget] Dummy service running for AI-SRE Chaos Testing...');

setInterval(() => {
  // keep process alive
}, 60000);

process.on('SIGINT', () => {
  console.log('[ChaosTarget] Received SIGINT, exiting gracefully');
  process.exit(0);
});

process.on('SIGTERM', () => {
  console.log('[ChaosTarget] Received SIGTERM, exiting gracefully');
  process.exit(0);
});
