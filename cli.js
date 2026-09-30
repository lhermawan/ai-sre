#!/usr/bin/env node

const { collectAllMetrics } = require('./src/metrics');
const { collectAllRecon } = require('./src/recon');
const { querySreApi } = require('./src/client');
const { createSignatureHeaders, verifyRequestSignature } = require('./src/auth');

async function main() {
  const args = process.argv.slice(2);
  const command = args[0] || 'all';

  try {
    if (command === 'metrics') {
      const res = await collectAllMetrics();
      console.log(JSON.stringify(res, null, 2));
      return;
    }

    if (command === 'recon') {
      const res = await collectAllRecon();
      console.log(JSON.stringify(res, null, 2));
      return;
    }

    if (command === 'all') {
      const [metrics, recon] = await Promise.all([
        collectAllMetrics(),
        collectAllRecon(),
      ]);

      const alerts = [
        ...(metrics.alerts || []),
        ...(recon.security_warnings || []),
      ];

      const report = {
        timestamp: new Date().toISOString(),
        service: 'ai-sre-patrol',
        overall_status: alerts.length === 0 ? 'HEALTHY' : 'WARNING',
        alerts,
        metrics,
        recon,
      };

      console.log(JSON.stringify(report, null, 2));
      return;
    }

    if (command === 'api-query') {
      const endpoint = args[1] || '/api/all';
      const res = await querySreApi(endpoint);
      console.log(JSON.stringify(res, null, 2));
      return;
    }

    if (command === 'test-auth') {
      console.log('🔐 Testing Asymmetric Ed25519 Authentication...');
      const headers = createSignatureHeaders({ method: 'GET', urlPath: '/api/metrics' });
      console.log('✅ Generated Signature Headers:');
      console.log(JSON.stringify(headers, null, 2));

      const verification = verifyRequestSignature({
        method: 'GET',
        urlPath: '/api/metrics',
        headers,
      });

      console.log('\n🔍 Verification with Public Key:');
      console.log(JSON.stringify(verification, null, 2));

      if (verification.valid) {
        console.log('\n🎉 PASS: Asymmetric Ed25519 signature is cryptographically valid and verified!');
      } else {
        console.error('\n❌ FAIL:', verification.error);
        process.exit(1);
      }
      return;
    }

    console.log(`Usage: node cli.js [metrics|recon|all|api-query <endpoint>|test-auth]`);
  } catch (err) {
    console.error('Fatal SRE Error:', err);
    process.exit(1);
  }
}

main();
