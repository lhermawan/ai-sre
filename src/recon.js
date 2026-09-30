const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { exec } = require('child_process');
const { promisify } = require('util');

const execAsync = promisify(exec);

async function scanPorts() {
  const listeners = [];
  const securityWarnings = [];

  try {
    const { stdout } = await execAsync('ss -tulpn', { timeout: 8000 });
    const lines = stdout.trim().split('\n');

    for (let i = 1; i < lines.length; i++) {
      const line = lines[i].trim();
      if (!line) continue;

      const cols = line.replace(/\s+/g, ' ').split(' ');
      if (cols.length < 5) continue;

      const proto = cols[0];
      const state = cols[1];
      const local = cols[4] || '';
      const processCol = cols.slice(6).join(' ');

      // Parse local address and port
      let host = '';
      let port = 0;

      const lastColon = local.lastIndexOf(':');
      if (lastColon !== -1) {
        host = local.substring(0, lastColon);
        port = parseInt(local.substring(lastColon + 1), 10);
      }

      if (isNaN(port) || port === 0) continue;

      // Extract process name
      let procName = 'unknown';
      const procMatch = processCol.match(/users:\(\("([^"]+)"/);
      if (procMatch) procName = procMatch[1];

      // Security Classification
      let exposure = 'UNKNOWN';
      let riskLevel = 'LOW';
      let note = 'Internal service';

      if (
        host === '127.0.0.1' ||
        host === '127.0.0.53' ||
        host === '127.0.0.54' ||
        host === '::1' ||
        host.includes('127.0.0.')
      ) {
        exposure = 'LOCALHOST_ISOLATED';
        riskLevel = 'SAFE';
        note = 'Restricted to loopback interface';
      } else if (host.startsWith('100.') || host.includes('tailscaled')) {
        exposure = 'VPN_MESH_ONLY';
        riskLevel = 'SAFE';
        note = 'Tailscale private network only';
      } else if (host === '0.0.0.0' || host === '*' || host === '[::]' || host === '::') {
        exposure = 'PUBLIC_ALL_INTERFACES';

        // Assess risk for ports on 0.0.0.0
        if ([80, 443].includes(port)) {
          riskLevel = 'LOW';
          note = 'Standard public web server (Nginx)';
        } else if (port === 2277) {
          riskLevel = 'LOW';
          note = 'Custom hardened SSH port';
        } else if ([3306, 5432, 6379, 27017].includes(port)) {
          riskLevel = 'HIGH';
          note = `CRITICAL: Database port ${port} is listening on all network interfaces!`;
          securityWarnings.push(`Database port ${port} (${procName}) is exposed on 0.0.0.0!`);
        } else {
          riskLevel = 'MEDIUM';
          note = `Service ${procName} is exposed on all interfaces (Port ${port})`;
          securityWarnings.push(`Port ${port} (${procName}) is listening on 0.0.0.0`);
        }
      }

      listeners.push({
        protocol: proto,
        state,
        local_address: host,
        port,
        process_name: procName,
        exposure,
        risk_level: riskLevel,
        note,
      });
    }
  } catch (err) {
    securityWarnings.push(`Port scan failed: ${err.message}`);
  }

  // Deduplicate and sort listeners by port
  const sorted = listeners.sort((a, b) => a.port - b.port);

  return {
    total_listeners: sorted.length,
    public_exposed_count: sorted.filter((l) => l.exposure === 'PUBLIC_ALL_INTERFACES').length,
    isolated_count: sorted.filter((l) => l.exposure === 'LOCALHOST_ISOLATED').length,
    security_warnings: securityWarnings,
    listeners: sorted,
  };
}

async function runNmapScan() {
  try {
    const targetPorts = '80,443,2277,3100,3200,3306,5000,5432,8080,8081,9000,9100';
    const { stdout } = await execAsync(`nmap -sT -p ${targetPorts} 127.0.0.1`, { timeout: 10000 });

    const openPorts = [];
    const lines = stdout.split('\n');
    for (const line of lines) {
      if (line.includes('/tcp') && line.includes('open')) {
        const parts = line.trim().split(/\s+/);
        openPorts.push({
          port_proto: parts[0],
          state: parts[1],
          service: parts[2] || 'unknown',
        });
      }
    }

    return {
      scanner: 'nmap-7.95',
      target: '127.0.0.1',
      open_ports: openPorts,
    };
  } catch (err) {
    return {
      scanner: 'nmap',
      error: `Nmap scan failed: ${err.message}`,
      open_ports: [],
    };
  }
}

async function inspectSslCertificates() {
  const certsDir = '/etc/letsencrypt/live';
  const certificates = [];
  const certWarnings = [];

  if (!fs.existsSync(certsDir)) {
    return {
      status: 'UNAVAILABLE',
      message: 'Certificates directory /etc/letsencrypt/live not found',
      certificates: [],
    };
  }

  try {
    const domains = fs.readdirSync(certsDir);

    for (const domain of domains) {
      const certPath = path.join(certsDir, domain, 'cert.pem');
      if (!fs.existsSync(certPath)) continue;

      try {
        const pem = fs.readFileSync(certPath);
        const cert = new crypto.X509Certificate(pem);

        const validTo = new Date(cert.validTo);
        const validFrom = new Date(cert.validFrom);
        const now = Date.now();
        const daysRemaining = Math.ceil((validTo.getTime() - now) / (1000 * 60 * 60 * 24));

        let status = 'HEALTHY';
        if (daysRemaining <= 0) {
          status = 'EXPIRED';
          certWarnings.push(`SSL Certificate for ${domain} has EXPIRED!`);
        } else if (daysRemaining <= 14) {
          status = 'CRITICAL';
          certWarnings.push(`SSL Certificate for ${domain} expires in ${daysRemaining} days!`);
        } else if (daysRemaining <= 30) {
          status = 'WARNING';
          certWarnings.push(`SSL Certificate for ${domain} expires in ${daysRemaining} days.`);
        }

        certificates.push({
          domain,
          subject: cert.subject,
          issuer: cert.issuer,
          valid_from: validFrom.toISOString(),
          valid_to: validTo.toISOString(),
          days_remaining: daysRemaining,
          status,
          fingerprint_sha256: cert.fingerprint256,
        });
      } catch (certErr) {
        certWarnings.push(`Failed to parse cert for ${domain}: ${certErr.message}`);
      }
    }
  } catch (err) {
    certWarnings.push(`Failed reading certificates directory: ${err.message}`);
  }

  return {
    total_certificates: certificates.length,
    warnings: certWarnings,
    certificates,
  };
}

async function collectAllRecon() {
  const [portScan, nmapLocal, ssl] = await Promise.all([
    scanPorts(),
    runNmapScan(),
    inspectSslCertificates(),
  ]);

  const allWarnings = [
    ...(portScan.security_warnings || []),
    ...(ssl.warnings || []),
  ];

  return {
    timestamp: new Date().toISOString(),
    overall_status: allWarnings.length === 0 ? 'HEALTHY' : 'WARNING',
    security_warnings: allWarnings,
    network_recon: {
      port_audit: portScan,
      nmap_localhost: nmapLocal,
    },
    ssl_recon: ssl,
  };
}

module.exports = {
  scanPorts,
  runNmapScan,
  inspectSslCertificates,
  collectAllRecon,
};
