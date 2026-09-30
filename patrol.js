#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const { querySreApi } = require('./src/client');
const { recordToMemoriaGraph } = require('./src/memoria-logger');
const { handleAlerts } = require('./src/alert');

const LOG_FILE = path.resolve(__dirname, 'logs/patrol.jsonl');

async function runPatrol() {
  const runTimestamp = new Date().toISOString();
  console.log(`🐾 [ANJING PENJAGA] Memulai patroli SRE pada ${runTimestamp}...`);

  try {
    // 1. Ambil data SRE via Asymmetric Key Auth
    const response = await querySreApi('/api/all');
    if (response.status_code !== 200 || !response.data?.ok) {
      throw new Error(
        `Gagal query SRE API: HTTP ${response.status_code} - ${JSON.stringify(response.data)}`
      );
    }

    const { metrics, recon } = response.data.data;
    const anomalies = [];
    const warnings = [];

    // 2. Evaluasi PM2 Processes
    const pm2List = metrics?.pm2?.processes || [];
    const offlineProcesses = pm2List.filter((p) => p.status !== 'online');
    if (offlineProcesses.length > 0) {
      anomalies.push({
        type: 'PM2_PROCESS_DOWN',
        severity: 'CRITICAL',
        message: `${offlineProcesses.length} proses PM2 tidak online: ${offlineProcesses.map((p) => `${p.name} (${p.status})`).join(', ')}`,
      });
    }

    const flappingProcesses = pm2List.filter((p) => (p.unstable_restarts || 0) > 3);
    if (flappingProcesses.length > 0) {
      warnings.push({
        type: 'PM2_FLAPPING',
        severity: 'WARNING',
        message: `Proses PM2 mengalami restart tidak stabil: ${flappingProcesses.map((p) => `${p.name} (${p.unstable_restarts} restarts)`).join(', ')}`,
      });
    }

    // 3. Evaluasi RAM
    const ram = metrics?.ram || {};
    if (ram.used_percent >= 92) {
      anomalies.push({
        type: 'RAM_EXHAUSTION',
        severity: 'CRITICAL',
        message: `Penggunaan RAM kritis: ${ram.used_percent}% (${ram.used_mb}MB / ${ram.total_mb}MB)`,
      });
    } else if (ram.used_percent >= 80) {
      warnings.push({
        type: 'RAM_HIGH',
        severity: 'WARNING',
        message: `Penggunaan RAM tinggi: ${ram.used_percent}%`,
      });
    }

    // 4. Evaluasi Disk
    const disk = metrics?.disk || {};
    if (disk.used_percent >= 90) {
      anomalies.push({
        type: 'DISK_FULL',
        severity: 'CRITICAL',
        message: `Kapasitas disk partisi root kritis: ${disk.used_percent}% (Tersedia: ${disk.available_gb}GB)`,
      });
    } else if (disk.used_percent >= 80) {
      warnings.push({
        type: 'DISK_HIGH',
        severity: 'WARNING',
        message: `Kapasitas disk partisi root mencapai ${disk.used_percent}%`,
      });
    }

    // 5. Evaluasi Port & Keamanan
    const securityWarnings = recon?.security_warnings || [];
    const dangerousPorts = (recon?.network_recon?.port_audit?.listeners || []).filter(
      (l) => l.risk_level === 'HIGH'
    );

    if (dangerousPorts.length > 0) {
      warnings.push({
        type: 'PORT_SECURITY_RISK',
        severity: 'WARNING',
        message: `Port sensitif terbuka pada 0.0.0.0: ${dangerousPorts.map((p) => `Port ${p.port} (${p.process_name})`).join(', ')}`,
      });
    }

    // 6. Evaluasi SSL Certificates
    const certs = recon?.ssl_recon?.certificates || [];
    const expiringCerts = certs.filter((c) => c.days_remaining <= 14);
    if (expiringCerts.length > 0) {
      anomalies.push({
        type: 'SSL_EXPIRING_SOON',
        severity: 'WARNING',
        message: `Sertifikat SSL segera kedaluwarsa: ${expiringCerts.map((c) => `${c.domain} (${c.days_remaining} hari)`).join(', ')}`,
      });
    }

    // Tentukan status keseluruhan
    let overallSeverity = 'HEALTHY';
    if (anomalies.length > 0) {
      overallSeverity = 'CRITICAL';
    } else if (warnings.length > 0) {
      overallSeverity = 'WARNING';
    }

    const summaryText =
      `Status: ${overallSeverity} | PM2: ${metrics?.pm2?.online_count || 0}/${pm2List.length} online | ` +
      `RAM: ${ram.used_percent || 0}% | Disk: ${disk.used_percent || 0}% | SSL: ${certs.length} certs aktif | ` +
      `Anomali: ${anomalies.length} kritis, ${warnings.length} peringatan.`;

    const patrolRecord = {
      timestamp: runTimestamp,
      severity: overallSeverity,
      summary: summaryText,
      anomalies,
      warnings,
      metrics_overview: {
        pm2_online: `${metrics?.pm2?.online_count}/${pm2List.length}`,
        ram_used_pct: ram.used_percent,
        disk_used_pct: disk.used_percent,
        cpu_load_1m: metrics?.cpu?.load_1m,
        active_ssl_certs: certs.length,
      },
    };

    // 7. Simpan log lokal ke JSONL
    fs.appendFileSync(LOG_FILE, JSON.stringify(patrolRecord) + '\n');
    console.log(`✅ Log patroli disimpan ke ${LOG_FILE}`);

    // 8. Tuliskan log ke MemoriaGraph
    const dateStr = runTimestamp.replace(/T/, ' ').replace(/\..+/, '');
    const entityName = `Patrol Run [${dateStr}]`;
    const fullDescription =
      `[${runTimestamp}] Hasil Patroli SRE Anjing Penjaga:\n` +
      `${summaryText}\n\n` +
      (anomalies.length > 0 ? `🚨 Temuan Kritis:\n` + anomalies.map((a) => `- ${a.message}`).join('\n') + '\n\n' : '') +
      (warnings.length > 0 ? `⚠️ Peringatan:\n` + warnings.map((w) => `- ${w.message}`).join('\n') + '\n\n' : '') +
      `Detail: PM2(${metrics?.pm2?.online_count}/${pm2List.length}), RAM(${ram.used_percent}%), Disk(${disk.used_percent}%).`;

    try {
      await recordToMemoriaGraph({
        entityName,
        entityType: 'PatrolLog',
        description: fullDescription,
        relations: [
          { relationship: 'LOGGED_BY', target: 'Friday' },
          { relationship: 'MONITORS', target: 'WhatsApp Bot Worker' },
          { relationship: 'MONITORS', target: 'MaskiiStudio' },
        ],
      });
      console.log(`🧠 Log patroli '${entityName}' berhasil dicatat ke MemoriaGraph!`);
    } catch (memErr) {
      console.warn(`⚠️ Peringatan: Gagal menulis ke MemoriaGraph: ${memErr.message}`);
    }

    // 9. Evaluasi & Kirim Alert Otomatis (Fase 3: Peringatan Otomatis)
    try {
      const alertResult = await handleAlerts({
        anomalies,
        warnings,
        metrics_overview: patrolRecord.metrics_overview,
        timestamp: runTimestamp,
      });
      if (alertResult.alerted) {
        console.log(`📢 [ALERT ENGINE] Notifikasi berhasil diproses: ${alertResult.type}`);
      }
    } catch (alertErr) {
      console.error(`⚠️ [ALERT ENGINE] Gagal memproses alert: ${alertErr.message}`);
    }

    console.log(`🏁 Patroli SRE selesai dengan status: ${overallSeverity}`);
    console.log(JSON.stringify(patrolRecord, null, 2));
    return patrolRecord;
  } catch (err) {
    console.error(`💥 Fatal error saat menjalankan patroli SRE:`, err);
    process.exit(1);
  }
}

if (require.main === module) {
  runPatrol();
}

module.exports = {
  runPatrol,
};
