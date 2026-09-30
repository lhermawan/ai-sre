const fs = require('fs');
const path = require('path');
const { recordToMemoriaGraph } = require('./memoria-logger');

const STATE_FILE = path.resolve(__dirname, '../logs/alert-state.json');
const ENV_FILE = path.resolve(__dirname, '../.env');

// Muat konfigurasi .env
function loadConfig() {
  if (fs.existsSync(ENV_FILE)) {
    try {
      if (typeof process.loadEnvFile === 'function') {
        process.loadEnvFile(ENV_FILE);
      } else {
        const content = fs.readFileSync(ENV_FILE, 'utf8');
        for (const line of content.split('\n')) {
          const match = line.match(/^\s*([\w.-]+)\s*=\s*(.*)?\s*$/);
          if (match) {
            let value = match[2] || '';
            if (value.startsWith('"') && value.endsWith('"')) value = value.slice(1, -1);
            process.env[match[1]] = value;
          }
        }
      }
    } catch (e) {
      // ignore
    }
  }

  return {
    alertPhone: process.env.ALERT_WA_NUMBER || '',
    workerUrl: process.env.WHATSAPP_WORKER_URL || 'http://127.0.0.1:3200',
    internalKey: process.env.WHATSAPP_INTERNAL_KEY || '',
    cooldownMinutes: parseInt(process.env.ALERT_COOLDOWN_MINUTES || '60', 10),
  };
}

function loadState() {
  try {
    if (fs.existsSync(STATE_FILE)) {
      return JSON.parse(fs.readFileSync(STATE_FILE, 'utf8'));
    }
  } catch (err) {
    console.error('Failed to read alert state:', err.message);
  }
  return {
    last_alert_time: null,
    last_incident_name: null,
    active_incidents: [],
    last_warning_alert_time: null,
    active_warnings: [],
  };
}

function saveState(state) {
  try {
    fs.writeFileSync(STATE_FILE, JSON.stringify(state, null, 2));
  } catch (err) {
    console.error('Failed to save alert state:', err.message);
  }
}

/**
 * Kirim pesan WhatsApp ke nomor tujuan via internal endpoint port 3200
 */
async function sendWhatsAppAlert(to, message) {
  const config = loadConfig();
  const url = `${config.workerUrl}/send`;

  const headers = {
    'Content-Type': 'application/json',
  };
  if (config.internalKey) {
    headers['Authorization'] = `Bearer ${config.internalKey}`;
  }

  const res = await fetch(url, {
    method: 'POST',
    headers,
    body: JSON.stringify({ to, message }),
    signal: AbortSignal.timeout(12000),
  });

  const data = await res.json();
  if (!res.ok || !data.ok) {
    throw new Error(data.error || `HTTP ${res.status}`);
  }
  return data;
}

/**
 * Format timestamp ke WIB string yang ramah dibaca
 */
function formatWibTime(isoString) {
  try {
    const d = new Date(isoString || Date.now());
    return new Intl.DateTimeFormat('id-ID', {
      timeZone: 'Asia/Jakarta',
      dateStyle: 'medium',
      timeStyle: 'medium',
    }).format(d) + ' WIB';
  } catch {
    return isoString;
  }
}

/**
 * Evaluasi anomali dan kirim alert WhatsApp bila terjadi incident atau recovery
 */
async function handleAlerts({
  anomalies = [],
  warnings = [],
  metrics_overview = {},
  timestamp = new Date().toISOString(),
}) {
  const config = loadConfig();
  const state = loadState();
  const now = Date.now();
  const wibTime = formatWibTime(timestamp);

  // Hanya anomali dengan severity CRITICAL yang memicu Incident Alert
  const criticalAnomalies = anomalies.filter((a) => a.severity === 'CRITICAL');
  const currentIncidentIds = criticalAnomalies.map((a) => `${a.type}:${a.message}`);
  const previousIncidentIds = (state.active_incidents || []).map((i) => `${i.type}:${i.message}`);

  const cooldownMs = config.cooldownMinutes * 60 * 1000;
  const lastAlertTimeMs = state.last_alert_time ? new Date(state.last_alert_time).getTime() : 0;
  const isCooldownExpired = now - lastAlertTimeMs > cooldownMs;

  // Cek apakah ada incident baru yang belum pernah di-alert
  const hasNewIncident = currentIncidentIds.some((id) => !previousIncidentIds.includes(id));

  // --- KASUS 1: TERJADI INSIDEN KRITIS ---
  if (criticalAnomalies.length > 0) {
    const shouldAlert = hasNewIncident || isCooldownExpired;

    if (shouldAlert) {
      console.log(`🚨 [ALERT ENGINE] Memicu Incident Alert WA ke ${config.alertPhone}...`);

      const incidentListText = criticalAnomalies.map((a) => `• *${a.type}*: ${a.message}`).join('\n');
      const warningText =
        warnings.length > 0
          ? `\n⚠️ *Peringatan Sekunder:*\n` + warnings.map((w) => `• ${w.message}`).join('\n')
          : '';

      const alertMessage =
        `🚨 *AI-SRE INCIDENT ALERT* 🚨\n\n` +
        `⚠️ *Tingkat Keparahan:* CRITICAL\n` +
        `⏰ *Waktu Terdeteksi:* ${wibTime}\n` +
        `🖥️ *Server Host:* production (157.10.157.25)\n\n` +
        `📋 *Detail Insiden:*\n${incidentListText}${warningText}\n\n` +
        `📊 *Status Sistem:*\n` +
        `• PM2 Online: ${metrics_overview.pm2_online || 'N/A'}\n` +
        `• RAM Used: ${metrics_overview.ram_used_pct || 'N/A'}%\n` +
        `• Disk Used: ${metrics_overview.disk_used_pct || 'N/A'}%\n` +
        `• CPU Load (1m): ${metrics_overview.cpu_load_1m || 'N/A'}\n\n` +
        `🛠️ *Tindakan Friday:*\n` +
        `Insiden telah dicatat ke MemoriaGraph Neo4j. AI-SRE Guard bersiaga untuk instruksi penanganan.`;

      let waSent = false;
      try {
        await sendWhatsAppAlert(config.alertPhone, alertMessage);
        console.log(`✅ [ALERT ENGINE] Pesan darurat berhasil dikirim ke WhatsApp ${config.alertPhone}`);
        waSent = true;
      } catch (waErr) {
        console.error(`❌ [ALERT ENGINE] Gagal mengirim pesan WA: ${waErr.message}`);
      }

      // Catat entitas Incident ke MemoriaGraph
      const dateStr = timestamp.replace(/T/, ' ').replace(/\..+/, '');
      const incidentEntityName = `Incident [${dateStr}] - ${criticalAnomalies[0].type}`;
      const incidentDesc =
        `[${timestamp}] CRITICAL INCIDENT DETECTED\n` +
        `Anomali: ${criticalAnomalies.map((a) => a.message).join('; ')}\n` +
        `Status WA: ${waSent ? 'Terkirim ke ' + config.alertPhone : 'Gagal terkirim'}\n` +
        `Host: 157.10.157.25, PM2: ${metrics_overview.pm2_online}`;

      try {
        await recordToMemoriaGraph({
          entityName: incidentEntityName,
          entityType: 'Incident',
          description: incidentDesc,
          relations: [
            { relationship: 'DETECTED_BY', target: 'Friday' },
            { relationship: 'ALERTED_TO', target: 'Nomor WA Maskii' },
            { relationship: 'TARGETS', target: 'Server Production' },
          ],
        });
        console.log(`🧠 [ALERT ENGINE] Entitas '${incidentEntityName}' dicatat ke MemoriaGraph!`);
      } catch (memErr) {
        console.warn(`⚠️ [ALERT ENGINE] Gagal mencatat Incident ke MemoriaGraph: ${memErr.message}`);
      }

      // Update state
      state.last_alert_time = new Date().toISOString();
      state.last_incident_name = incidentEntityName;
      state.active_incidents = criticalAnomalies;
      saveState(state);

      return { alerted: true, type: 'INCIDENT', message: alertMessage };
    } else {
      console.log(`⏳ [ALERT ENGINE] Insiden aktif masih dalam masa cooldown (${config.cooldownMinutes}m).`);
      return { alerted: false, reason: 'COOLDOWN_ACTIVE' };
    }
  }

  // --- KASUS 2: PERINGATAN (WARNING) ---
  if (criticalAnomalies.length === 0 && warnings.length > 0) {
    const currentWarningIds = warnings.map((w) => `${w.type}:${w.message}`);
    const previousWarningIds = (state.active_warnings || []).map((w) => `${w.type}:${w.message}`);

    const lastWarningTimeMs = state.last_warning_alert_time ? new Date(state.last_warning_alert_time).getTime() : 0;
    const isWarningCooldownExpired = now - lastWarningTimeMs > cooldownMs;
    const hasNewWarning = currentWarningIds.some((id) => !previousWarningIds.includes(id));

    if (hasNewWarning || isWarningCooldownExpired) {
      console.log(`⚠️ [ALERT ENGINE] Memicu Warning Alert WA ke ${config.alertPhone}...`);

      const warningListText = warnings.map((w) => `• *${w.type}*: ${w.message}`).join('\n');
      const warningMessage =
        `⚠️ *AI-SRE WARNING ALERT* ⚠️\n\n` +
        `🟡 *Tingkat Keparahan:* WARNING (Peringatan)\n` +
        `⏰ *Waktu Terdeteksi:* ${wibTime}\n` +
        `🖥️ *Server Host:* Multi-Node Hub\n\n` +
        `📋 *Detail Peringatan:*\n${warningListText}\n\n` +
        `📊 *Status Sistem:*\n` +
        `• PM2: ${metrics_overview.pm2_online || 'N/A'}\n` +
        `• RAM: ${metrics_overview.ram_used_pct || 'N/A'}\n` +
        `• Disk: ${metrics_overview.disk_used_pct || 'N/A'}\n\n` +
        `🛠️ *Tindakan Friday:*\n` +
        `Peringatan telah dicatat ke MemoriaGraph Neo4j. Friday memantau status secara berkala.`;

      let waSent = false;
      try {
        await sendWhatsAppAlert(config.alertPhone, warningMessage);
        console.log(`✅ [ALERT ENGINE] Pesan peringatan berhasil dikirim ke WhatsApp ${config.alertPhone}`);
        waSent = true;
      } catch (waErr) {
        console.error(`❌ [ALERT ENGINE] Gagal mengirim pesan peringatan WA: ${waErr.message}`);
      }

      const dateStr = timestamp.replace(/T/, ' ').replace(/\..+/, '');
      const warningEntityName = `Warning [${dateStr}] - ${warnings[0].type}`;
      try {
        await recordToMemoriaGraph({
          entityName: warningEntityName,
          entityType: 'Warning',
          description: `[${timestamp}] WARNING ALERT\n${warnings.map((w) => w.message).join('; ')}\nStatus WA: ${waSent ? 'Terkirim' : 'Gagal'}`,
          relations: [
            { relationship: 'DETECTED_BY', target: 'Friday' },
            { relationship: 'ALERTED_TO', target: 'Nomor WA Maskii' },
          ],
        });
      } catch (memErr) {
        console.warn(`⚠️ [ALERT ENGINE] Gagal mencatat Warning ke MemoriaGraph: ${memErr.message}`);
      }

      state.last_warning_alert_time = new Date().toISOString();
      state.active_warnings = warnings;
      saveState(state);

      return { alerted: true, type: 'WARNING', message: warningMessage };
    } else {
      console.log(`⏳ [ALERT ENGINE] Peringatan aktif masih dalam masa cooldown (${config.cooldownMinutes}m).`);
    }
  }

  // Jika warning sebelumnya ada tetapi sekarang sudah nihil
  if (warnings.length === 0 && (state.active_warnings || []).length > 0) {
    state.active_warnings = [];
    saveState(state);
  }

  // --- KASUS 3: RECOVERY (SEMUA ANOMALI PULIH) ---
  if (criticalAnomalies.length === 0 && (state.active_incidents || []).length > 0) {
    console.log(`🎉 [ALERT ENGINE] Insiden pulih! Mengirimkan notifikasi resolusi ke ${config.alertPhone}...`);

    const prevSummary = state.active_incidents.map((i) => `• ${i.message}`).join('\n');
    const resolvedMessage =
      `✅ *AI-SRE INCIDENT RESOLVED* ✅\n\n` +
      `🎉 *Status Sistem:* NORMAL / HEALTHY\n` +
      `⏰ *Waktu Pemulihan:* ${wibTime}\n` +
      `🖥️ *Server Host:* production (157.10.157.25)\n\n` +
      `📋 *Resolusi:* Seluruh anomali kritis telah pulih normal.\n` +
      `Sebelumnya terdeteksi:\n${prevSummary}\n\n` +
      `📊 *Metriks Terkini:*\n` +
      `• PM2 Online: ${metrics_overview.pm2_online || 'N/A'}\n` +
      `• RAM Used: ${metrics_overview.ram_used_pct || 'N/A'}%\n` +
      `• Disk Used: ${metrics_overview.disk_used_pct || 'N/A'}%\n\n` +
      `✨ Semua layanan operasional kembali aman & terpantau penuh.`;

    let waSent = false;
    try {
      await sendWhatsAppAlert(config.alertPhone, resolvedMessage);
      console.log(`✅ [ALERT ENGINE] Notifikasi pemulihan berhasil dikirim ke WhatsApp ${config.alertPhone}`);
      waSent = true;
    } catch (waErr) {
      console.error(`❌ [ALERT ENGINE] Gagal mengirim pesan pemulihan WA: ${waErr.message}`);
    }

    // Catat pemulihan ke MemoriaGraph
    const dateStr = timestamp.replace(/T/, ' ').replace(/\..+/, '');
    const recoveryEntityName = `Incident Resolution [${dateStr}]`;
    try {
      const relations = [
        { relationship: 'RESOLVED_BY', target: 'Friday' },
        { relationship: 'REPORTED_TO', target: 'Nomor WA Maskii' },
      ];
      if (state.last_incident_name) {
        relations.push({ relationship: 'RESOLVES', target: state.last_incident_name });
      }

      await recordToMemoriaGraph({
        entityName: recoveryEntityName,
        entityType: 'IncidentResolution',
        description: `Pemulihan insiden pada ${timestamp}. Layanan kembali normal: PM2 (${metrics_overview.pm2_online}), RAM (${metrics_overview.ram_used_pct}%).`,
        relations,
      });
      console.log(`🧠 [ALERT ENGINE] Entitas '${recoveryEntityName}' dicatat ke MemoriaGraph!`);
    } catch (memErr) {
      console.warn(`⚠️ [ALERT ENGINE] Gagal mencatat Recovery ke MemoriaGraph: ${memErr.message}`);
    }

    // Reset active incidents
    state.active_incidents = [];
    state.last_alert_time = new Date().toISOString();
    saveState(state);

    return { alerted: true, type: 'RESOLUTION', message: resolvedMessage };
  }

  // Normal, tidak ada incident
  return { alerted: false, reason: 'SYSTEM_HEALTHY' };
}

module.exports = {
  handleAlerts,
  sendWhatsAppAlert,
  loadConfig,
};
