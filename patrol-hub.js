#!/usr/bin/env node

const fs = require("fs");
const path = require("path");
const { createSignatureHeaders, MASKII_PRIV_KEY_PATH } = require("./src/auth");
const { recordToMemoriaGraph } = require("./src/memoria-logger");
const { handleAlerts } = require("./src/alert");

const NODES_FILE = fs.existsSync(path.resolve(__dirname, "nodes.json"))
  ? path.resolve(__dirname, "nodes.json")
  : path.resolve(__dirname, "nodes.example.json");
const LOG_FILE = path.resolve(__dirname, "logs/patrol-hub.jsonl");

// Ensure logs directory exists
const logsDir = path.dirname(LOG_FILE);
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir, { recursive: true });
}

async function queryNode(nodeUrl, endpoint) {
  const url = new URL(endpoint, nodeUrl);
  const headers = createSignatureHeaders({
    method: "GET",
    urlPath: url.pathname,
    agentId: "maskii",
    privateKeyPath: MASKII_PRIV_KEY_PATH,
  });

  const res = await fetch(url.toString(), {
    method: "GET",
    headers: {
      ...headers,
      Accept: "application/json",
    },
    signal: AbortSignal.timeout(12000),
  });

  const data = await res.json();
  if (!res.ok || !data.ok) {
    throw new Error(data.error || `HTTP ${res.status}`);
  }
  return data;
}

async function inspectNode(node) {
  console.log(`🔍 [HUB SRE] Menginspeksi node: ${node.name} (${node.url})...`);
  try {
    const res = await queryNode(node.url, "/api/all");
    const { metrics, recon } = res.data;

    const pm2List = metrics?.pm2?.processes || [];
    const offlineProcesses = pm2List.filter((p) => p.status !== "online");
    const flappingProcesses = pm2List.filter((p) => (p.unstable_restarts || 0) > 3);
    const ram = metrics?.ram || {};
    const disk = metrics?.disk || {};
    const certs = recon?.ssl_recon?.certificates || [];

    const anomalies = [];
    const warnings = [];

    // PM2 Check
    if (offlineProcesses.length > 0) {
      anomalies.push({
        node: node.id,
        node_name: node.name,
        type: "PM2_PROCESS_DOWN",
        severity: "CRITICAL",
        message: `[${node.name}] ${offlineProcesses.length} proses PM2 tidak online: ${offlineProcesses.map((p) => `${p.name} (${p.status})`).join(", ")}`,
      });
    }

    if (flappingProcesses.length > 0) {
      warnings.push({
        node: node.id,
        node_name: node.name,
        type: "PM2_FLAPPING",
        severity: "WARNING",
        message: `[${node.name}] Flapping: ${flappingProcesses.map((p) => `${p.name} (${p.unstable_restarts} restarts)`).join(", ")}`,
      });
    }

    // RAM Check
    if (ram.used_percent >= 92) {
      anomalies.push({
        node: node.id,
        node_name: node.name,
        type: "RAM_EXHAUSTION",
        severity: "CRITICAL",
        message: `[${node.name}] RAM Kritis: ${ram.used_percent}% (${ram.used_mb}MB / ${ram.total_mb}MB)`,
      });
    } else if (ram.used_percent >= 80) {
      warnings.push({
        node: node.id,
        node_name: node.name,
        type: "RAM_HIGH",
        severity: "WARNING",
        message: `[${node.name}] RAM Tinggi: ${ram.used_percent}%`,
      });
    }

    // Disk Check
    if (disk.used_percent >= 90) {
      anomalies.push({
        node: node.id,
        node_name: node.name,
        type: "DISK_FULL",
        severity: "CRITICAL",
        message: `[${node.name}] Disk Root Kritis: ${disk.used_percent}%`,
      });
    } else if (disk.used_percent >= 80) {
      warnings.push({
        node: node.id,
        node_name: node.name,
        type: "DISK_HIGH",
        severity: "WARNING",
        message: `[${node.name}] Disk Root Mencapai ${disk.used_percent}%`,
      });
    }

    // SSL Check
    const expiringCerts = certs.filter((c) => c.days_remaining <= 14);
    if (expiringCerts.length > 0) {
      anomalies.push({
        node: node.id,
        node_name: node.name,
        type: "SSL_EXPIRING_SOON",
        severity: "WARNING",
        message: `[${node.name}] SSL Segera Kedaluwarsa: ${expiringCerts.map((c) => `${c.domain} (${c.days_remaining} hari)`).join(", ")}`,
      });
    }

    return {
      node_id: node.id,
      node_name: node.name,
      status: "ONLINE",
      anomalies,
      warnings,
      metrics_overview: {
        pm2_online: `${metrics?.pm2?.online_count || 0}/${metrics?.pm2?.total_processes || pm2List.length}`,
        ram_used_pct: ram.used_percent,
        disk_used_pct: disk.used_percent,
        cpu_load_1m: metrics?.cpu?.load_1m,
        active_ssl_certs: certs.length,
      },
    };
  } catch (err) {
    console.error(`❌ [HUB SRE] Gagal menghubungi node ${node.name}: ${err.message}`);
    return {
      node_id: node.id,
      node_name: node.name,
      status: "UNREACHABLE",
      anomalies: [
        {
          node: node.id,
          node_name: node.name,
          type: "NODE_UNREACHABLE",
          severity: "CRITICAL",
          message: `Node ${node.name} (${node.url}) tidak dapat dihubungi: ${err.message}`,
        },
      ],
      warnings: [],
      metrics_overview: {},
    };
  }
}

async function runHubPatrol() {
  const runTimestamp = new Date().toISOString();
  console.log(`\n🐾 [AI-SRE HUB WATCHDOG (32GB)] Memulai patroli multi-node pada ${runTimestamp}...`);

  const nodes = JSON.parse(fs.readFileSync(NODES_FILE, "utf8"));
  const allResults = [];
  let combinedAnomalies = [];
  let combinedWarnings = [];

  for (const node of nodes) {
    const result = await inspectNode(node);
    allResults.push(result);
    combinedAnomalies = combinedAnomalies.concat(result.anomalies);
    combinedWarnings = combinedWarnings.concat(result.warnings);
  }

  // Tentukan severity global
  let globalSeverity = "HEALTHY";
  if (combinedAnomalies.length > 0) {
    globalSeverity = "CRITICAL";
  } else if (combinedWarnings.length > 0) {
    globalSeverity = "WARNING";
  }

  const hubReport = {
    timestamp: runTimestamp,
    hub_location: "vm-maskii (100.79.34.4 / 32GB RAM)",
    global_severity: globalSeverity,
    nodes_monitored: nodes.length,
    results: allResults,
    anomalies: combinedAnomalies,
    warnings: combinedWarnings,
  };

  // 1. Simpan log lokal
  fs.appendFileSync(LOG_FILE, JSON.stringify(hubReport) + "\n");

  // 2. Simpan ke MemoriaGraph lokal (100% localhost Neo4j)
  const dateStr = runTimestamp.replace(/T/, " ").replace(/\..+/, "");
  const entityName = `Hub Patrol [${dateStr}]`;
  const desc =
    `[${runTimestamp}] Multi-Node Watchdog Patrol dari Command Center (vm-maskii 32GB):\n` +
    `Status Global: ${globalSeverity} (${nodes.length} nodes aktif)\n` +
    allResults
      .map(
        (r) =>
          `• ${r.node_name}: ${r.status} | PM2: ${r.metrics_overview.pm2_online || "N/A"} | RAM: ${r.metrics_overview.ram_used_pct || "N/A"}% | Disk: ${r.metrics_overview.disk_used_pct || "N/A"}%`
      )
      .join("\n") +
    (combinedAnomalies.length > 0
      ? "\n\n🚨 Temuan Kritis:\n" + combinedAnomalies.map((a) => `- ${a.message}`).join("\n")
      : "") +
    (combinedWarnings.length > 0
      ? "\n\n⚠️ Peringatan:\n" + combinedWarnings.map((w) => `- ${w.message}`).join("\n")
      : "");

  try {
    await recordToMemoriaGraph({
      entityName,
      entityType: "HubPatrolLog",
      description: desc,
      relations: [
        { relationship: "LOGGED_BY", target: "Friday AI Hub" },
        { relationship: "OPERATES_ON", target: "vm-maskii" },
        { relationship: "MONITORS", target: "Production Server" },
      ],
    });
    console.log(`🧠 [HUB SRE] Laporan patroli multi-node '${entityName}' tersimpan di MemoriaGraph!`);
  } catch (memErr) {
    console.warn(`⚠️ [HUB SRE] Gagal mencatat ke MemoriaGraph: ${memErr.message}`);
  }

  // 3. Evaluasi Alert WhatsApp
  try {
    await handleAlerts({
      anomalies: combinedAnomalies,
      warnings: combinedWarnings,
      metrics_overview: {
        pm2_online: allResults.map((r) => `${r.node_id}:${r.metrics_overview.pm2_online}`).join(", "),
        ram_used_pct: allResults.map((r) => `${r.node_id}:${r.metrics_overview.ram_used_pct}%`).join(", "),
      },
      timestamp: runTimestamp,
    });
  } catch (alertErr) {
    console.error(`⚠️ [HUB SRE] Gagal proses alert: ${alertErr.message}`);
  }

  console.log(`🏁 [HUB SRE] Patroli selesai dengan status: ${globalSeverity}`);
  console.log(JSON.stringify(hubReport, null, 2));
  return hubReport;
}

if (require.main === module) {
  runHubPatrol();
}

module.exports = { runHubPatrol };
