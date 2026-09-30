#!/usr/bin/env node

/**
 * AI-SRE Model Context Protocol (MCP) Server
 * Menggunakan otentikasi Zero Trust Asymmetric Key bertanda tangan Maskii Private Key (/root/.ssh/id_ed25519_maskii)
 */

const { Server } = require('@modelcontextprotocol/sdk/server/index.js');
const { StdioServerTransport } = require('@modelcontextprotocol/sdk/server/stdio.js');
const {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} = require('@modelcontextprotocol/sdk/types.js');
const { createSignatureHeaders, MASKII_PRIV_KEY_PATH } = require('./src/auth');
const { runHubPatrol: runPatrol } = require('./patrol-hub');
const { sendWhatsAppAlert, loadConfig } = require('./src/alert');

const SRE_SERVER_URL = process.env.AI_SRE_URL || 'http://127.0.0.1:3400';

/**
 * Helper untuk query ke SRE API Daemon lokal menggunakan Maskii Private Key
 */
async function querySreWithMaskiiKey(endpoint) {
  const url = new URL(endpoint, SRE_SERVER_URL);
  const headers = createSignatureHeaders({
    method: 'GET',
    urlPath: url.pathname,
    agentId: 'maskii',
    privateKeyPath: MASKII_PRIV_KEY_PATH,
  });

  const res = await fetch(url.toString(), {
    method: 'GET',
    headers: {
      ...headers,
      Accept: 'application/json',
    },
    signal: AbortSignal.timeout(15000),
  });

  const data = await res.json();
  if (!res.ok || !data.ok) {
    throw new Error(data.error || `HTTP ${res.status}`);
  }
  return data;
}

// Inisialisasi Server MCP
const server = new Server(
  {
    name: 'ai-sre',
    version: '1.0.0',
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// Daftar Tools MCP
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      {
        name: 'sre_get_system_health',
        description:
          'Mengambil gambaran lengkap kesehatan sistem (PM2, RAM, Disk, CPU, Recon Port, dan SSL) via Zero Trust Ed25519 menggunakan Private Key Maskii.',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
      {
        name: 'sre_get_metrics',
        description:
          'Mengambil telemetri metriks performa sistem (19 proses PM2, kapasitas RAM, penggunaan Disk /, load CPU) terotentikasi Private Key Maskii.',
        inputSchema: {
          type: 'object',
          properties: {
            filter: {
              type: 'string',
              description: 'Filter opsional: "pm2", "ram", "disk", "cpu", atau kosongkan untuk semua.',
            },
          },
        },
      },
      {
        name: 'sre_get_recon',
        description:
          'Mengambil hasil audit keamanan jaringan dan SSL (deteksi port terbuka ke 0.0.0.0 vs 127.0.0.1, masa berlaku sertifikat Let\'s Encrypt) terotentikasi Private Key Maskii.',
        inputSchema: {
          type: 'object',
          properties: {
            filter: {
              type: 'string',
              description: 'Filter opsional: "ports", "ssl", "warnings", atau kosongkan untuk semua.',
            },
          },
        },
      },
      {
        name: 'sre_run_patrol',
        description:
          'Mengeksekusi siklus inspeksi patroli watchdog (Anjing Penjaga) secara manual, mencatat telemetry & insiden ke MemoriaGraph Neo4j, dan mengembalikan hasil analisis sistem.',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
      {
        name: 'sre_send_alert',
        description:
          'Mengirimkan pesan/peringatan darurat langsung ke nomor WhatsApp pribadi Maskii (085735544336) via bot internal port 3200.',
        inputSchema: {
          type: 'object',
          properties: {
            message: {
              type: 'string',
              description: 'Isi teks pesan alert yang akan dikirimkan ke nomor WhatsApp pribadi Maskii.',
            },
          },
          required: ['message'],
        },
      },
    ],
  };
});

// Handler Eksekusi Tools
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    switch (name) {
      case 'sre_get_system_health': {
        const result = await querySreWithMaskiiKey('/api/all');
        const metrics = result.data.metrics;
        const recon = result.data.recon;

        const summary = {
          auth_info: {
            authenticated_as: result.agent,
            auth_method: 'Ed25519 Zero Trust (Maskii Private Key)',
            verified_key: result.verified_key,
          },
          overview: {
            timestamp: result.timestamp,
            pm2_status: `${metrics.pm2.online_count}/${metrics.pm2.total_processes} Online`,
            ram_usage: `${metrics.ram.used_percent}% (${metrics.ram.used_mb}MB / ${metrics.ram.total_mb}MB)`,
            disk_usage: `${metrics.disk.used_percent}% (${metrics.disk.used_gb}GB / ${metrics.disk.total_gb}GB)`,
            cpu_load: metrics.cpu.load_1m,
            active_ssl: recon.ssl_recon.total_certificates,
            security_warnings: recon.security_warnings.length,
          },
          security_warnings: recon.security_warnings,
        };

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(summary, null, 2),
            },
          ],
        };
      }

      case 'sre_get_metrics': {
        const result = await querySreWithMaskiiKey('/api/metrics');
        let data = result.data;

        if (args?.filter && data[args.filter]) {
          data = { [args.filter]: data[args.filter] };
        }

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  auth: `Authenticated with Maskii Key (${result.agent})`,
                  timestamp: result.timestamp,
                  metrics: data,
                },
                null,
                2
              ),
            },
          ],
        };
      }

      case 'sre_get_recon': {
        const result = await querySreWithMaskiiKey('/api/recon');
        let data = result.data;

        if (args?.filter) {
          if (args.filter === 'ports') data = data.network_recon;
          else if (args.filter === 'ssl') data = data.ssl_recon;
          else if (args.filter === 'warnings') data = data.security_warnings;
        }

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  auth: `Authenticated with Maskii Key (${result.agent})`,
                  timestamp: result.timestamp,
                  recon: data,
                },
                null,
                2
              ),
            },
          ],
        };
      }

      case 'sre_run_patrol': {
        const patrolResult = await runPatrol();
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(patrolResult, null, 2),
            },
          ],
        };
      }

      case 'sre_send_alert': {
        const config = loadConfig();
        const alertMsg =
          `📢 *MANUAL ALERT FROM FRIDAY (CHAT/MCP)* 📢\n\n` +
          `${args.message}\n\n` +
          `⏰ Waktu: ${new Date().toLocaleString('id-ID', { timeZone: 'Asia/Jakarta' })} WIB\n` +
          `🔐 Dikirim dengan otentikasi Maskii Private Key.`;

        await sendWhatsAppAlert(config.alertPhone, alertMsg);
        return {
          content: [
            {
              type: 'text',
              text: `✅ Alert berhasil dikirim ke nomor WhatsApp pribadi Maskii (${config.alertPhone}).`,
            },
          ],
        };
      }

      default:
        throw new Error(`Tool tidak dikenal: ${name}`);
    }
  } catch (err) {
    return {
      isError: true,
      content: [
        {
          type: 'text',
          text: `❌ Error mengeksekusi tool '${name}': ${err.message}`,
        },
      ],
    };
  }
});

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('AI-SRE MCP Server berjalan pada mode STDIO dengan otentikasi Maskii Private Key.');
}

main().catch((err) => {
  console.error('Fatal error pada MCP Server:', err);
  process.exit(1);
});
