# 🛡️ AI-SRE: Autonomous Site Reliability Engineering & Observability Daemon

> **Autonomous Infrastructure Reliability, Security Reconnaissance, and Self-Healing Engine for Distributed Cloud & Edge Nodes.**

[![Node.js](https://img.shields.io/badge/Node.js-18%2B-green.svg)](https://nodejs.org/)
[![License: ISC](https://img.shields.io/badge/License-ISC-blue.svg)](LICENSE)
[![Architecture: Zero--Trust](https://img.shields.io/badge/Security-Zero--Trust%20Ed25519-red.svg)](#security--zero-trust-authentication)
[![Protocol: MCP](https://img.shields.io/badge/Interface-Model%20Context%20Protocol-purple.svg)](https://modelcontextprotocol.io/)

---

## 📌 Overview

**AI-SRE** is a lightweight, agentic Site Reliability Engineering daemon engineered to safeguard multi-node infrastructure. Unlike traditional heavy APM suites, AI-SRE pairs autonomous background telemetry collection with **asymmetric cryptographic authentication (Ed25519)** and native **Model Context Protocol (MCP)** interfaces, enabling AI assistants (such as FRIDAY / Antigravity) to inspect, triage, and remediate system anomalies autonomously.

---

## ⚡ Core Capabilities

1. **Zero-Trust Cryptographic Communication**
   - All inter-node telemetry requests (`/api/*`) are signed using Ed25519 asymmetric private keys and verified against authorized public keys (`keys/*.pub`).
   - Replay protection with strict 60-second timestamp freshness windows.

2. **Full-Spectrum System Telemetry & Reconnaissance**
   - **Metrics Engine (`src/metrics.js`)**: Real-time CPU pressure, memory utilization (RSS / Heap / Swap), disk I/O, and network bandwidth.
   - **Reconnaissance Engine (`src/recon.js`)**: PM2 process cluster inspection, systemd service health, Docker container states, and listening socket audits.

3. **Autonomous SRE Patrol & Self-Healing Hub**
   - Distributed multi-node patrol orchestrator (`patrol-hub.js`).
   - Automated memory leak detection and graceful service restarts.
   - Circuit-breaker cooldown preventing alert spamming.

4. **Native MCP Server (Model Context Protocol)**
   - Exposes production-ready tools for AI agents:
     - `sre_get_system_health`: Real-time health check across cluster nodes.
     - `sre_get_metrics`: CPU, memory, and disk telemetry.
     - `sre_get_recon`: Service state, PM2 processes, and open ports.
     - `sre_run_patrol`: Execute comprehensive multi-node patrol.
     - `sre_send_alert`: Dispatch incident notification.

5. **Telemetry Bridge for Holographic HUD & Notifications**
   - Fast JSON telemetry streaming for Three.js WebGL 3D Arc Reactor interfaces.
   - Direct incident alerting via WhatsApp Bot worker integration.

---

## 🏗️ Architecture

```
                          ┌────────────────────────┐
                          │   Friday AI / Agent    │
                          │   (Antigravity / MCP)  │
                          └───────────┬────────────┘
                                      │ MCP Tools
                                      ▼
                          ┌────────────────────────┐
                          │     AI-SRE Hub         │
                          │  (vm-maskii :3400)     │
                          └───────────┬────────────┘
                                      │
            ┌─────────────────────────┴─────────────────────────┐
            │ Ed25519 Signed Request (Tailscale Private Mesh)   │
            ▼                                                   ▼
┌────────────────────────┐                             ┌────────────────────────┐
│  AI-SRE Node (lucky)   │                             │  AI-SRE Node (atcs)    │
│  - 14 PM2 Processes    │                             │  - KVM Hypervisor      │
│  - MySQL & Nginx       │                             │  - Ant Media           │
└────────────────────────┘                             └────────────────────────┘
```

---

## 🚀 Getting Started

### Prerequisites
- Node.js 18.0.0 or higher
- Linux (Ubuntu / Debian / RHEL)

### Installation

```bash
# Clone the repository
git clone https://github.com/lhermawan/ai-sre.git
cd ai-sre

# Install dependencies
npm install

# Copy environment configuration
cp .env.example .env
```

### Keypair Generation (Ed25519)

Generate asymmetric authentication keypairs for the agent and hub:

```bash
mkdir -p keys
ssh-keygen -t ed25519 -N "" -f keys/friday_agent.key -C "friday-agent-auth"
```

Export authorized public keys to the node's `keys/` directory (`keys/*.pub`).

---

## 🔧 CLI & MCP Usage

### Running Locally
```bash
# Start daemon
npm start

# Run system metrics check
node cli.js metrics

# Run service reconnaissance
node cli.js recon

# Execute full cluster patrol
node patrol-hub.js
```

### Connecting to MCP (Claude Desktop / Antigravity)

Add to your MCP configuration (`mcp_config.json`):

```json
{
  "mcpServers": {
    "ai-sre": {
      "command": "node",
      "args": ["/path/to/ai-sre/mcp-server.js"]
    }
  }
}
```

---

## 🔒 Security Best Practices

- **Never commit `.env` or private keys (`keys/*.key`)**.
- Keep all inter-node communication confined to private overlay networks (e.g., Tailscale / WireGuard).
- Enforce periodic key rotation for Ed25519 agents.

---

## 📄 License

This project is licensed under the [ISC License](LICENSE).

Authored by **Maskii Studio / Friday AI-SRE Team**.
