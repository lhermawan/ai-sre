const os = require('os');
const { exec } = require('child_process');
const fs = require('fs');
const { promisify } = require('util');

const execAsync = promisify(exec);

async function getPm2Metrics() {
  try {
    const { stdout } = await execAsync('pm2 jlist', { timeout: 8000 });
    const list = JSON.parse(stdout);

    const processes = list.map((proc) => {
      const pm2Env = proc.pm2_env || {};
      const mon = proc.monit || {};
      const memoryBytes = mon.memory || 0;
      const memoryMb = parseFloat((memoryBytes / (1024 * 1024)).toFixed(2));
      const cpuPercent = parseFloat((mon.cpu || 0).toFixed(1));

      return {
        id: proc.pm_id,
        name: proc.name,
        status: pm2Env.status || 'unknown',
        restarts: pm2Env.restart_time || 0,
        unstable_restarts: pm2Env.unstable_restarts || 0,
        uptime_seconds: pm2Env.pm_uptime ? Math.floor((Date.now() - pm2Env.pm_uptime) / 1000) : 0,
        cpu_percent: cpuPercent,
        memory_mb: memoryMb,
        exec_mode: pm2Env.exec_mode || 'fork_mode',
      };
    });

    const errored = processes.filter((p) => p.status === 'errored' || p.status === 'stopped');
    const online = processes.filter((p) => p.status === 'online');

    return {
      status: errored.length === 0 ? 'HEALTHY' : 'DEGRADED',
      total_processes: processes.length,
      online_count: online.length,
      errored_count: errored.length,
      processes,
      alerts: errored.map((p) => `Process ${p.name} (id:${p.id}) is in status: ${p.status}`),
    };
  } catch (err) {
    return {
      status: 'ERROR',
      error: `Failed to fetch PM2 list: ${err.message}`,
      processes: [],
      alerts: ['PM2 service unreachable or errored'],
    };
  }
}

async function getRamMetrics() {
  try {
    const meminfo = fs.readFileSync('/proc/meminfo', 'utf8');
    const parseField = (name) => {
      const match = meminfo.match(new RegExp(`^${name}:\\s+(\\d+)\\s+kB`, 'm'));
      return match ? parseInt(match[1], 10) * 1024 : 0;
    };

    const totalBytes = parseField('MemTotal') || os.totalmem();
    const freeBytes = parseField('MemFree');
    const availableBytes = parseField('MemAvailable') || os.freemem();
    const buffersBytes = parseField('Buffers');
    const cachedBytes = parseField('Cached');

    const usedBytes = totalBytes - availableBytes;
    const usedPercent = parseFloat(((usedBytes / totalBytes) * 100).toFixed(2));

    let status = 'HEALTHY';
    if (usedPercent >= 92) status = 'CRITICAL';
    else if (usedPercent >= 80) status = 'WARNING';

    return {
      status,
      total_mb: parseFloat((totalBytes / (1024 * 1024)).toFixed(1)),
      used_mb: parseFloat((usedBytes / (1024 * 1024)).toFixed(1)),
      available_mb: parseFloat((availableBytes / (1024 * 1024)).toFixed(1)),
      used_percent: usedPercent,
    };
  } catch {
    const total = os.totalmem();
    const free = os.freemem();
    const used = total - free;
    const usedPercent = parseFloat(((used / total) * 100).toFixed(2));

    return {
      status: usedPercent >= 90 ? 'CRITICAL' : 'HEALTHY',
      total_mb: parseFloat((total / (1024 * 1024)).toFixed(1)),
      used_mb: parseFloat((used / (1024 * 1024)).toFixed(1)),
      available_mb: parseFloat((free / (1024 * 1024)).toFixed(1)),
      used_percent: usedPercent,
    };
  }
}

async function getDiskMetrics() {
  try {
    const { stdout } = await execAsync('df -B1 /', { timeout: 5000 });
    const lines = stdout.trim().split('\n');
    if (lines.length < 2) throw new Error('Unexpected df output format');

    const parts = lines[1].replace(/\s+/g, ' ').split(' ');
    const filesystem = parts[0];
    const totalBytes = parseInt(parts[1], 10);
    const usedBytes = parseInt(parts[2], 10);
    const availableBytes = parseInt(parts[3], 10);
    const usedPercentStr = parts[4] || '0%';
    const usedPercent = parseFloat(usedPercentStr.replace('%', ''));

    let status = 'HEALTHY';
    if (usedPercent >= 90) status = 'CRITICAL';
    else if (usedPercent >= 80) status = 'WARNING';

    return {
      status,
      filesystem,
      mount: '/',
      total_gb: parseFloat((totalBytes / (1024 * 1024 * 1024)).toFixed(2)),
      used_gb: parseFloat((usedBytes / (1024 * 1024 * 1024)).toFixed(2)),
      available_gb: parseFloat((availableBytes / (1024 * 1024 * 1024)).toFixed(2)),
      used_percent: usedPercent,
    };
  } catch (err) {
    return {
      status: 'ERROR',
      error: `Failed to inspect disk usage: ${err.message}`,
    };
  }
}

async function getCpuMetrics() {
  const cpus = os.cpus();
  const loadavg = os.loadavg();
  const cores = cpus.length;
  const load1m = parseFloat(loadavg[0].toFixed(2));
  const load5m = parseFloat(loadavg[1].toFixed(2));
  const load15m = parseFloat(loadavg[2].toFixed(2));

  const loadPercent = parseFloat(((load1m / cores) * 100).toFixed(1));

  let status = 'HEALTHY';
  if (loadPercent >= 90) status = 'CRITICAL';
  else if (loadPercent >= 75) status = 'WARNING';

  return {
    status,
    cores,
    model: cpus[0]?.model || 'Generic CPU',
    load_1m: load1m,
    load_5m: load5m,
    load_15m: load15m,
    estimated_load_percent: loadPercent,
  };
}

async function collectAllMetrics() {
  const [pm2, ram, disk, cpu] = await Promise.all([
    getPm2Metrics(),
    getRamMetrics(),
    getDiskMetrics(),
    getCpuMetrics(),
  ]);

  const alerts = [];
  if (pm2.alerts && pm2.alerts.length > 0) alerts.push(...pm2.alerts);
  if (ram.status === 'CRITICAL') alerts.push(`RAM usage critical: ${ram.used_percent}%`);
  if (disk.status === 'CRITICAL') alerts.push(`Disk usage critical: ${disk.used_percent}%`);
  if (cpu.status === 'CRITICAL') alerts.push(`CPU load critical: ${cpu.estimated_load_percent}%`);

  const overallStatus =
    pm2.status === 'CRITICAL' || ram.status === 'CRITICAL' || disk.status === 'CRITICAL'
      ? 'CRITICAL'
      : pm2.status === 'DEGRADED' || ram.status === 'WARNING' || disk.status === 'WARNING'
      ? 'WARNING'
      : 'HEALTHY';

  return {
    timestamp: new Date().toISOString(),
    overall_status: overallStatus,
    alerts,
    pm2,
    ram,
    disk,
    cpu,
    system: {
      hostname: os.hostname(),
      uptime_seconds: Math.floor(os.uptime()),
      uptime_hours: parseFloat((os.uptime() / 3600).toFixed(1)),
      platform: os.platform(),
      arch: os.arch(),
      node_version: process.version,
    },
  };
}

module.exports = {
  getPm2Metrics,
  getRamMetrics,
  getDiskMetrics,
  getCpuMetrics,
  collectAllMetrics,
};
