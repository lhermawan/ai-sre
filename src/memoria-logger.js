const { spawn } = require('child_process');

/**
 * Log entity and relationships directly into local MemoriaGraph Neo4j via record_log.py
 */
async function recordToMemoriaGraph({
  entityName,
  entityType = 'PatrolLog',
  description = '',
  relations = [],
}) {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify({
      entityName,
      entityType,
      description,
      relations,
    });

    const proc = spawn('/opt/memoriagraph/venv/bin/python', [
      '/opt/memoriagraph/record_log.py',
    ]);
    let stdout = '';
    let stderr = '';

    proc.stdout.on('data', (d) => {
      stdout += d.toString();
    });

    proc.stderr.on('data', (d) => {
      stderr += d.toString();
    });

    proc.on('close', (code) => {
      if (code === 0 && stdout.includes('SUCCESS_RECORD_MEMORIAGRAPH')) {
        resolve({ success: true, entity: entityName });
      } else {
        reject(
          new Error(`MemoriaGraph logging failed (code ${code}): ${stderr || stdout}`)
        );
      }
    });

    proc.on('error', (err) => {
      reject(err);
    });

    proc.stdin.write(payload);
    proc.stdin.end();
  });
}

module.exports = {
  recordToMemoriaGraph,
};
