const http = require('http');
const { collectAllMetrics } = require('./metrics');
const { collectAllRecon } = require('./recon');
const { verifyRequestSignature } = require('./auth');

const HOST = process.env.AI_SRE_HOST || '127.0.0.1';
const PORT = parseInt(process.env.AI_SRE_PORT || '3400', 10);

const server = http.createServer(async (req, res) => {
  res.setHeader('Content-Type', 'application/json');

  // Enforce localhost IP check
  const remoteIp = req.socket.remoteAddress || '';
  const isLocal =
    remoteIp === '127.0.0.1' ||
    remoteIp === '::1' ||
    remoteIp === '::ffff:127.0.0.1';

  if (!isLocal) {
    console.warn(`⛔ [403 Forbidden] Access attempt from non-local IP: ${remoteIp}`);
    res.writeHead(403);
    res.end(JSON.stringify({ ok: false, error: 'Forbidden: Localhost access only' }));
    return;
  }

  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = url.pathname;

  // Unauthenticated healthcheck
  if (req.method === 'GET' && pathname === '/health') {
    res.writeHead(200);
    res.end(
      JSON.stringify({
        ok: true,
        service: 'ai-sre-agent',
        status: 'online',
        timestamp: new Date().toISOString(),
      })
    );
    return;
  }

  // All /api/* endpoints require Asymmetric Signature Authentication
  if (pathname.startsWith('/api/')) {
    const authResult = verifyRequestSignature({
      method: req.method,
      urlPath: pathname,
      headers: req.headers,
    });

    if (!authResult.valid) {
      console.warn(`⛔ [401 Unauthorized] Auth failed on ${pathname}: ${authResult.error}`);
      res.writeHead(401);
      res.end(
        JSON.stringify({
          ok: false,
          error: `Unauthorized: ${authResult.error}`,
          required_auth: 'Ed25519 Asymmetric Signature (X-Agent-ID, X-Timestamp, X-Nonce, X-Signature)',
        })
      );
      return;
    }

    try {
      if (req.method === 'GET' && pathname === '/api/metrics') {
        const data = await collectAllMetrics();
        res.writeHead(200);
        res.end(JSON.stringify({ ok: true, agent: authResult.agentId, data }, null, 2));
        return;
      }

      if (req.method === 'GET' && pathname === '/api/recon') {
        const data = await collectAllRecon();
        res.writeHead(200);
        res.end(JSON.stringify({ ok: true, agent: authResult.agentId, data }, null, 2));
        return;
      }

      if (req.method === 'GET' && pathname === '/api/all') {
        const [metrics, recon] = await Promise.all([collectAllMetrics(), collectAllRecon()]);
        res.writeHead(200);
        res.end(
          JSON.stringify(
            {
              ok: true,
              agent: authResult.agentId,
              timestamp: new Date().toISOString(),
              data: {
                metrics,
                recon,
              },
            },
            null,
            2
          )
        );
        return;
      }

      if (req.method === 'GET' && pathname === '/api/graph/visualize') {
        const bankFilter = url.searchParams.get('bank') || null;
        const limitParam = parseInt(url.searchParams.get('limit') || '150', 10);
        
        const { execFile } = require('child_process');
        execFile(
          '/opt/memoriagraph/venv/bin/python',
          [
            '-c',
            `import sys; sys.path.insert(0, '/opt/memoriagraph'); from src.graph_visualizer import export_graph_for_3d_hud; import json; print(json.dumps(export_graph_for_3d_hud(limit_nodes=${limitParam}, bank_filter=${bankFilter ? `'${bankFilter}'` : 'None'})))`
          ],
          { cwd: '/opt/memoriagraph' },
          (error, stdout, stderr) => {
            if (error) {
              console.error('Visualizer export error:', stderr || error.message);
              res.writeHead(500);
              res.end(JSON.stringify({ ok: false, error: error.message }));
              return;
            }
            res.writeHead(200);
            res.end(stdout.trim());
          }
        );
        return;
      }
    } catch (err) {
      console.error(`Internal error on ${pathname}:`, err);
      res.writeHead(500);
      res.end(JSON.stringify({ ok: false, error: err.message }));
      return;
    }
  }

  res.writeHead(404);
  res.end(JSON.stringify({ ok: false, error: 'Endpoint not found' }));
});

function startServer() {
  server.listen(PORT, HOST, () => {
    console.log(`👁️ 👂 AI-SRE Agent API listening on http://${HOST}:${PORT}`);
    console.log(`🔐 Zero Trust Asymmetric Auth: Enabled (Ed25519)`);
  });
}

if (require.main === module) {
  startServer();
}

module.exports = {
  server,
  startServer,
};
