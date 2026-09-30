const http = require('http');
const { createSignatureHeaders } = require('./auth');

const SRE_SERVER_URL = process.env.AI_SRE_URL || 'http://127.0.0.1:3400';

/**
 * Fetch from AI-SRE API with Asymmetric Private Key signature
 */
async function querySreApi(endpoint = '/api/all') {
  const url = new URL(endpoint, SRE_SERVER_URL);
  const headers = createSignatureHeaders({
    method: 'GET',
    urlPath: url.pathname,
  });

  return new Promise((resolve, reject) => {
    const req = http.request(
      url,
      {
        method: 'GET',
        headers: {
          ...headers,
          Accept: 'application/json',
        },
        timeout: 15000,
      },
      (res) => {
        let body = '';
        res.on('data', (chunk) => {
          body += chunk.toString();
        });
        res.on('end', () => {
          try {
            const parsed = JSON.parse(body);
            resolve({
              status_code: res.statusCode,
              headers: res.headers,
              data: parsed,
            });
          } catch (e) {
            resolve({
              status_code: res.statusCode,
              raw: body,
              error: 'Failed to parse JSON response',
            });
          }
        });
      }
    );

    req.on('error', (err) => {
      reject(new Error(`Failed connecting to AI-SRE server: ${err.message}`));
    });

    req.on('timeout', () => {
      req.destroy();
      reject(new Error('AI-SRE request timed out after 15s'));
    });

    req.end();
  });
}

module.exports = {
  querySreApi,
};
