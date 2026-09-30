const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const KEYS_DIR = path.resolve(__dirname, '../keys');
const DEFAULT_PUB_KEY_PATH = path.resolve(KEYS_DIR, 'friday_agent.pub');
const DEFAULT_PRIV_KEY_PATH = path.resolve(KEYS_DIR, 'friday_agent.key');
const MASKII_PRIV_KEY_PATH = '/root/.ssh/id_ed25519_maskii';
const MASKII_PUB_KEY_PATH = path.resolve(KEYS_DIR, 'maskii.pub');

// In-memory sliding window for nonces (cleared every 60s)
const nonceCache = new Map();
const MAX_TIME_SKEW_MS = 60 * 1000; // 60 seconds

function cleanNonceCache() {
  const now = Date.now();
  for (const [nonce, expiry] of nonceCache.entries()) {
    if (now > expiry) {
      nonceCache.delete(nonce);
    }
  }
}

/**
 * Muat Private Key baik format PEM standard maupun OpenSSH ed25519
 */
function loadPrivateKey(keyPath) {
  const content = fs.readFileSync(keyPath, 'utf8');
  if (content.includes('BEGIN OPENSSH PRIVATE KEY')) {
    const lines = content.trim().split('\n').filter((l) => !l.startsWith('-----'));
    const buf = Buffer.from(lines.join(''), 'base64');
    let offset = 15; // Lewati 'openssh-key-v1\0'
    function readString() {
      const len = buf.readUInt32BE(offset);
      offset += 4;
      const str = buf.subarray(offset, offset + len);
      offset += len;
      return str;
    }
    readString(); // cipher (none)
    readString(); // kdf (none)
    readString(); // kdfoptions
    offset += 4; // numKeys
    readString(); // pub key blob
    const privKeyBlob = readString();
    let pOffset = 8; // lewati dua checkints uint32
    const keyTypeLen = privKeyBlob.readUInt32BE(pOffset);
    pOffset += 4 + keyTypeLen;
    const pubLen = privKeyBlob.readUInt32BE(pOffset);
    pOffset += 4 + pubLen;
    const privLen = privKeyBlob.readUInt32BE(pOffset);
    pOffset += 4;
    const privBytes = privKeyBlob.subarray(pOffset, pOffset + privLen);
    const seed = privBytes.subarray(0, 32);
    const pkcs8Prefix = Buffer.from('302e020100300506032b657004220420', 'hex');
    return crypto.createPrivateKey({
      key: Buffer.concat([pkcs8Prefix, seed]),
      format: 'der',
      type: 'pkcs8',
    });
  }
  return crypto.createPrivateKey(content);
}

/**
 * Generate client signature headers using Asymmetric Private Key (Maskii or Friday)
 */
function createSignatureHeaders({
  method = 'GET',
  urlPath = '/',
  agentId = 'maskii',
  privateKeyPath = MASKII_PRIV_KEY_PATH,
} = {}) {
  const privateKey = loadPrivateKey(privateKeyPath);

  const timestamp = Date.now().toString();
  const nonce = crypto.randomBytes(16).toString('hex');
  const normalizedPath = urlPath.split('?')[0];

  const payload = `${method.toUpperCase()}:${normalizedPath}:${timestamp}:${nonce}:${agentId}`;
  const signature = crypto.sign(null, Buffer.from(payload, 'utf8'), privateKey);

  return {
    'X-Agent-ID': agentId,
    'X-Timestamp': timestamp,
    'X-Nonce': nonce,
    'X-Signature': signature.toString('base64'),
  };
}

/**
 * Dapatkan daftar semua public key yang diotorisasi
 */
function getAuthorizedPublicKeys() {
  const keys = [];
  try {
    if (fs.existsSync(KEYS_DIR)) {
      const files = fs.readdirSync(KEYS_DIR).filter((f) => f.endsWith('.pub'));
      for (const file of files) {
        try {
          const keyPath = path.resolve(KEYS_DIR, file);
          const pem = fs.readFileSync(keyPath, 'utf8');
          keys.push({
            name: file.replace('.pub', ''),
            key: crypto.createPublicKey(pem),
          });
        } catch (e) {
          // ignore invalid pub key
        }
      }
    }
  } catch (err) {
    console.error('Failed to read authorized keys:', err);
  }
  return keys;
}

/**
 * Verify request headers using Authorized Public Keys (Zero Trust Verification)
 */
function verifyRequestSignature({
  method = 'GET',
  urlPath = '/',
  headers = {},
  publicKeyPath = null,
} = {}) {
  cleanNonceCache();

  const agentId = headers['x-agent-id'] || headers['X-Agent-ID'];
  const timestampStr = headers['x-timestamp'] || headers['X-Timestamp'];
  const nonce = headers['x-nonce'] || headers['X-Nonce'];
  const signatureBase64 = headers['x-signature'] || headers['X-Signature'];

  if (!agentId || !timestampStr || !nonce || !signatureBase64) {
    return {
      valid: false,
      error: 'Missing required security headers (X-Agent-ID, X-Timestamp, X-Nonce, X-Signature)',
    };
  }

  const timestamp = parseInt(timestampStr, 10);
  if (isNaN(timestamp)) {
    return { valid: false, error: 'Invalid X-Timestamp header' };
  }

  const now = Date.now();
  if (Math.abs(now - timestamp) > MAX_TIME_SKEW_MS) {
    return { valid: false, error: 'Timestamp expired or clock skew exceeded 60s' };
  }

  if (nonceCache.has(nonce)) {
    return { valid: false, error: 'Replay attack detected: Nonce already used' };
  }

  const normalizedPath = urlPath.split('?')[0];
  const payload = `${method.toUpperCase()}:${normalizedPath}:${timestampStr}:${nonce}:${agentId}`;
  const payloadBuffer = Buffer.from(payload, 'utf8');

  let signatureBuffer;
  try {
    signatureBuffer = Buffer.from(signatureBase64, 'base64');
  } catch {
    return { valid: false, error: 'Invalid Base64 signature format' };
  }

  // Cari key yang cocok di antara authorized public keys
  const authorizedKeys = getAuthorizedPublicKeys();
  let verifiedKeyName = null;

  for (const { name, key } of authorizedKeys) {
    try {
      const isVerified = crypto.verify(null, payloadBuffer, key, signatureBuffer);
      if (isVerified) {
        verifiedKeyName = name;
        break;
      }
    } catch {
      // lanjut coba key lain
    }
  }

  if (!verifiedKeyName) {
    return {
      valid: false,
      error: 'Asymmetric signature verification failed (Key not authorized or signature mismatch)',
    };
  }

  // Daftarkan nonce pada sliding window
  nonceCache.set(nonce, now + MAX_TIME_SKEW_MS);

  return {
    valid: true,
    agentId,
    verifiedKey: verifiedKeyName,
    timestamp,
  };
}

module.exports = {
  createSignatureHeaders,
  verifyRequestSignature,
  loadPrivateKey,
  getAuthorizedPublicKeys,
  DEFAULT_PUB_KEY_PATH,
  DEFAULT_PRIV_KEY_PATH,
  MASKII_PRIV_KEY_PATH,
  MASKII_PUB_KEY_PATH,
};
