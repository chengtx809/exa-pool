/**
 * Exa Pool - Cloudflare Worker
 * A load balancing solution for managing multiple Exa API keys
 */

// ============================================================================
// Environment Bindings Interface
// ============================================================================

/**
 * @typedef {Object} Env
 * @property {D1Database} DB - D1 database binding
 * @property {string} ADMIN_KEY - Admin authentication key
 */

// ============================================================================
// Database Schema
// ============================================================================

const DB_SCHEMA = `
-- Exa API 密钥表
CREATE TABLE IF NOT EXISTS exa_keys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  key TEXT UNIQUE NOT NULL,
  status TEXT DEFAULT 'active' CHECK(status IN ('active', 'exhausted', 'invalid')),
  last_used TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  error_message TEXT,
  success_count INTEGER DEFAULT 0
);

-- 允许访问的 API Key 表
CREATE TABLE IF NOT EXISTS allowed_keys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  key TEXT UNIQUE NOT NULL,
  name TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);

-- 请求统计表
CREATE TABLE IF NOT EXISTS request_stats (
  id INTEGER PRIMARY KEY CHECK(id = 1),
  total_success INTEGER DEFAULT 0,
  total_failure INTEGER DEFAULT 0
);

-- Initialize request_stats with default row
INSERT OR IGNORE INTO request_stats (id, total_success, total_failure) VALUES (1, 0, 0);

-- 轮询状态表（记录当前轮询位置）
CREATE TABLE IF NOT EXISTS round_robin_state (
  id INTEGER PRIMARY KEY CHECK(id = 1),
  last_key_id INTEGER DEFAULT 0
);

-- 系统配置表
CREATE TABLE IF NOT EXISTS config (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

-- Initialize round_robin_state with default row
INSERT OR IGNORE INTO round_robin_state (id, last_key_id) VALUES (1, 0);

-- Research 任务与密钥映射表
CREATE TABLE IF NOT EXISTS research_tasks (
  id TEXT PRIMARY KEY,
  exa_key_id INTEGER NOT NULL,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (exa_key_id) REFERENCES exa_keys(id) ON DELETE CASCADE
);

-- Create indexes for better query performance
CREATE INDEX IF NOT EXISTS idx_exa_keys_status ON exa_keys(status);
CREATE INDEX IF NOT EXISTS idx_allowed_keys_key ON allowed_keys(key);
CREATE INDEX IF NOT EXISTS idx_research_tasks_exa_key_id ON research_tasks(exa_key_id);
`;

// ============================================================================
// Database Initialization
// ============================================================================

/** Flag to track if database has been initialized in this worker instance */
let dbInitialized = false;

/**
 * Initialize the D1 database with required tables
 * Runs only once per worker instance
 * @param {D1Database} db - D1 database instance
 * @returns {Promise<void>}
 */
async function initializeDatabase(db) {
  if (dbInitialized) {
    return;
  }

  const statements = DB_SCHEMA
    .split(';')
    .map(s => s.trim())
    .filter(s => s.length > 0);

  for (const statement of statements) {
    try {
      await db.prepare(statement).run();
    } catch (error) {
      // Ignore errors for CREATE TABLE IF NOT EXISTS and INSERT OR IGNORE
      // These are expected when tables already exist
      if (!error.message?.includes('already exists')) {
        console.error('Database initialization error:', error);
      }
    }
  }

  dbInitialized = true;
}

/**
 * Ensure database is initialized before handling requests
 * @param {D1Database} db - D1 database instance
 * @returns {Promise<void>}
 */
async function ensureDatabase(db) {
  await initializeDatabase(db);
}

// ============================================================================
// Router Framework
// ============================================================================

/**
 * @typedef {Object} RouteHandler
 * @property {RegExp} pattern - URL pattern to match
 * @property {string} method - HTTP method
 * @property {function(Request, Env, Object): Promise<Response>} handler - Request handler
 */

/** @type {RouteHandler[]} */
const routes = [
  // Admin Panel
  { pattern: /^\/$/, method: 'GET', handler: serveAdminPanel },
  { pattern: /^\/api\/admin\/login$/, method: 'POST', handler: handleAdminLogin },
  { pattern: /^\/api\/admin\/logout$/, method: 'POST', handler: handleAdminLogout },
  { pattern: /^\/api\/admin\/keys$/, method: 'GET', handler: listExaKeys },
  { pattern: /^\/api\/admin\/keys$/, method: 'POST', handler: addExaKeys },
  { pattern: /^\/api\/admin\/keys$/, method: 'DELETE', handler: deleteExaKeys },
  { pattern: /^\/api\/admin\/keys\/validate$/, method: 'POST', handler: updateKeysValidationStatus },
  { pattern: /^\/api\/admin\/keys\/check$/, method: 'POST', handler: checkSingleKeyValidity },
  { pattern: /^\/api\/admin\/keys\/cleanup$/, method: 'POST', handler: cleanupInvalidKeys },
  { pattern: /^\/api\/admin\/allowed-keys$/, method: 'GET', handler: listAllowedKeys },
  { pattern: /^\/api\/admin\/allowed-keys$/, method: 'POST', handler: addAllowedKey },
  { pattern: /^\/api\/admin\/allowed-keys$/, method: 'DELETE', handler: deleteAllowedKey },
  { pattern: /^\/api\/admin\/stats$/, method: 'GET', handler: getStats },
  
  // Proxy API - 官方 Exa API 兼容路径
  { pattern: /^\/research\/v1$/, method: 'POST', handler: proxyResearchCreate },
  { pattern: /^\/research\/v1$/, method: 'GET', handler: proxyResearchList },
  { pattern: /^\/research\/v1\/(?<id>[^/]+)$/, method: 'GET', handler: proxyResearchGet },
  { pattern: /^\/search$/, method: 'POST', handler: proxySearch },
  { pattern: /^\/contents$/, method: 'POST', handler: proxyContents },
  { pattern: /^\/findSimilar$/, method: 'POST', handler: proxyFindSimilar },
  { pattern: /^\/answer$/, method: 'POST', handler: proxyAnswer },
];

/**
 * Match a request to a route handler
 * @param {Request} request - Incoming request
 * @returns {{handler: function, params: Object} | null}
 */
function matchRoute(request) {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

  for (const route of routes) {
    if (route.method === method) {
      const match = path.match(route.pattern);
      if (match) {
        return {
          handler: route.handler,
          params: match.groups || {}
        };
      }
    }
  }
  return null;
}

// ============================================================================
// Authentication Component
// ============================================================================

/** Session expiration time in milliseconds (7 days) */
const SESSION_EXPIRATION_MS = 7 * 24 * 60 * 60 * 1000;

/**
 * @typedef {Object} AuthResult
 * @property {boolean} valid - Whether authentication succeeded
 * @property {string} [error] - Error message if authentication failed
 */

/**
 * Validate admin key against environment configuration
 * @param {string} key - Admin key to validate
 * @param {Env} env - Environment bindings
 * @returns {AuthResult}
 */
function validateAdminKey(key, env) {
  if (!key || typeof key !== 'string') {
    return { valid: false, error: 'Admin key is required' };
  }

  if (!env.ADMIN_KEY) {
    return { valid: false, error: 'Admin key not configured' };
  }

  // Constant-time comparison to prevent timing attacks
  const keyBuffer = new TextEncoder().encode(key);
  const adminKeyBuffer = new TextEncoder().encode(env.ADMIN_KEY);

  if (keyBuffer.length !== adminKeyBuffer.length) {
    return { valid: false, error: 'Invalid admin key' };
  }

  let result = 0;
  for (let i = 0; i < keyBuffer.length; i++) {
    result |= keyBuffer[i] ^ adminKeyBuffer[i];
  }

  if (result !== 0) {
    return { valid: false, error: 'Invalid admin key' };
  }

  return { valid: true };
}

/**
 * Base64URL encode
 * @param {ArrayBuffer|Uint8Array} buffer
 * @returns {string}
 */
function base64UrlEncode(buffer) {
  const bytes = buffer instanceof ArrayBuffer ? new Uint8Array(buffer) : buffer;
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Base64URL decode
 * @param {string} str
 * @returns {Uint8Array}
 */
function base64UrlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  const binary = atob(str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Generate a JWT token using HMAC-SHA256
 * @param {Object} payload - Token payload
 * @param {string} secret - Secret key for signing
 * @returns {Promise<string>} - JWT token
 */
async function generateJWT(payload, secret) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const encodedHeader = base64UrlEncode(new TextEncoder().encode(JSON.stringify(header)));
  const encodedPayload = base64UrlEncode(new TextEncoder().encode(JSON.stringify(payload)));
  
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  
  const signature = await crypto.subtle.sign(
    'HMAC',
    key,
    new TextEncoder().encode(`${encodedHeader}.${encodedPayload}`)
  );
  
  return `${encodedHeader}.${encodedPayload}.${base64UrlEncode(signature)}`;
}

/**
 * Verify and decode a JWT token
 * @param {string} token - JWT token
 * @param {string} secret - Secret key for verification
 * @returns {Promise<{valid: boolean, payload?: Object, error?: string}>}
 */
async function verifyJWT(token, secret) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) {
      return { valid: false, error: 'Invalid token format' };
    }
    
    const [encodedHeader, encodedPayload, encodedSignature] = parts;
    
    const key = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );
    
    const signatureValid = await crypto.subtle.verify(
      'HMAC',
      key,
      base64UrlDecode(encodedSignature),
      new TextEncoder().encode(`${encodedHeader}.${encodedPayload}`)
    );
    
    if (!signatureValid) {
      return { valid: false, error: 'Invalid signature' };
    }
    
    const payload = JSON.parse(new TextDecoder().decode(base64UrlDecode(encodedPayload)));
    
    // Check expiration
    if (payload.exp && Date.now() > payload.exp) {
      return { valid: false, error: 'Token expired' };
    }
    
    return { valid: true, payload };
  } catch (error) {
    return { valid: false, error: 'Invalid token' };
  }
}

/**
 * Generate a session token (JWT)
 * @param {Env} env - Environment bindings
 * @returns {Promise<string>} - JWT token
 */
async function generateSessionToken(env) {
  const payload = {
    role: 'admin',
    iat: Date.now(),
    exp: Date.now() + SESSION_EXPIRATION_MS
  };
  return generateJWT(payload, env.ADMIN_KEY);
}

/**
 * Validate a session token (JWT)
 * @param {string} token - Session token to validate
 * @param {Env} env - Environment bindings
 * @returns {Promise<AuthResult>}
 */
async function validateSessionToken(token, env) {
  if (!token || typeof token !== 'string') {
    return { valid: false, error: 'Session token is required' };
  }
  
  const result = await verifyJWT(token, env.ADMIN_KEY);
  
  if (!result.valid) {
    return { valid: false, error: result.error };
  }
  
  return { valid: true };
}

/**
 * Extract session token from request headers
 * @param {Request} request - Incoming request
 * @returns {string|null} - Session token or null
 */
function getSessionTokenFromRequest(request) {
  const authHeader = request.headers.get('Authorization');
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.slice(7);
  }
  return null;
}

/**
 * Middleware to require admin authentication
 * @param {Request} request - Incoming request
 * @param {Env} env - Environment bindings
 * @returns {Promise<AuthResult>}
 */
async function requireAdminAuth(request, env) {
  const token = getSessionTokenFromRequest(request);
  if (!token) {
    return { valid: false, error: 'Authentication required' };
  }
  return validateSessionToken(token, env);
}

/**
 * Extract API key from request headers
 * @param {Request} request - Incoming request
 * @returns {string|null} - API key or null
 */
function getApiKeyFromRequest(request) {
  // Check x-api-key header first
  const apiKey = request.headers.get('x-api-key');
  if (apiKey) {
    return apiKey;
  }
  
  // Also check Authorization header with Bearer token
  const authHeader = request.headers.get('Authorization');
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.slice(7);
  }
  
  return null;
}

/**
 * Validate an API key against the allowed_keys table
 * @param {string} key - API key to validate
 * @param {D1Database} db - D1 database instance
 * @returns {Promise<AuthResult>}
 */
async function validateAllowedKey(key, db) {
  if (!key || typeof key !== 'string') {
    return { valid: false, error: 'API key is required' };
  }

  try {
    const result = await db.prepare(
      'SELECT id FROM allowed_keys WHERE key = ?'
    ).bind(key).first();

    if (!result) {
      return { valid: false, error: 'Invalid API key' };
    }

    return { valid: true };
  } catch (error) {
    console.error('Error validating API key:', error);
    return { valid: false, error: 'Failed to validate API key' };
  }
}

/**
 * Middleware to require API key authentication for proxy endpoints
 * @param {Request} request - Incoming request
 * @param {D1Database} db - D1 database instance
 * @returns {Promise<AuthResult>}
 */
async function requireApiKeyAuth(request, db) {
  const apiKey = getApiKeyFromRequest(request);
  if (!apiKey) {
    return { valid: false, error: 'API key is required' };
  }
  return validateAllowedKey(apiKey, db);
}

// ============================================================================
// Key Pool Management Component
// ============================================================================

/**
 * Validate Exa API key format
 * Exa keys typically start with a specific prefix and have a certain length
 * @param {string} key - Key to validate
 * @returns {boolean} - Whether the key format is valid
 */
function isValidExaKeyFormat(key) {
  // Basic validation: non-empty string with reasonable length
  // Exa keys are typically alphanumeric with dashes
  if (!key || typeof key !== 'string') {
    return false;
  }
  
  const trimmed = key.trim();
  // Minimum length check and basic character validation
  // Exa keys are typically 30+ characters
  if (trimmed.length < 10) {
    return false;
  }
  
  // Allow alphanumeric characters, dashes, and underscores
  return /^[a-zA-Z0-9_-]+$/.test(trimmed);
}

/**
 * Parse multi-line key input and validate each key
 * @param {string} input - Multi-line string with one key per line
 * @returns {{keys: string[], invalid: string[]}} - Parsed valid keys and invalid entries
 */
function parseKeyInput(input) {
  if (!input || typeof input !== 'string') {
    return { keys: [], invalid: [] };
  }

  const lines = input.split('\n');
  const keys = [];
  const invalid = [];

  for (const line of lines) {
    const trimmed = line.trim();
    
    // Skip empty lines
    if (trimmed.length === 0) {
      continue;
    }

    if (isValidExaKeyFormat(trimmed)) {
      keys.push(trimmed);
    } else {
      invalid.push(trimmed);
    }
  }

  return { keys, invalid };
}

/**
 * Add multiple Exa keys to the database with duplicate detection
 * @param {D1Database} db - D1 database instance
 * @param {string[]} keys - Array of keys to add
 * @returns {Promise<{added: number, skipped: string[], errors: string[]}>}
 */
async function addKeysToDatabase(db, keys) {
  const added = [];
  const skipped = [];
  const errors = [];

  for (const key of keys) {
    try {
      await db.prepare(
        'INSERT INTO exa_keys (key, status) VALUES (?, ?)'
      ).bind(key, 'active').run();
      added.push(key);
    } catch (error) {
      // Check if it's a duplicate key error
      if (error.message?.includes('UNIQUE constraint failed') || 
          error.message?.includes('SQLITE_CONSTRAINT')) {
        skipped.push(key);
      } else {
        errors.push(`${key}: ${error.message}`);
      }
    }
  }

  return { added: added.length, skipped, errors };
}

/**
 * Get the next available Exa key using round-robin selection
 * @param {D1Database} db - D1 database instance
 * @returns {Promise<{id: number, key: string} | null>}
 */
async function getNextKey(db) {
  // Get current round-robin state
  const stateResult = await db.prepare(
    'SELECT last_key_id FROM round_robin_state WHERE id = 1'
  ).first();
  
  const lastKeyId = stateResult?.last_key_id || 0;

  // Get the next active key after the last used one
  let nextKey = await db.prepare(
    `SELECT id, key FROM exa_keys 
     WHERE status = 'active' AND id > ? 
     ORDER BY id ASC 
     LIMIT 1`
  ).bind(lastKeyId).first();

  // If no key found after lastKeyId, wrap around to the beginning
  if (!nextKey) {
    nextKey = await db.prepare(
      `SELECT id, key FROM exa_keys 
       WHERE status = 'active' 
       ORDER BY id ASC 
       LIMIT 1`
    ).first();
  }

  if (!nextKey) {
    return null;
  }

  // Update round-robin state
  await db.prepare(
    'UPDATE round_robin_state SET last_key_id = ? WHERE id = 1'
  ).bind(nextKey.id).run();

  // Update last_used timestamp
  await db.prepare(
    'UPDATE exa_keys SET last_used = datetime(\'now\') WHERE id = ?'
  ).bind(nextKey.id).run();

  return { id: nextKey.id, key: nextKey.key };
}

/**
 * Mark a key with a specific status
 * @param {D1Database} db - D1 database instance
 * @param {number} keyId - Key ID to update
 * @param {string} status - New status ('active', 'exhausted', 'invalid')
 * @param {string} [errorMessage] - Optional error message
 * @returns {Promise<void>}
 */
async function markKeyStatus(db, keyId, status, errorMessage = null) {
  await db.prepare(
    'UPDATE exa_keys SET status = ?, error_message = ? WHERE id = ?'
  ).bind(status, errorMessage, keyId).run();
}

/**
 * Delete multiple keys by their IDs
 * @param {D1Database} db - D1 database instance
 * @param {number[]} keyIds - Array of key IDs to delete
 * @returns {Promise<number>} - Number of keys deleted
 */
async function deleteKeysFromDatabase(db, keyIds) {
  if (!keyIds || keyIds.length === 0) {
    return 0;
  }

  // Build placeholders for the IN clause
  const placeholders = keyIds.map(() => '?').join(', ');
  const result = await db.prepare(
    `DELETE FROM exa_keys WHERE id IN (${placeholders})`
  ).bind(...keyIds).run();

  return result.meta?.changes || 0;
}

// ============================================================================
// Placeholder Handlers (to be implemented in subsequent tasks)
// ============================================================================

/**
 * Serve the admin panel HTML
 * @param {Request} request - Incoming request
 * @param {Env} env - Environment bindings
 * @param {Object} params - Route parameters
 * @returns {Promise<Response>}
 */
async function serveAdminPanel(request, env, params) {
  const config = {
    validationConcurrency: parseInt(env.VALIDATION_CONCURRENCY) || 10
  };
  return new Response(generateAdminPanelHTML(config), {
    headers: { 'Content-Type': 'text/html; charset=utf-8' }
  });
}

/**
 * Generate the admin panel HTML
 * @param {Object} config - Configuration options
 * @param {number} config.validationConcurrency - Concurrency limit for key validation
 * @returns {string} - Complete HTML document
 */
function generateAdminPanelHTML(config = { validationConcurrency: 10 }) {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <script>window.APP_CONFIG = ${JSON.stringify(config)};</script>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Exa 密钥负载均衡器 - 管理面板</title>
  <style>
    :root {
      --primary: #6366f1;
      --primary-hover: #4f46e5;
      --danger: #ef4444;
      --danger-hover: #dc2626;
      --success: #22c55e;
      --warning: #f59e0b;
      --bg: #0f172a;
      --bg-card: #1e293b;
      --bg-input: #334155;
      --text: #f1f5f9;
      --text-muted: #94a3b8;
      --border: #475569;
      --radius: 8px;
    }
    
    * { box-sizing: border-box; margin: 0; padding: 0; }
    
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      min-height: 100vh;
      line-height: 1.5;
    }
    
    .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
    
    /* Login */
    .login-container {
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
    }
    
    .login-box {
      background: var(--bg-card);
      padding: 40px;
      border-radius: var(--radius);
      width: 100%;
      max-width: 400px;
    }
    
    .login-box h1 { text-align: center; margin-bottom: 30px; font-size: 24px; }
    
    /* Forms */
    .form-group { margin-bottom: 16px; }
    .form-group label { display: block; margin-bottom: 6px; color: var(--text-muted); font-size: 14px; }
    
    input, textarea {
      width: 100%;
      padding: 12px;
      background: var(--bg-input);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      color: var(--text);
      font-size: 14px;
    }
    
    input:focus, textarea:focus {
      outline: none;
      border-color: var(--primary);
      box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.2);
    }
    
    textarea { resize: vertical; min-height: 100px; font-family: monospace; }
    
    /* Buttons */
    .btn {
      padding: 10px 20px;
      border: none;
      border-radius: var(--radius);
      cursor: pointer;
      font-size: 14px;
      font-weight: 500;
      transition: all 0.2s;
    }
    
    .btn-primary { background: var(--primary); color: white; }
    .btn-primary:hover { background: var(--primary-hover); }
    .btn-danger { background: var(--danger); color: white; }
    .btn-danger:hover { background: var(--danger-hover); }
    .btn-secondary { background: var(--bg-input); color: var(--text); }
    .btn-secondary:hover { background: var(--border); }
    .btn-full { width: 100%; }
    .btn:disabled { opacity: 0.5; cursor: not-allowed; }
    
    /* Header */
    .header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 30px;
      padding-bottom: 20px;
      border-bottom: 1px solid var(--border);
    }
    
    .header h1 { font-size: 24px; }
    
    /* Stats Section */
    .stats-section {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 20px;
      margin-bottom: 30px;
    }
    
    .stats-group {
      background: var(--bg-card);
      border-radius: var(--radius);
      padding: 20px;
    }
    
    .stats-group-title {
      font-size: 14px;
      color: var(--text-muted);
      margin-bottom: 16px;
      padding-bottom: 12px;
      border-bottom: 1px solid var(--border);
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(2, 1fr);
      gap: 16px;
    }
    
    .stat-card {
      padding: 12px;
      background: var(--bg-input);
      border-radius: var(--radius);
    }
    
    .stat-card .label { color: var(--text-muted); font-size: 12px; margin-bottom: 4px; }
    .stat-card .value { font-size: 24px; font-weight: 600; }
    .stat-card .value.success { color: var(--success); }
    .stat-card .value.warning { color: var(--warning); }
    .stat-card .value.danger { color: var(--danger); }
    
    /* Donut Chart for Key Stats */
    .donut-chart-container {
      display: flex;
      flex-direction: column;
      align-items: center;
    }
    
    .donut-chart {
      position: relative;
      width: 160px;
      height: 160px;
    }
    
    .donut-chart svg {
      width: 100%;
      height: 100%;
      transform: rotate(-90deg);
    }
    
    .donut-chart circle {
      fill: none;
      stroke-width: 20;
    }
    
    .donut-bg { stroke: var(--bg-input); }
    .donut-active { stroke: var(--success); }
    .donut-exhausted { stroke: var(--warning); }
    .donut-invalid { stroke: var(--danger); }
    
    .donut-center {
      position: absolute;
      top: 50%;
      left: 50%;
      transform: translate(-50%, -50%);
      text-align: center;
    }
    
    .donut-center .total-value { font-size: 32px; font-weight: 700; }
    .donut-center .total-label { font-size: 12px; color: var(--text-muted); }
    
    .donut-legend {
      display: flex;
      justify-content: center;
      gap: 16px;
      margin-top: 16px;
      flex-wrap: wrap;
    }
    
    .legend-item {
      display: flex;
      align-items: center;
      gap: 6px;
      font-size: 13px;
    }
    
    .legend-dot {
      width: 10px;
      height: 10px;
      border-radius: 50%;
    }
    
    .legend-dot.active { background: var(--success); }
    .legend-dot.exhausted { background: var(--warning); }
    .legend-dot.invalid { background: var(--danger); }
    
    /* Validation Progress */
    .validation-progress {
      background: var(--bg-input);
      border-radius: var(--radius);
      padding: 16px;
      margin-bottom: 16px;
    }
    
    .progress-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 10px;
    }
    
    .progress-title { font-weight: 500; }
    .progress-count { color: var(--text-muted); font-size: 14px; }
    
    .progress-bar-container {
      height: 8px;
      background: var(--border);
      border-radius: 4px;
      overflow: hidden;
    }
    
    .progress-bar {
      height: 100%;
      background: var(--primary);
      border-radius: 4px;
      transition: width 0.3s ease;
    }
    
    .progress-details {
      margin-top: 10px;
      font-size: 13px;
      color: var(--text-muted);
    }
    
    .progress-details .valid { color: var(--success); }
    .progress-details .exhausted { color: var(--warning); }
    .progress-details .invalid { color: var(--danger); }
    
    .legend-value { font-weight: 600; }
    
    /* Request Stats - larger display */
    .request-stats {
      display: flex;
      gap: 20px;
    }
    
    .request-stat {
      flex: 1;
      text-align: center;
      padding: 16px;
      background: var(--bg-input);
      border-radius: var(--radius);
    }
    
    .request-stat .value { font-size: 32px; font-weight: 700; }
    .request-stat .label { font-size: 13px; color: var(--text-muted); margin-top: 4px; }
    .request-stat .rate { font-size: 12px; color: var(--text-muted); margin-top: 8px; }
    
    @media (max-width: 768px) {
      .stats-section { grid-template-columns: 1fr; }
      .request-stats { flex-direction: column; }
      .donut-legend { gap: 12px; }
    }
    
    /* Sections */
    .section {
      background: var(--bg-card);
      border-radius: var(--radius);
      padding: 20px;
      margin-bottom: 20px;
    }
    
    .section-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 16px;
    }
    
    .section-header h2 { font-size: 18px; }
    
    .section-actions { display: flex; gap: 10px; }
    
    /* Tables */
    .table-container { overflow-x: auto; }
    
    table { width: 100%; border-collapse: collapse; table-layout: fixed; }
    
    th, td {
      padding: 12px;
      text-align: left;
      border-bottom: 1px solid var(--border);
    }
    
    th { color: var(--text-muted); font-weight: 500; font-size: 13px; text-transform: uppercase; }
    
    /* Column widths for keys table */
    th:nth-child(1), td:nth-child(1) { width: 40px; }
    th:nth-child(2), td:nth-child(2) { width: 300px; }
    th:nth-child(3), td:nth-child(3) { width: 80px; }
    th:nth-child(4), td:nth-child(4) { width: 80px; }
    th:nth-child(5), td:nth-child(5) { width: 150px; }
    th:nth-child(6), td:nth-child(6) { width: 150px; }
    
    tr:hover { background: rgba(255, 255, 255, 0.02); }
    
    .status-badge {
      display: inline-block;
      padding: 4px 10px;
      border-radius: 20px;
      font-size: 12px;
      font-weight: 500;
    }
    
    .status-active { background: rgba(34, 197, 94, 0.2); color: var(--success); }
    .status-exhausted { background: rgba(245, 158, 11, 0.2); color: var(--warning); }
    .status-invalid { background: rgba(239, 68, 68, 0.2); color: var(--danger); }
    
    /* Key display with eye toggle */
    .key-display {
      display: flex;
      align-items: center;
      gap: 8px;
      min-width: 280px;
    }
    
    .key-display .key-text {
      font-family: monospace;
      font-size: 12px;
      word-break: break-all;
    }
    
    .key-toggle {
      cursor: pointer;
      color: var(--text-muted);
      padding: 2px;
      transition: color 0.2s;
      user-select: none;
      display: inline-flex;
      align-items: center;
      width: 18px;
      height: 18px;
    }
    
    .key-toggle:hover { color: var(--text); }
    .key-toggle svg { width: 16px; height: 16px; }
    
    .key-toggle-all {
      cursor: pointer;
      margin-right: 4px;
      user-select: none;
      display: inline-flex;
      align-items: center;
      vertical-align: middle;
      width: 18px;
      height: 18px;
    }
    
    .key-toggle-all svg { width: 16px; height: 16px; }
    
    /* Checkbox */
    input[type="checkbox"] { width: auto; margin-right: 8px; }
    
    /* Loading & Error */
    .loading { text-align: center; padding: 40px; color: var(--text-muted); }
    .error { background: rgba(239, 68, 68, 0.1); color: var(--danger); padding: 12px; border-radius: var(--radius); margin-bottom: 16px; }
    .success-msg { background: rgba(34, 197, 94, 0.1); color: var(--success); padding: 12px; border-radius: var(--radius); margin-bottom: 16px; }
    
    /* Modal */
    .modal-overlay {
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background: rgba(0, 0, 0, 0.7);
      display: flex;
      align-items: center;
      justify-content: center;
      z-index: 1000;
    }
    
    .modal {
      background: var(--bg-card);
      padding: 24px;
      border-radius: var(--radius);
      width: 100%;
      max-width: 500px;
      max-height: 90vh;
      overflow-y: auto;
    }
    
    .modal h3 { margin-bottom: 16px; }
    .modal-actions { display: flex; gap: 10px; justify-content: flex-end; margin-top: 20px; }
    
    .hidden { display: none !important; }
    
    /* Filter Select */
    .filter-select {
      padding: 8px 12px;
      background: var(--bg-input);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      color: var(--text);
      font-size: 14px;
      cursor: pointer;
    }
    
    .filter-select:focus {
      outline: none;
      border-color: var(--primary);
    }
    
    /* Responsive */
    @media (max-width: 768px) {
      .section-header { flex-direction: column; gap: 10px; align-items: flex-start; }
      .section-actions { width: 100%; flex-wrap: wrap; }
      .section-actions .btn { flex: 1; }
      .filter-select { width: 100%; }
    }
  </style>
</head>
<body>
  <!-- Login View -->
  <div id="loginView" class="login-container">
    <div class="login-box">
      <h1>🔑 Exa 密钥负载均衡器</h1>
      <div id="loginError" class="error hidden"></div>
      <form id="loginForm">
        <div class="form-group">
          <label for="adminKey">管理员密钥</label>
          <input type="password" id="adminKey" placeholder="请输入管理员密钥" required>
        </div>
        <button type="submit" class="btn btn-primary btn-full">登录</button>
      </form>
    </div>
  </div>

  <!-- Dashboard View -->
  <div id="dashboardView" class="container hidden">
    <div class="header">
      <h1>🔑 Exa 密钥负载均衡器</h1>
      <button id="logoutBtn" class="btn btn-secondary">退出登录</button>
    </div>

    <!-- Stats -->
    <div class="stats-section">
      <!-- Key Stats Group -->
      <div class="stats-group">
        <div class="stats-group-title">🔑 密钥状态</div>
        <div class="donut-chart-container">
          <div class="donut-chart">
            <svg viewBox="0 0 100 100">
              <circle class="donut-bg" cx="50" cy="50" r="40" stroke-dasharray="251.2" stroke-dashoffset="0"></circle>
              <circle id="donutInvalid" class="donut-invalid" cx="50" cy="50" r="40" stroke-dasharray="0 251.2" stroke-dashoffset="0"></circle>
              <circle id="donutExhausted" class="donut-exhausted" cx="50" cy="50" r="40" stroke-dasharray="0 251.2" stroke-dashoffset="0"></circle>
              <circle id="donutActive" class="donut-active" cx="50" cy="50" r="40" stroke-dasharray="0 251.2" stroke-dashoffset="0"></circle>
            </svg>
            <div class="donut-center">
              <div class="total-value" id="statTotal">-</div>
              <div class="total-label">总密钥</div>
            </div>
          </div>
          <div class="donut-legend">
            <div class="legend-item">
              <span class="legend-dot active"></span>
              <span>有效</span>
              <span class="legend-value" id="statActive">-</span>
            </div>
            <div class="legend-item">
              <span class="legend-dot exhausted"></span>
              <span>耗尽</span>
              <span class="legend-value" id="statExhausted">-</span>
            </div>
            <div class="legend-item">
              <span class="legend-dot invalid"></span>
              <span>无效</span>
              <span class="legend-value" id="statInvalid">-</span>
            </div>
          </div>
        </div>
      </div>
      
      <!-- Request Stats Group -->
      <div class="stats-group">
        <div class="stats-group-title">📊 请求统计</div>
        <div class="request-stats">
          <div class="request-stat">
            <div class="value success" id="statSuccess">-</div>
            <div class="label">成功请求</div>
            <div class="rate" id="statSuccessRate">-</div>
          </div>
          <div class="request-stat">
            <div class="value danger" id="statFailure">-</div>
            <div class="label">失败请求</div>
            <div class="rate" id="statTotalRequests">-</div>
          </div>
        </div>
      </div>
    </div>

    <!-- Exa Keys Section -->
    <div class="section">
      <div class="section-header">
        <h2>Exa API 密钥
          <select id="keyStatusFilter" class="filter-select" style="margin-left: 12px; vertical-align: middle;">
            <option value="all">全部密钥</option>
            <option value="active">活跃</option>
            <option value="exhausted">已耗尽</option>
            <option value="invalid">无效</option>
          </select>
        </h2>
        <div class="section-actions">
          <button id="validateKeysBtn" class="btn btn-secondary">🔍 检测活跃密钥</button>
          <button id="cleanupKeysBtn" class="btn btn-secondary">🧹 清理无效密钥</button>
          <button id="addKeysBtn" class="btn btn-primary">+ 添加密钥</button>
          <button id="deleteSelectedBtn" class="btn btn-danger" disabled>删除所选</button>
        </div>
      </div>
      <!-- Validation Progress -->
      <div id="validationProgress" class="validation-progress hidden">
        <div class="progress-header">
          <span class="progress-title">正在检测密钥有效性...</span>
          <span class="progress-count" id="progressCount">0/0</span>
        </div>
        <div class="progress-bar-container">
          <div class="progress-bar" id="progressBar" style="width: 0%"></div>
        </div>
        <div class="progress-details" id="progressDetails"></div>
      </div>
      <div id="keysMessage"></div>
      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th><input type="checkbox" id="selectAllKeys"></th>
              <th><span class="key-toggle-all" id="toggleAllKeys" onclick="toggleAllKeysVisibility()"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg></span> 密钥</th>
              <th>状态</th>
              <th>成功次数</th>
              <th>最后使用</th>
              <th>创建时间</th>
            </tr>
          </thead>
          <tbody id="keysTableBody">
            <tr><td colspan="7" class="loading">加载中...</td></tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- Allowed Keys Section -->
    <div class="section">
      <div class="section-header">
        <h2>Exa Pool 请求密钥</h2>
        <div class="section-actions">
          <button id="addAllowedKeyBtn" class="btn btn-primary">+ 添加密钥</button>
          <button id="deleteSelectedAllowedBtn" class="btn btn-danger" disabled>删除所选</button>
        </div>
      </div>
      <div id="allowedKeysMessage"></div>
      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th><input type="checkbox" id="selectAllAllowedKeys"></th>
              <th><span class="key-toggle-all" id="toggleAllAllowedKeys" onclick="toggleAllAllowedKeysVisibility()"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg></span> 密钥</th>
              <th>名称</th>
              <th>创建时间</th>
            </tr>
          </thead>
          <tbody id="allowedKeysTableBody">
            <tr><td colspan="4" class="loading">加载中...</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- Add Keys Modal -->
  <div id="addKeysModal" class="modal-overlay hidden">
    <div class="modal">
      <h3>添加 Exa 密钥</h3>
      <div id="addKeysError" class="error hidden"></div>
      <form id="addKeysForm">
        <div class="form-group">
          <label>输入密钥（每行一个）</label>
          <textarea id="keysInput" rows="8" placeholder="密钥1&#10;密钥2&#10;密钥3"></textarea>
        </div>
        <div class="modal-actions">
          <button type="button" class="btn btn-secondary" onclick="closeModal('addKeysModal')">取消</button>
          <button type="submit" class="btn btn-primary">添加密钥</button>
        </div>
      </form>
    </div>
  </div>

  <!-- Add Allowed Key Modal -->
  <div id="addAllowedKeyModal" class="modal-overlay hidden">
    <div class="modal">
      <h3>添加允许的密钥</h3>
      <div id="addAllowedKeyError" class="error hidden"></div>
      <form id="addAllowedKeyForm">
        <div class="form-group">
          <label for="allowedKeyInput">API 密钥</label>
          <input type="text" id="allowedKeyInput" placeholder="请输入 API 密钥" required>
        </div>
        <div class="form-group">
          <label for="allowedKeyName">名称（可选）</label>
          <input type="text" id="allowedKeyName" placeholder="密钥名称">
        </div>
        <div class="modal-actions">
          <button type="button" class="btn btn-secondary" onclick="closeModal('addAllowedKeyModal')">取消</button>
          <button type="submit" class="btn btn-primary">添加密钥</button>
        </div>
      </form>
    </div>
  </div>

  <script>
    // Format time to UTC+8 (China timezone)
    function formatTime(dateStr) {
      if (!dateStr) return '-';
      const date = new Date(dateStr + 'Z'); // Treat as UTC
      return date.toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' });
    }
    
    // SVG icons for eye toggle
    const eyeOpenSvg = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>';
    const eyeClosedSvg = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>';
    
    // Toggle key visibility (show/hide full key)
    function toggleKeyVisibility(el) {
      const keyText = el.nextElementSibling;
      const isHidden = el.dataset.hidden !== 'false';
      if (isHidden) {
        keyText.textContent = el.dataset.key;
        el.innerHTML = eyeClosedSvg;
        el.dataset.hidden = 'false';
      } else {
        keyText.textContent = el.dataset.masked;
        el.innerHTML = eyeOpenSvg;
        el.dataset.hidden = 'true';
      }
    }
    
    // Toggle all keys visibility
    function toggleAllKeysVisibility() {
      const toggleAllBtn = document.getElementById('toggleAllKeys');
      const allToggles = document.querySelectorAll('#keysTableBody .key-toggle');
      const isShowingAll = toggleAllBtn.dataset.showing === 'true';
      
      allToggles.forEach(el => {
        const keyText = el.nextElementSibling;
        if (isShowingAll) {
          keyText.textContent = el.dataset.masked;
          el.innerHTML = eyeOpenSvg;
          el.dataset.hidden = 'true';
        } else {
          keyText.textContent = el.dataset.key;
          el.innerHTML = eyeClosedSvg;
          el.dataset.hidden = 'false';
        }
      });
      
      toggleAllBtn.innerHTML = isShowingAll ? eyeOpenSvg : eyeClosedSvg;
      toggleAllBtn.dataset.showing = isShowingAll ? 'false' : 'true';
    }
    
    // Toggle all allowed keys visibility
    function toggleAllAllowedKeysVisibility() {
      const toggleAllBtn = document.getElementById('toggleAllAllowedKeys');
      const allToggles = document.querySelectorAll('#allowedKeysTableBody .key-toggle');
      const isShowingAll = toggleAllBtn.dataset.showing === 'true';
      
      allToggles.forEach(el => {
        const keyText = el.nextElementSibling;
        if (isShowingAll) {
          keyText.textContent = el.dataset.masked;
          el.innerHTML = eyeOpenSvg;
          el.dataset.hidden = 'true';
        } else {
          keyText.textContent = el.dataset.key;
          el.innerHTML = eyeClosedSvg;
          el.dataset.hidden = 'false';
        }
      });
      
      toggleAllBtn.innerHTML = isShowingAll ? eyeOpenSvg : eyeClosedSvg;
      toggleAllBtn.dataset.showing = isShowingAll ? 'false' : 'true';
    }
    
    // State
    let sessionToken = localStorage.getItem('sessionToken');
    let selectedKeyIds = new Set();
    let selectedAllowedKeyIds = new Set();

    // API Helper
    async function api(endpoint, options = {}) {
      const headers = { 'Content-Type': 'application/json', ...options.headers };
      if (sessionToken) headers['Authorization'] = 'Bearer ' + sessionToken;
      
      const response = await fetch(endpoint, { ...options, headers });
      const data = await response.json();
      
      if (response.status === 401 && endpoint !== '/api/admin/login') {
        logout();
        throw new Error('Session expired');
      }
      
      return { ok: response.ok, status: response.status, data };
    }

    // Auth
    async function login(adminKey) {
      const { ok, data } = await api('/api/admin/login', {
        method: 'POST',
        body: JSON.stringify({ adminKey })
      });
      
      if (ok && data.token) {
        sessionToken = data.token;
        localStorage.setItem('sessionToken', sessionToken);
        showDashboard();
      } else {
        throw new Error(data.message || 'Login failed');
      }
    }

    function logout() {
      sessionToken = null;
      localStorage.removeItem('sessionToken');
      showLogin();
    }

    // Views
    function showLogin() {
      document.getElementById('loginView').classList.remove('hidden');
      document.getElementById('dashboardView').classList.add('hidden');
    }

    function showDashboard() {
      document.getElementById('loginView').classList.add('hidden');
      document.getElementById('dashboardView').classList.remove('hidden');
      loadStats();
      loadKeys();
      loadAllowedKeys();
    }

    // Data Loading
    async function loadStats() {
      try {
        const { ok, data } = await api('/api/admin/stats');
        if (ok) {
          document.getElementById('statTotal').textContent = data.totalKeys;
          document.getElementById('statActive').textContent = data.activeKeys;
          document.getElementById('statExhausted').textContent = data.exhaustedKeys;
          document.getElementById('statInvalid').textContent = data.invalidKeys;
          document.getElementById('statSuccess').textContent = data.totalSuccess;
          document.getElementById('statFailure').textContent = data.totalFailure;
          
          // Calculate and display rates
          const total = data.totalSuccess + data.totalFailure;
          const successRate = total > 0 ? ((data.totalSuccess / total) * 100).toFixed(1) : 0;
          document.getElementById('statSuccessRate').textContent = \`成功率 \${successRate}%\`;
          document.getElementById('statTotalRequests').textContent = \`共 \${total} 次请求\`;
          
          // Update donut chart
          updateDonutChart(data.activeKeys, data.exhaustedKeys, data.invalidKeys);
        }
      } catch (e) { console.error('Failed to load stats:', e); }
    }
    
    // Update donut chart with key stats
    function updateDonutChart(active, exhausted, invalid) {
      const total = active + exhausted + invalid;
      const circumference = 2 * Math.PI * 40; // r=40
      
      if (total === 0) {
        // No keys, show empty state
        document.getElementById('donutActive').setAttribute('stroke-dasharray', '0 ' + circumference);
        document.getElementById('donutExhausted').setAttribute('stroke-dasharray', '0 ' + circumference);
        document.getElementById('donutInvalid').setAttribute('stroke-dasharray', '0 ' + circumference);
        return;
      }
      
      // Calculate percentages
      const activePercent = active / total;
      const exhaustedPercent = exhausted / total;
      const invalidPercent = invalid / total;
      
      // Calculate stroke-dasharray values
      const activeLength = activePercent * circumference;
      const exhaustedLength = exhaustedPercent * circumference;
      const invalidLength = invalidPercent * circumference;
      
      // Calculate offsets (segments stack on top of each other)
      const activeOffset = 0;
      const exhaustedOffset = -activeLength;
      const invalidOffset = -(activeLength + exhaustedLength);
      
      // Apply to SVG circles
      document.getElementById('donutActive').setAttribute('stroke-dasharray', activeLength + ' ' + circumference);
      document.getElementById('donutActive').setAttribute('stroke-dashoffset', activeOffset);
      
      document.getElementById('donutExhausted').setAttribute('stroke-dasharray', exhaustedLength + ' ' + circumference);
      document.getElementById('donutExhausted').setAttribute('stroke-dashoffset', exhaustedOffset);
      
      document.getElementById('donutInvalid').setAttribute('stroke-dasharray', invalidLength + ' ' + circumference);
      document.getElementById('donutInvalid').setAttribute('stroke-dashoffset', invalidOffset);
    }

    async function loadKeys() {
      const tbody = document.getElementById('keysTableBody');
      const filter = document.getElementById('keyStatusFilter').value;
      try {
        const { ok, data } = await api('/api/admin/keys');
        if (ok && data.keys) {
          // 根据筛选条件过滤密钥
          let filteredKeys = data.keys;
          if (filter !== 'all') {
            filteredKeys = data.keys.filter(key => key.status === filter);
          }
          
          if (filteredKeys.length === 0) {
            const filterText = filter === 'all' ? '暂无密钥' : '没有符合条件的密钥';
            tbody.innerHTML = '<tr><td colspan="7" class="loading">' + filterText + '</td></tr>';
          } else {
            const statusMap = { active: '活跃', exhausted: '已耗尽', invalid: '无效' };
            tbody.innerHTML = filteredKeys.map(key => \`
              <tr>
                <td><input type="checkbox" class="key-checkbox" data-id="\${key.id}"></td>
                <td>
                  <div class="key-display">
                    <span class="key-toggle" onclick="toggleKeyVisibility(this)" data-key="\${key.key}" data-masked="\${key.maskedKey}"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg></span>
                    <code class="key-text">\${key.maskedKey}</code>
                  </div>
                </td>
                <td><span class="status-badge status-\${key.status}">\${statusMap[key.status] || key.status}</span></td>
                <td>\${key.successCount}</td>
                <td>\${formatTime(key.lastUsed)}</td>
                <td>\${formatTime(key.createdAt)}</td>
              </tr>
            \`).join('');
          }
          updateDeleteButton();
        }
      } catch (e) {
        tbody.innerHTML = '<tr><td colspan="7" class="error">加载密钥失败</td></tr>';
      }
    }

    async function loadAllowedKeys() {
      const tbody = document.getElementById('allowedKeysTableBody');
      selectedAllowedKeyIds.clear();
      updateAllowedDeleteButton();
      try {
        const { ok, data } = await api('/api/admin/allowed-keys');
        if (ok && data.allowedKeys) {
          if (data.allowedKeys.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" class="loading">暂无允许的密钥</td></tr>';
          } else {
            tbody.innerHTML = data.allowedKeys.map(key => \`
              <tr>
                <td><input type="checkbox" class="allowed-key-checkbox" data-id="\${key.id}"></td>
                <td>
                  <div class="key-display">
                    <span class="key-toggle allowed-key-toggle" onclick="toggleKeyVisibility(this)" data-key="\${key.key}" data-masked="\${key.maskedKey}" data-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg></span>
                    <code class="key-text">\${key.maskedKey}</code>
                  </div>
                </td>
                <td>\${key.name || '-'}</td>
                <td>\${formatTime(key.createdAt)}</td>
              </tr>
            \`).join('');
          }
        }
      } catch (e) {
        tbody.innerHTML = '<tr><td colspan="4" class="error">加载允许的密钥失败</td></tr>';
      }
    }

    // Actions
    async function addKeys(keysText) {
      const { ok, data } = await api('/api/admin/keys', {
        method: 'POST',
        body: JSON.stringify({ keys: keysText })
      });
      
      if (ok) {
        let msg = \`已添加: \${data.added}\`;
        if (data.skipped?.length) msg += \`，跳过（重复）: \${data.skipped.length}\`;
        if (data.invalid?.length) msg += \`，无效: \${data.invalid.length}\`;
        showMessage('keysMessage', msg, 'success');
        loadStats();
        loadKeys();
        closeModal('addKeysModal');
      } else {
        throw new Error(data.message || '添加密钥失败');
      }
    }

    async function deleteSelectedKeys() {
      if (selectedKeyIds.size === 0) return;
      if (!confirm(\`确定删除 \${selectedKeyIds.size} 个密钥吗？\`)) return;
      
      const { ok, data } = await api('/api/admin/keys', {
        method: 'DELETE',
        body: JSON.stringify({ keyIds: Array.from(selectedKeyIds) })
      });
      
      if (ok) {
        showMessage('keysMessage', \`已删除 \${data.deleted} 个密钥\`, 'success');
        selectedKeyIds.clear();
        loadStats();
        loadKeys();
      } else {
        showMessage('keysMessage', data.message || '删除密钥失败', 'error');
      }
    }

    async function cleanupInvalidKeys() {
      if (!confirm('确定清理所有已耗尽和无效的密钥吗？')) return;
      
      const btn = document.getElementById('cleanupKeysBtn');
      btn.disabled = true;
      btn.textContent = '🧹 清理中...';
      
      try {
        const { ok, data } = await api('/api/admin/keys/cleanup', {
          method: 'POST'
        });
        
        if (ok) {
          if (data.deleted > 0) {
            showMessage('keysMessage', \`已清理 \${data.deleted} 个密钥（耗尽: \${data.exhausted}, 无效: \${data.invalid}）\`, 'success');
          } else {
            showMessage('keysMessage', '没有需要清理的密钥', 'success');
          }
          loadStats();
          loadKeys();
        } else {
          showMessage('keysMessage', data.message || '清理密钥失败', 'error');
        }
      } finally {
        btn.disabled = false;
        btn.textContent = '🧹 清理无效密钥';
      }
    }

    async function addAllowedKey(key, name) {
      const { ok, data } = await api('/api/admin/allowed-keys', {
        method: 'POST',
        body: JSON.stringify({ key, name })
      });
      
      if (ok) {
        showMessage('allowedKeysMessage', '密钥添加成功', 'success');
        loadAllowedKeys();
        loadStats();
        closeModal('addAllowedKeyModal');
      } else {
        throw new Error(data.message || '添加密钥失败');
      }
    }

    async function deleteAllowedKey(id) {
      if (!confirm('确定删除这个密钥吗？')) return;
      
      const { ok, data } = await api('/api/admin/allowed-keys', {
        method: 'DELETE',
        body: JSON.stringify({ id })
      });
      
      if (ok) {
        showMessage('allowedKeysMessage', '密钥已删除', 'success');
        loadAllowedKeys();
        loadStats();
      } else {
        showMessage('allowedKeysMessage', data.message || '删除失败', 'error');
      }
    }

    async function deleteSelectedAllowedKeys() {
      if (selectedAllowedKeyIds.size === 0) return;
      if (!confirm(\`确定删除 \${selectedAllowedKeyIds.size} 个密钥吗？\`)) return;
      
      const { ok, data } = await api('/api/admin/allowed-keys', {
        method: 'DELETE',
        body: JSON.stringify({ keyIds: Array.from(selectedAllowedKeyIds) })
      });
      
      if (ok) {
        showMessage('allowedKeysMessage', \`已删除 \${data.deleted} 个密钥\`, 'success');
        selectedAllowedKeyIds.clear();
        loadAllowedKeys();
        loadStats();
      } else {
        showMessage('allowedKeysMessage', data.message || '删除密钥失败', 'error');
      }
    }

    // UI Helpers
    function showMessage(elementId, message, type) {
      const el = document.getElementById(elementId);
      el.className = type === 'success' ? 'success-msg' : 'error';
      el.textContent = message;
      el.classList.remove('hidden');
      setTimeout(() => el.classList.add('hidden'), 5000);
    }

    function closeModal(modalId) {
      document.getElementById(modalId).classList.add('hidden');
    }

    function updateDeleteButton() {
      const btn = document.getElementById('deleteSelectedBtn');
      btn.disabled = selectedKeyIds.size === 0;
      btn.textContent = selectedKeyIds.size > 0 ? \`删除所选 (\${selectedKeyIds.size})\` : '删除所选';
    }

    function updateAllowedDeleteButton() {
      const btn = document.getElementById('deleteSelectedAllowedBtn');
      btn.disabled = selectedAllowedKeyIds.size === 0;
      btn.textContent = selectedAllowedKeyIds.size > 0 ? \`删除所选 (\${selectedAllowedKeyIds.size})\` : '删除所选';
    }

    // Event Listeners
    document.getElementById('loginForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const errorEl = document.getElementById('loginError');
      try {
        await login(document.getElementById('adminKey').value);
      } catch (err) {
        errorEl.textContent = err.message;
        errorEl.classList.remove('hidden');
      }
    });

    document.getElementById('logoutBtn').addEventListener('click', logout);
    document.getElementById('addKeysBtn').addEventListener('click', () => {
      document.getElementById('addKeysModal').classList.remove('hidden');
      document.getElementById('keysInput').value = '';
    });
    document.getElementById('deleteSelectedBtn').addEventListener('click', deleteSelectedKeys);
    document.getElementById('validateKeysBtn').addEventListener('click', validateAllKeys);
    document.getElementById('cleanupKeysBtn').addEventListener('click', cleanupInvalidKeys);
    document.getElementById('keyStatusFilter').addEventListener('change', () => {
      selectedKeyIds.clear();
      loadKeys();
    });
    document.getElementById('addAllowedKeyBtn').addEventListener('click', () => {
      document.getElementById('addAllowedKeyModal').classList.remove('hidden');
      document.getElementById('allowedKeyInput').value = '';
      document.getElementById('allowedKeyName').value = '';
    });

    document.getElementById('addKeysForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const errorEl = document.getElementById('addKeysError');
      try {
        await addKeys(document.getElementById('keysInput').value);
      } catch (err) {
        errorEl.textContent = err.message;
        errorEl.classList.remove('hidden');
      }
    });

    document.getElementById('addAllowedKeyForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const errorEl = document.getElementById('addAllowedKeyError');
      try {
        await addAllowedKey(
          document.getElementById('allowedKeyInput').value,
          document.getElementById('allowedKeyName').value
        );
      } catch (err) {
        errorEl.textContent = err.message;
        errorEl.classList.remove('hidden');
      }
    });

    document.getElementById('selectAllKeys').addEventListener('change', (e) => {
      document.querySelectorAll('.key-checkbox').forEach(cb => {
        cb.checked = e.target.checked;
        const id = parseInt(cb.dataset.id);
        if (e.target.checked) selectedKeyIds.add(id);
        else selectedKeyIds.delete(id);
      });
      updateDeleteButton();
    });

    document.getElementById('keysTableBody').addEventListener('change', (e) => {
      if (e.target.classList.contains('key-checkbox')) {
        const id = parseInt(e.target.dataset.id);
        if (e.target.checked) selectedKeyIds.add(id);
        else selectedKeyIds.delete(id);
        updateDeleteButton();
      }
    });

    document.getElementById('deleteSelectedAllowedBtn').addEventListener('click', deleteSelectedAllowedKeys);

    document.getElementById('selectAllAllowedKeys').addEventListener('change', (e) => {
      document.querySelectorAll('.allowed-key-checkbox').forEach(cb => {
        cb.checked = e.target.checked;
        const id = parseInt(cb.dataset.id);
        if (e.target.checked) selectedAllowedKeyIds.add(id);
        else selectedAllowedKeyIds.delete(id);
      });
      updateAllowedDeleteButton();
    });

    document.getElementById('allowedKeysTableBody').addEventListener('change', (e) => {
      if (e.target.classList.contains('allowed-key-checkbox')) {
        const id = parseInt(e.target.dataset.id);
        if (e.target.checked) selectedAllowedKeyIds.add(id);
        else selectedAllowedKeyIds.delete(id);
        updateAllowedDeleteButton();
      }
    });

    // Close modals on overlay click
    document.querySelectorAll('.modal-overlay').forEach(overlay => {
      overlay.addEventListener('click', (e) => {
        if (e.target === overlay) overlay.classList.add('hidden');
      });
    });

    // Validate all keys
    async function validateAllKeys() {
      const validateBtn = document.getElementById('validateKeysBtn');
      const progressDiv = document.getElementById('validationProgress');
      const progressBar = document.getElementById('progressBar');
      const progressCount = document.getElementById('progressCount');
      const progressDetails = document.getElementById('progressDetails');
      
      // Get all keys first
      const { ok, data } = await api('/api/admin/keys');
      if (!ok || !data.keys || data.keys.length === 0) {
        showMessage('keysMessage', '没有可检测的密钥', 'error');
        return;
      }
      
      // Filter only active keys for validation
      const keysToValidate = data.keys.filter(k => k.status === 'active');
      if (keysToValidate.length === 0) {
        showMessage('keysMessage', '没有活跃状态的密钥需要检测', 'error');
        return;
      }
      
      // Show progress UI
      validateBtn.disabled = true;
      validateBtn.textContent = '检测中...';
      progressDiv.classList.remove('hidden');
      
      let completed = 0;
      let validCount = 0;
      let exhaustedCount = 0;
      let invalidCount = 0;
      const total = keysToValidate.length;
      const invalidKeys = [];
      const exhaustedKeys = [];
      
      // Update progress display
      function updateProgress() {
        const percent = Math.round((completed / total) * 100);
        progressBar.style.width = percent + '%';
        progressCount.textContent = completed + '/' + total;
        progressDetails.innerHTML = 
          '<span class="valid">✓ 有效: ' + validCount + '</span> | ' +
          '<span class="exhausted">⚠ 耗尽: ' + exhaustedCount + '</span> | ' +
          '<span class="invalid">✗ 无效: ' + invalidCount + '</span>';
      }
      
      updateProgress();
      
      // Validate keys with concurrency limit
      const concurrency = window.APP_CONFIG?.validationConcurrency || 10;
      const queue = [...keysToValidate];
      
      async function validateKey(keyData) {
        try {
          // Use backend API to check key validity (avoids CORS issues)
          const { ok, data } = await api('/api/admin/keys/check', {
            method: 'POST',
            body: JSON.stringify({
              keyId: keyData.id,
              key: keyData.key
            })
          });
          
          if (ok && data.status) {
            if (data.status === 'valid') {
              validCount++;
            } else if (data.status === 'invalid') {
              invalidCount++;
              invalidKeys.push(keyData.id);
            } else if (data.status === 'exhausted') {
              exhaustedCount++;
              exhaustedKeys.push(keyData.id);
            } else {
              validCount++;
            }
          } else {
            // API error, treat as valid
            validCount++;
          }
        } catch (error) {
          // Network error, treat as valid (don't mark as invalid)
          validCount++;
        }
        
        completed++;
        updateProgress();
      }
      
      // Process queue with concurrency
      async function processQueue() {
        const workers = [];
        for (let i = 0; i < concurrency; i++) {
          workers.push((async () => {
            while (queue.length > 0) {
              const keyData = queue.shift();
              if (keyData) {
                await validateKey(keyData);
              }
            }
          })());
        }
        await Promise.all(workers);
      }
      
      await processQueue();
      
      // Mark invalid and exhausted keys in database
      if (invalidKeys.length > 0 || exhaustedKeys.length > 0) {
        try {
          await api('/api/admin/keys/validate', {
            method: 'POST',
            body: JSON.stringify({ 
              invalidKeyIds: invalidKeys,
              exhaustedKeyIds: exhaustedKeys
            })
          });
        } catch (e) {
          console.error('Failed to update key status:', e);
        }
      }
      
      // Show completion message
      const msg = '检测完成: ' + validCount + ' 个有效, ' + 
                  exhaustedCount + ' 个耗尽, ' + 
                  invalidCount + ' 个无效';
      showMessage('keysMessage', msg, invalidCount > 0 || exhaustedCount > 0 ? 'error' : 'success');
      
      // Reset UI
      validateBtn.disabled = false;
      validateBtn.textContent = '🔍 检测活跃密钥';
      setTimeout(() => {
        progressDiv.classList.add('hidden');
      }, 3000);
      
      // Reload data
      loadStats();
      loadKeys();
    }

    // Init
    if (sessionToken) {
      showDashboard();
    } else {
      showLogin();
    }
  </script>
</body>
</html>`;
}

/**
 * Handle admin login request
 * @param {Request} request - Incoming request
 * @param {Env} env - Environment bindings
 * @param {Object} params - Route parameters
 * @returns {Promise<Response>}
 */
async function handleAdminLogin(request, env, params) {
  try {
    const body = await request.json();
    const { adminKey } = body;

    const authResult = validateAdminKey(adminKey, env);
    
    if (!authResult.valid) {
      return jsonResponse(
        { error: 'Unauthorized', message: authResult.error },
        401
      );
    }

    // Generate JWT session token
    const sessionToken = await generateSessionToken(env);

    return jsonResponse({
      success: true,
      token: sessionToken,
      expiresIn: SESSION_EXPIRATION_MS / 1000 // seconds
    });
  } catch (error) {
    return jsonResponse(
      { error: 'Bad Request', message: 'Invalid request body' },
      400
    );
  }
}

/**
 * Handle admin logout request
 * @param {Request} request - Incoming request
 * @param {Env} env - Environment bindings
 * @param {Object} params - Route parameters
 * @returns {Promise<Response>}
 */
async function handleAdminLogout(request, env, params) {
  // JWT is stateless, just return success (client will clear localStorage)
  return jsonResponse({ success: true, message: 'Logged out successfully' });
}

/**
 * List all Exa keys with masked values
 * @param {Request} request - Incoming request
 * @param {Env} env - Environment bindings
 * @param {Object} params - Route parameters
 * @returns {Promise<Response>}
 */
async function listExaKeys(request, env, params) {
  // Require admin authentication
  const authResult = await requireAdminAuth(request, env);
  if (!authResult.valid) {
    return jsonResponse(
      { error: 'Unauthorized', message: authResult.error },
      401
    );
  }

  try {
    const result = await env.DB.prepare(
      `SELECT id, key, status, last_used, created_at, error_message, success_count 
       FROM exa_keys 
       ORDER BY created_at DESC`
    ).all();

    // Mask keys for display (show only last 4 characters)
    const keys = (result.results || []).map(row => ({
      id: row.id,
      key: row.key,
      maskedKey: maskKey(row.key),
      status: row.status,
      lastUsed: row.last_used,
      createdAt: row.created_at,
      errorMessage: row.error_message,
      successCount: row.success_count || 0
    }));

    return jsonResponse({ keys });
  } catch (error) {
    console.error('Error listing keys:', error);
    return jsonResponse(
      { error: 'Internal Server Error', message: 'Failed to list keys' },
      500
    );
  }
}

/**
 * Add multiple Exa keys from multi-line input
 * @param {Request} request - Incoming request
 * @param {Env} env - Environment bindings
 * @param {Object} params - Route parameters
 * @returns {Promise<Response>}
 */
async function addExaKeys(request, env, params) {
  // Require admin authentication
  const authResult = await requireAdminAuth(request, env);
  if (!authResult.valid) {
    return jsonResponse(
      { error: 'Unauthorized', message: authResult.error },
      401
    );
  }

  try {
    const body = await request.json();
    const { keys: keysInput } = body;

    if (!keysInput || typeof keysInput !== 'string') {
      return jsonResponse(
        { error: 'Bad Request', message: 'Keys input is required as a string' },
        400
      );
    }

    // Parse and validate keys
    const { keys, invalid } = parseKeyInput(keysInput);

    if (keys.length === 0 && invalid.length === 0) {
      return jsonResponse(
        { error: 'Bad Request', message: 'No keys provided' },
        400
      );
    }

    // Add valid keys to database
    const result = await addKeysToDatabase(env.DB, keys);

    return jsonResponse({
      success: true,
      added: result.added,
      skipped: result.skipped,
      invalid: invalid,
      errors: result.errors
    });
  } catch (error) {
    console.error('Error adding keys:', error);
    return jsonResponse(
      { error: 'Bad Request', message: 'Invalid request body' },
      400
    );
  }
}

/**
 * Check single key validity by making a minimal search request to Exa API
 * @param {Request} request - Incoming request
 * @param {Env} env - Environment bindings
 * @param {Object} params - Route parameters
 * @returns {Promise<Response>}
 */
async function checkSingleKeyValidity(request, env, params) {
  // Require admin authentication
  const authResult = await requireAdminAuth(request, env);
  if (!authResult.valid) {
    return jsonResponse(
      { error: 'Unauthorized', message: authResult.error },
      401
    );
  }

  try {
    const body = await request.json();
    const { keyId, key } = body;

    if (!key || typeof key !== 'string') {
      return jsonResponse(
        { error: 'Bad Request', message: 'key is required' },
        400
      );
    }

    // Make minimal search request to Exa API
    const response = await fetch('https://api.exa.ai/search', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': key
      },
      body: JSON.stringify({
        query: 'test',
        numResults: 1
      })
    });

    let status = 'valid';
    let errorMessage = null;

    if (response.ok) {
      status = 'valid';
    } else if (response.status === 401) {
      status = 'invalid';
      errorMessage = 'Invalid API key';
    } else if (response.status === 402) {
      status = 'exhausted';
      errorMessage = 'Insufficient balance';
    } else if (response.status === 400) {
      // Check if it's an invalid API key error
      try {
        const errorData = await response.json();
        if (errorData.error && typeof errorData.error === 'string' && 
            errorData.error.toLowerCase().includes('api-key')) {
          status = 'invalid';
          errorMessage = 'Invalid API key format';
        }
      } catch {
        // Not JSON or parse error, treat as valid
      }
    }
    // Other errors (429, 5xx) - treat as valid (temporary issues)

    return jsonResponse({
      keyId,
      status,
      errorMessage
    });
  } catch (error) {
    console.error('Error checking key validity:', error);
    return jsonResponse(
      { error: 'Internal Server Error', message: 'Failed to check key validity' },
      500
    );
  }
}

/**
 * Cleanup exhausted and invalid keys
 * @param {Request} request - Incoming request
 * @param {Env} env - Environment bindings
 * @param {Object} params - Route parameters
 * @returns {Promise<Response>}
 */
async function cleanupInvalidKeys(request, env, params) {
  // Require admin authentication
  const authResult = await requireAdminAuth(request, env);
  if (!authResult.valid) {
    return jsonResponse(
      { error: 'Unauthorized', message: authResult.error },
      401
    );
  }

  try {
    // Get count before deletion
    const countResult = await env.DB.prepare(
      `SELECT 
        SUM(CASE WHEN status = 'exhausted' THEN 1 ELSE 0 END) as exhausted,
        SUM(CASE WHEN status = 'invalid' THEN 1 ELSE 0 END) as invalid
       FROM exa_keys WHERE status IN ('exhausted', 'invalid')`
    ).first();

    const exhaustedCount = countResult?.exhausted || 0;
    const invalidCount = countResult?.invalid || 0;

    if (exhaustedCount === 0 && invalidCount === 0) {
      return jsonResponse({
        success: true,
        deleted: 0,
        exhausted: 0,
        invalid: 0,
        message: '没有需要清理的密钥'
      });
    }

    // Delete exhausted and invalid keys
    const result = await env.DB.prepare(
      `DELETE FROM exa_keys WHERE status IN ('exhausted', 'invalid')`
    ).run();

    const deleted = result.meta?.changes || 0;

    return jsonResponse({
      success: true,
      deleted,
      exhausted: exhaustedCount,
      invalid: invalidCount
    });
  } catch (error) {
    console.error('Error cleaning up keys:', error);
    return jsonResponse(
      { error: 'Internal Server Error', message: 'Failed to cleanup keys' },
      500
    );
  }
}

/**
 * Update keys validation status (mark invalid/exhausted keys)
 * @param {Request} request - Incoming request
 * @param {Env} env - Environment bindings
 * @param {Object} params - Route parameters
 * @returns {Promise<Response>}
 */
async function updateKeysValidationStatus(request, env, params) {
  // Require admin authentication
  const authResult = await requireAdminAuth(request, env);
  if (!authResult.valid) {
    return jsonResponse(
      { error: 'Unauthorized', message: authResult.error },
      401
    );
  }

  try {
    const body = await request.json();
    const { invalidKeyIds, exhaustedKeyIds } = body;
    
    let invalidUpdated = 0;
    let exhaustedUpdated = 0;

    // Mark invalid keys
    if (invalidKeyIds && Array.isArray(invalidKeyIds) && invalidKeyIds.length > 0) {
      const validIds = invalidKeyIds.filter(id => typeof id === 'number' && Number.isInteger(id) && id > 0);
      if (validIds.length > 0) {
        const placeholders = validIds.map(() => '?').join(', ');
        const result = await env.DB.prepare(
          `UPDATE exa_keys SET status = 'invalid', error_message = 'Validation failed: Invalid API key' WHERE id IN (${placeholders})`
        ).bind(...validIds).run();
        invalidUpdated = result.meta?.changes || 0;
      }
    }

    // Mark exhausted keys
    if (exhaustedKeyIds && Array.isArray(exhaustedKeyIds) && exhaustedKeyIds.length > 0) {
      const validIds = exhaustedKeyIds.filter(id => typeof id === 'number' && Number.isInteger(id) && id > 0);
      if (validIds.length > 0) {
        const placeholders = validIds.map(() => '?').join(', ');
        const result = await env.DB.prepare(
          `UPDATE exa_keys SET status = 'exhausted', error_message = 'Validation failed: Insufficient balance' WHERE id IN (${placeholders})`
        ).bind(...validIds).run();
        exhaustedUpdated = result.meta?.changes || 0;
      }
    }

    return jsonResponse({
      success: true,
      invalidUpdated,
      exhaustedUpdated
    });
  } catch (error) {
    console.error('Error updating keys validation status:', error);
    return jsonResponse(
      { error: 'Bad Request', message: 'Invalid request body' },
      400
    );
  }
}

/**
 * Delete multiple Exa keys by their IDs
 * @param {Request} request - Incoming request
 * @param {Env} env - Environment bindings
 * @param {Object} params - Route parameters
 * @returns {Promise<Response>}
 */
async function deleteExaKeys(request, env, params) {
  // Require admin authentication
  const authResult = await requireAdminAuth(request, env);
  if (!authResult.valid) {
    return jsonResponse(
      { error: 'Unauthorized', message: authResult.error },
      401
    );
  }

  try {
    const body = await request.json();
    const { keyIds } = body;

    if (!keyIds || !Array.isArray(keyIds) || keyIds.length === 0) {
      return jsonResponse(
        { error: 'Bad Request', message: 'keyIds array is required' },
        400
      );
    }

    // Validate all IDs are numbers
    const validIds = keyIds.filter(id => typeof id === 'number' && Number.isInteger(id) && id > 0);
    
    if (validIds.length === 0) {
      return jsonResponse(
        { error: 'Bad Request', message: 'No valid key IDs provided' },
        400
      );
    }

    const deleted = await deleteKeysFromDatabase(env.DB, validIds);

    return jsonResponse({
      success: true,
      deleted: deleted,
      requested: validIds.length
    });
  } catch (error) {
    console.error('Error deleting keys:', error);
    return jsonResponse(
      { error: 'Bad Request', message: 'Invalid request body' },
      400
    );
  }
}

/**
 * List all allowed API keys
 * @param {Request} request - Incoming request
 * @param {Env} env - Environment bindings
 * @param {Object} params - Route parameters
 * @returns {Promise<Response>}
 */
async function listAllowedKeys(request, env, params) {
  // Require admin authentication
  const authResult = await requireAdminAuth(request, env);
  if (!authResult.valid) {
    return jsonResponse(
      { error: 'Unauthorized', message: authResult.error },
      401
    );
  }

  try {
    const result = await env.DB.prepare(
      'SELECT id, key, name, created_at FROM allowed_keys ORDER BY created_at DESC'
    ).all();

    const keys = (result.results || []).map(row => ({
      id: row.id,
      key: row.key,
      maskedKey: maskKey(row.key),
      name: row.name,
      createdAt: row.created_at
    }));

    return jsonResponse({ allowedKeys: keys });
  } catch (error) {
    console.error('Error listing allowed keys:', error);
    return jsonResponse(
      { error: 'Internal Server Error', message: 'Failed to list allowed keys' },
      500
    );
  }
}

/**
 * Add a new allowed API key
 * @param {Request} request - Incoming request
 * @param {Env} env - Environment bindings
 * @param {Object} params - Route parameters
 * @returns {Promise<Response>}
 */
async function addAllowedKey(request, env, params) {
  // Require admin authentication
  const authResult = await requireAdminAuth(request, env);
  if (!authResult.valid) {
    return jsonResponse(
      { error: 'Unauthorized', message: authResult.error },
      401
    );
  }

  try {
    const body = await request.json();
    const { key, name } = body;

    if (!key || typeof key !== 'string' || key.trim().length === 0) {
      return jsonResponse(
        { error: 'Bad Request', message: 'Key is required' },
        400
      );
    }

    const trimmedKey = key.trim();
    const trimmedName = name ? name.trim() : null;

    try {
      await env.DB.prepare(
        'INSERT INTO allowed_keys (key, name) VALUES (?, ?)'
      ).bind(trimmedKey, trimmedName).run();

      return jsonResponse({
        success: true,
        message: 'Allowed key added successfully'
      });
    } catch (error) {
      if (error.message?.includes('UNIQUE constraint failed') ||
          error.message?.includes('SQLITE_CONSTRAINT')) {
        return jsonResponse(
          { error: 'Conflict', message: 'Key already exists' },
          409
        );
      }
      throw error;
    }
  } catch (error) {
    console.error('Error adding allowed key:', error);
    return jsonResponse(
      { error: 'Bad Request', message: 'Invalid request body' },
      400
    );
  }
}

/**
 * Delete an allowed API key
 * @param {Request} request - Incoming request
 * @param {Env} env - Environment bindings
 * @param {Object} params - Route parameters
 * @returns {Promise<Response>}
 */
async function deleteAllowedKey(request, env, params) {
  // Require admin authentication
  const authResult = await requireAdminAuth(request, env);
  if (!authResult.valid) {
    return jsonResponse(
      { error: 'Unauthorized', message: authResult.error },
      401
    );
  }

  try {
    const body = await request.json();
    const { id, keyIds } = body;

    // Support batch delete with keyIds array
    if (keyIds && Array.isArray(keyIds) && keyIds.length > 0) {
      const validIds = keyIds.filter(k => typeof k === 'number' && Number.isInteger(k) && k > 0);
      if (validIds.length === 0) {
        return jsonResponse(
          { error: 'Bad Request', message: 'No valid key IDs provided' },
          400
        );
      }

      const placeholders = validIds.map(() => '?').join(', ');
      const result = await env.DB.prepare(
        `DELETE FROM allowed_keys WHERE id IN (${placeholders})`
      ).bind(...validIds).run();

      return jsonResponse({
        success: true,
        deleted: result.meta?.changes || 0,
        message: `Deleted ${result.meta?.changes || 0} allowed key(s)`
      });
    }

    // Single delete with id
    if (!id || typeof id !== 'number' || !Number.isInteger(id) || id <= 0) {
      return jsonResponse(
        { error: 'Bad Request', message: 'Valid key ID is required' },
        400
      );
    }

    const result = await env.DB.prepare(
      'DELETE FROM allowed_keys WHERE id = ?'
    ).bind(id).run();

    if (result.meta?.changes === 0) {
      return jsonResponse(
        { error: 'Not Found', message: 'Key not found' },
        404
      );
    }

    return jsonResponse({
      success: true,
      deleted: 1,
      message: 'Allowed key deleted successfully'
    });
  } catch (error) {
    console.error('Error deleting allowed key:', error);
    return jsonResponse(
      { error: 'Bad Request', message: 'Invalid request body' },
      400
    );
  }
}

/**
 * Get system statistics
 * @param {Request} request - Incoming request
 * @param {Env} env - Environment bindings
 * @param {Object} params - Route parameters
 * @returns {Promise<Response>}
 */
async function getStats(request, env, params) {
  // Require admin authentication
  const authResult = await requireAdminAuth(request, env);
  if (!authResult.valid) {
    return jsonResponse(
      { error: 'Unauthorized', message: authResult.error },
      401
    );
  }

  try {
    // Get key counts by status
    const countResult = await env.DB.prepare(`
      SELECT 
        COUNT(*) as total,
        SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) as active,
        SUM(CASE WHEN status = 'exhausted' THEN 1 ELSE 0 END) as exhausted,
        SUM(CASE WHEN status = 'invalid' THEN 1 ELSE 0 END) as invalid
      FROM exa_keys
    `).first();

    // Get allowed keys count
    const allowedKeysResult = await env.DB.prepare(
      'SELECT COUNT(*) as count FROM allowed_keys'
    ).first();

    // Get request stats
    const requestStatsResult = await env.DB.prepare(
      'SELECT total_success, total_failure FROM request_stats WHERE id = 1'
    ).first();

    return jsonResponse({
      totalKeys: countResult?.total || 0,
      activeKeys: countResult?.active || 0,
      exhaustedKeys: countResult?.exhausted || 0,
      invalidKeys: countResult?.invalid || 0,
      allowedKeysCount: allowedKeysResult?.count || 0,
      totalSuccess: requestStatsResult?.total_success || 0,
      totalFailure: requestStatsResult?.total_failure || 0
    });
  } catch (error) {
    console.error('Error getting stats:', error);
    return jsonResponse(
      { error: 'Internal Server Error', message: 'Failed to get statistics' },
      500
    );
  }
}

/**
 * Proxy search request to Exa API
 * Supports all official Exa search parameters:
 * - query: Search query string (required)
 * - additionalQueries: Additional query variations for deep search
 * - type: Search type (neural, fast, auto, deep)
 * - category: Data category filter (company, research paper, news, pdf, github, tweet, personal site, linkedin profile, financial report)
 * - userLocation: Two-letter ISO country code
 * - numResults: Number of results (max 100)
 * - includeDomains/excludeDomains: Domain filters (max 1200)
 * - startCrawlDate/endCrawlDate: Crawl date filters (ISO 8601)
 * - startPublishedDate/endPublishedDate: Published date filters (ISO 8601)
 * - includeText/excludeText: Text content filters
 * - contents: Content retrieval options (text, highlights, summary)
 * - context: Return page contents as context string for LLM
 * - moderation: Enable content moderation
 * 
 * @param {Request} request - Incoming request
 * @param {Env} env - Environment bindings
 * @param {Object} params - Route parameters
 * @returns {Promise<Response>}
 */
async function proxySearch(request, env, params) {
  // Validate API key
  const authResult = await requireApiKeyAuth(request, env.DB);
  if (!authResult.valid) {
    return jsonResponse(
      { error: 'Unauthorized', message: authResult.error },
      401
    );
  }

  try {
    const body = await request.json();
    
    // Validate required parameter
    if (!body.query || typeof body.query !== 'string') {
      return jsonResponse(
        { error: 'Bad Request', message: 'query parameter is required' },
        400
      );
    }
    
    return await executeWithRetry(env, async (exaKey) => {
      const response = await fetch('https://api.exa.ai/search', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': exaKey
        },
        body: JSON.stringify(body)
      });

      return processExaResponse(response);
    });
  } catch (error) {
    console.error('Error proxying search:', error);
    return jsonResponse(
      { error: 'Bad Request', message: 'Invalid request body' },
      400
    );
  }
}

/**
 * Proxy contents request to Exa API
 * Supports all official Exa contents parameters:
 * - urls: Array of URLs to get contents from (required)
 * - text: Return full page text (boolean or object with maxCharacters)
 * - highlights: Text snippets options (query, numSentences, highlightsPerUrl)
 * - summary: Summary options (query)
 * - livecrawl: Livecrawl options (never, fallback, always, preferred)
 * - livecrawlTimeout: Timeout for livecrawling in ms
 * - subpages: Number of subpages to crawl
 * - subpageTarget: Term to find specific subpages
 * - extras: Extra parameters (links)
 * - context: Return contents as context string for LLM
 * 
 * @param {Request} request - Incoming request
 * @param {Env} env - Environment bindings
 * @param {Object} params - Route parameters
 * @returns {Promise<Response>}
 */
async function proxyContents(request, env, params) {
  // Validate API key
  const authResult = await requireApiKeyAuth(request, env.DB);
  if (!authResult.valid) {
    return jsonResponse(
      { error: 'Unauthorized', message: authResult.error },
      401
    );
  }

  try {
    const body = await request.json();
    
    // Validate required parameter - support both 'urls' and legacy 'ids'
    const urls = body.urls || body.ids;
    if (!urls || !Array.isArray(urls) || urls.length === 0) {
      return jsonResponse(
        { error: 'Bad Request', message: 'urls parameter is required and must be a non-empty array' },
        400
      );
    }
    
    return await executeWithRetry(env, async (exaKey) => {
      const response = await fetch('https://api.exa.ai/contents', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': exaKey
        },
        body: JSON.stringify(body)
      });

      return processExaResponse(response);
    });
  } catch (error) {
    console.error('Error proxying contents:', error);
    return jsonResponse(
      { error: 'Bad Request', message: 'Invalid request body' },
      400
    );
  }
}

/**
 * Proxy findSimilar request to Exa API
 * Find similar links to the provided URL
 * @param {Request} request - Incoming request
 * @param {Env} env - Environment bindings
 * @param {Object} params - Route parameters
 * @returns {Promise<Response>}
 */
async function proxyFindSimilar(request, env, params) {
  const authResult = await requireApiKeyAuth(request, env.DB);
  if (!authResult.valid) {
    return jsonResponse(
      { error: 'Unauthorized', message: authResult.error },
      401
    );
  }

  try {
    const body = await request.json();
    
    if (!body.url || typeof body.url !== 'string') {
      return jsonResponse(
        { error: 'Bad Request', message: 'url parameter is required' },
        400
      );
    }
    
    return await executeWithRetry(env, async (exaKey) => {
      const response = await fetch('https://api.exa.ai/findSimilar', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': exaKey
        },
        body: JSON.stringify(body)
      });

      return processExaResponse(response);
    });
  } catch (error) {
    console.error('Error proxying findSimilar:', error);
    return jsonResponse(
      { error: 'Bad Request', message: 'Invalid request body' },
      400
    );
  }
}

/**
 * Proxy answer request to Exa API
 * Get an LLM answer informed by Exa search results
 * @param {Request} request - Incoming request
 * @param {Env} env - Environment bindings
 * @param {Object} params - Route parameters
 * @returns {Promise<Response>}
 */
async function proxyAnswer(request, env, params) {
  const authResult = await requireApiKeyAuth(request, env.DB);
  if (!authResult.valid) {
    return jsonResponse(
      { error: 'Unauthorized', message: authResult.error },
      401
    );
  }

  try {
    const body = await request.json();
    
    if (!body.query || typeof body.query !== 'string') {
      return jsonResponse(
        { error: 'Bad Request', message: 'query parameter is required' },
        400
      );
    }
    
    // Handle streaming response
    if (body.stream === true) {
      return await executeAnswerStream(env, body);
    }
    
    return await executeWithRetry(env, async (exaKey) => {
      const response = await fetch('https://api.exa.ai/answer', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': exaKey
        },
        body: JSON.stringify(body)
      });

      return processExaResponse(response);
    });
  } catch (error) {
    console.error('Error proxying answer:', error);
    return jsonResponse(
      { error: 'Bad Request', message: 'Invalid request body' },
      400
    );
  }
}

// ============================================================================
// Exa Research API 代理
// ============================================================================

/**
 * 创建 Research 任务
 * @param {Request} request
 * @param {Env} env
 * @returns {Promise<Response>}
 */
async function proxyResearchCreate(request, env) {
  const authResult = await requireApiKeyAuth(request, env.DB);
  if (!authResult.valid) {
    return jsonResponse(
      { error: 'Unauthorized', message: authResult.error },
      401
    );
  }

  let body;
  try {
    body = await request.json();
  } catch (error) {
    return jsonResponse(
      { error: 'Bad Request', message: 'Invalid JSON body' },
      400
    );
  }

  if (!body || typeof body.instructions !== 'string' || body.instructions.trim().length === 0) {
    return jsonResponse(
      { error: 'Bad Request', message: 'instructions is required and must be a non-empty string' },
      400
    );
  }

  if (body.instructions.length > 4096) {
    return jsonResponse(
      { error: 'Bad Request', message: 'instructions too long (max 4096 characters)' },
      400
    );
  }

  if (body.model && !['exa-research-fast', 'exa-research', 'exa-research-pro'].includes(body.model)) {
    return jsonResponse(
      { error: 'Bad Request', message: 'model must be one of exa-research-fast|exa-research|exa-research-pro' },
      400
    );
  }

  if (body.outputSchema && typeof body.outputSchema !== 'object') {
    return jsonResponse(
      { error: 'Bad Request', message: 'outputSchema must be an object when provided' },
      400
    );
  }

  // 使用特殊的执行逻辑，需要保存 task ID 与 key 的映射
  return executeResearchCreate(env, body);
}

/**
 * 执行 Research 创建请求，并保存任务与密钥的映射
 * @param {Env} env - Environment bindings
 * @param {Object} body - Request body
 * @returns {Promise<Response>}
 */
async function executeResearchCreate(env, body) {
  const maxRetries = 3;
  let attempts = 0;
  let lastResponse = null;
  
  while (attempts < maxRetries) {
    const keyData = await getNextKey(env.DB);
    
    if (!keyData) {
      await recordFailure(env.DB);
      return jsonResponse(
        { error: 'Service Unavailable', message: 'No API keys available' },
        503
      );
    }
    
    try {
      const response = await fetch('https://api.exa.ai/research/v1', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': keyData.key
        },
        body: JSON.stringify(body)
      });
      
      const result = await processExaResponse(response);
      
      if (result.success) {
        await recordSuccess(env.DB, keyData.id);
        
        // 解析响应获取 task ID 并保存映射
        const responseBody = await result.response.text();
        try {
          const responseData = JSON.parse(responseBody);
          // Exa API 返回的字段是 researchId
          const taskId = responseData.researchId || responseData.id;
          if (taskId) {
            await saveResearchTaskMapping(env.DB, taskId, keyData.id);
          }
        } catch (e) {
          console.error('Failed to parse research response:', e);
        }
        
        return new Response(responseBody, {
          status: result.response.status,
          headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, Authorization, x-api-key'
          }
        });
      }
      
      lastResponse = result;
      
      if (result.keyExhausted) {
        await markKeyStatus(env.DB, keyData.id, 'exhausted', 'Insufficient balance');
      } else if (result.keyInvalid) {
        await markKeyStatus(env.DB, keyData.id, 'invalid', 'Invalid API key');
      }
      
      if (!result.shouldRetry) {
        await recordFailure(env.DB);
        return new Response(result.responseBody || '{"error":"Unknown error"}', {
          status: result.response.status,
          headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
          }
        });
      }
      
    } catch (error) {
      console.error('Request error:', error);
    }
    
    attempts++;
  }
  
  await recordFailure(env.DB);
  
  if (lastResponse && lastResponse.responseBody) {
    return new Response(lastResponse.responseBody, {
      status: lastResponse.response.status,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      }
    });
  }
  
  return jsonResponse(
    { error: 'Service Unavailable', message: 'All retry attempts failed' },
    503
  );
}

/**
 * 保存 Research 任务与 Exa key 的映射
 * @param {D1Database} db - D1 database instance
 * @param {string} taskId - Research task ID
 * @param {number} keyId - Exa key ID
 * @returns {Promise<void>}
 */
async function saveResearchTaskMapping(db, taskId, keyId) {
  try {
    await db.prepare(
      'INSERT OR REPLACE INTO research_tasks (id, exa_key_id) VALUES (?, ?)'
    ).bind(taskId, keyId).run();
  } catch (error) {
    console.error('Failed to save research task mapping:', error);
  }
}

/**
 * 获取 Research 任务对应的 Exa key
 * @param {D1Database} db - D1 database instance
 * @param {string} taskId - Research task ID
 * @returns {Promise<{id: number, key: string} | null>}
 */
async function getResearchTaskKey(db, taskId) {
  try {
    const result = await db.prepare(
      `SELECT ek.id, ek.key FROM research_tasks rt
       JOIN exa_keys ek ON rt.exa_key_id = ek.id
       WHERE rt.id = ?`
    ).bind(taskId).first();
    
    if (result) {
      return { id: result.id, key: result.key };
    }
  } catch (error) {
    console.error('Failed to get research task key:', error);
  }
  return null;
}

/**
 * 获取 Research 任务列表
 * 从本地数据库获取所有已记录的任务，并聚合各个 key 下的任务详情
 * @param {Request} request
 * @param {Env} env
 * @returns {Promise<Response>}
 */
async function proxyResearchList(request, env) {
  const authResult = await requireApiKeyAuth(request, env.DB);
  if (!authResult.valid) {
    return jsonResponse(
      { error: 'Unauthorized', message: authResult.error },
      401
    );
  }

  const url = new URL(request.url);
  const limit = url.searchParams.get('limit');
  let limitNum = 20; // 默认返回 20 条
  if (limit !== null) {
    const n = Number(limit);
    if (!Number.isInteger(n) || n < 1 || n > 50) {
      return jsonResponse(
        { error: 'Bad Request', message: 'limit must be an integer between 1 and 50' },
        400
      );
    }
    limitNum = n;
  }

  try {
    // 从本地数据库获取所有任务及其对应的 key
    const result = await env.DB.prepare(
      `SELECT rt.id as task_id, ek.id as key_id, ek.key as exa_key
       FROM research_tasks rt
       JOIN exa_keys ek ON rt.exa_key_id = ek.id
       ORDER BY rt.created_at DESC
       LIMIT ?`
    ).bind(limitNum).all();

    const tasks = result.results || [];
    
    if (tasks.length === 0) {
      return jsonResponse({ data: [] });
    }

    // 并发请求每个任务的详情
    const taskPromises = tasks.map(async (task) => {
      try {
        const response = await fetch(
          `https://api.exa.ai/research/v1/${encodeURIComponent(task.task_id)}`,
          {
            method: 'GET',
            headers: { 'x-api-key': task.exa_key }
          }
        );
        
        if (response.ok) {
          return await response.json();
        }
        return null;
      } catch (e) {
        console.error(`Failed to fetch task ${task.task_id}:`, e);
        return null;
      }
    });

    const taskResults = await Promise.all(taskPromises);
    const validTasks = taskResults.filter(t => t !== null);

    return jsonResponse({ data: validTasks });
  } catch (error) {
    console.error('Error listing research tasks:', error);
    return jsonResponse(
      { error: 'Internal Server Error', message: 'Failed to list research tasks' },
      500
    );
  }
}

/**
 * 获取单个 Research 任务
 * @param {Request} request
 * @param {Env} env
 * @param {Object} params
 * @returns {Promise<Response>}
 */
async function proxyResearchGet(request, env, params) {
  const authResult = await requireApiKeyAuth(request, env.DB);
  if (!authResult.valid) {
    return jsonResponse(
      { error: 'Unauthorized', message: authResult.error },
      401
    );
  }

  const researchId = params?.id;
  if (!researchId) {
    return jsonResponse(
      { error: 'Bad Request', message: 'researchId is required in path' },
      400
    );
  }

  // 查找该任务对应的 key
  const keyData = await getResearchTaskKey(env.DB, researchId);
  
  if (!keyData) {
    // 如果找不到映射，可能是旧任务或者任务不存在，尝试用轮询的 key
    return executeWithRetry(env, async (exaKey) => {
      const url = new URL(request.url);
      const queryString = url.searchParams.toString();
      const upstreamUrl = queryString
        ? `https://api.exa.ai/research/v1/${encodeURIComponent(researchId)}?${queryString}`
        : `https://api.exa.ai/research/v1/${encodeURIComponent(researchId)}`;
      
      const response = await fetch(upstreamUrl, {
        method: 'GET',
        headers: {
          'x-api-key': exaKey
        }
      });

      return processExaResponse(response);
    });
  }

  // 使用创建任务时的 key 来查询
  const url = new URL(request.url);
  const queryString = url.searchParams.toString();
  const upstreamUrl = queryString
    ? `https://api.exa.ai/research/v1/${encodeURIComponent(researchId)}?${queryString}`
    : `https://api.exa.ai/research/v1/${encodeURIComponent(researchId)}`;

  try {
    const response = await fetch(upstreamUrl, {
      method: 'GET',
      headers: {
        'x-api-key': keyData.key
      }
    });

    const result = await processExaResponse(response);
    
    if (result.success) {
      await recordSuccess(env.DB, keyData.id);
      const responseBody = await result.response.text();
      return new Response(responseBody, {
        status: result.response.status,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, Authorization, x-api-key'
        }
      });
    }
    
    // 如果 key 失效，标记状态
    if (result.keyExhausted) {
      await markKeyStatus(env.DB, keyData.id, 'exhausted', 'Insufficient balance');
    } else if (result.keyInvalid) {
      await markKeyStatus(env.DB, keyData.id, 'invalid', 'Invalid API key');
    }
    
    await recordFailure(env.DB);
    return new Response(result.responseBody || '{"error":"Unknown error"}', {
      status: result.response.status,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      }
    });
  } catch (error) {
    console.error('Error fetching research task:', error);
    await recordFailure(env.DB);
    return jsonResponse(
      { error: 'Internal Server Error', message: 'Failed to fetch research task' },
      500
    );
  }
}

/**
 * Execute answer request with streaming support
 * @param {Env} env - Environment bindings
 * @param {Object} body - Request body
 * @returns {Promise<Response>}
 */
async function executeAnswerStream(env, body) {
  const keyData = await getNextKey(env.DB);
  
  if (!keyData) {
    await recordFailure(env.DB);
    return jsonResponse(
      { error: 'Service Unavailable', message: 'No API keys available' },
      503
    );
  }
  
  try {
    const response = await fetch('https://api.exa.ai/answer', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': keyData.key
      },
      body: JSON.stringify(body)
    });
    
    if (response.ok) {
      await recordSuccess(env.DB, keyData.id);
      return new Response(response.body, {
        status: response.status,
        headers: {
          'Content-Type': 'text/event-stream',
          'Cache-Control': 'no-cache',
          'Connection': 'keep-alive',
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, Authorization, x-api-key'
        }
      });
    }
    
    if (response.status === 401) {
      await markKeyStatus(env.DB, keyData.id, 'invalid', 'Invalid API key');
    } else if (response.status === 402) {
      await markKeyStatus(env.DB, keyData.id, 'exhausted', 'Insufficient balance');
    }
    
    await recordFailure(env.DB);
    const responseBody = await response.text();
    return new Response(responseBody, {
      status: response.status,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      }
    });
  } catch (error) {
    console.error('Streaming error:', error);
    await recordFailure(env.DB);
    return jsonResponse(
      { error: 'Internal Server Error', message: 'Streaming request failed' },
      500
    );
  }
}

/**
 * Process Exa API response and determine if retry is needed
 * @param {Response} response - Exa API response
 * @returns {Promise<{success: boolean, response: Response, responseBody: string|null, shouldRetry: boolean, keyExhausted: boolean, keyInvalid: boolean}>}
 */
async function processExaResponse(response) {
  const status = response.status;
  
  // Success
  if (status >= 200 && status < 300) {
    return {
      success: true,
      response: response,
      responseBody: null,
      shouldRetry: false,
      keyExhausted: false,
      keyInvalid: false
    };
  }
  
  // Read response body for error analysis
  let responseBody = null;
  try {
    responseBody = await response.text();
  } catch (e) {
    // Ignore read errors
  }
  
  // Invalid key (401)
  if (status === 401) {
    return {
      success: false,
      response: response,
      responseBody,
      shouldRetry: true,
      keyExhausted: false,
      keyInvalid: true
    };
  }
  
  // Payment required / exhausted (402)
  if (status === 402) {
    return {
      success: false,
      response: response,
      responseBody,
      shouldRetry: true,
      keyExhausted: true,
      keyInvalid: false
    };
  }
  
  // Bad request (400) - check if it's an invalid API key error
  if (status === 400) {
    let isInvalidKey = false;
    if (responseBody) {
      try {
        const errorData = JSON.parse(responseBody);
        // Check for "x-api-key header is invalid" error message
        if (errorData.error && typeof errorData.error === 'string' && 
            errorData.error.toLowerCase().includes('api-key')) {
          isInvalidKey = true;
        }
      } catch (e) {
        // Not JSON, check raw text
        if (responseBody.toLowerCase().includes('api-key') && 
            responseBody.toLowerCase().includes('invalid')) {
          isInvalidKey = true;
        }
      }
    }
    
    if (isInvalidKey) {
      return {
        success: false,
        response: response,
        responseBody,
        shouldRetry: true,
        keyExhausted: false,
        keyInvalid: true
      };
    }
    
    // Other 400 errors - don't retry (likely bad request from client)
    return {
      success: false,
      response: response,
      responseBody,
      shouldRetry: false,
      keyExhausted: false,
      keyInvalid: false
    };
  }
  
  // Rate limited (429) - retry with different key
  if (status === 429) {
    return {
      success: false,
      response: response,
      responseBody,
      shouldRetry: true,
      keyExhausted: false,
      keyInvalid: false
    };
  }
  
  // Server errors (5xx) - retry with different key
  if (status >= 500) {
    return {
      success: false,
      response: response,
      responseBody,
      shouldRetry: true,
      keyExhausted: false,
      keyInvalid: false
    };
  }
  
  // Other client errors - don't retry
  return {
    success: false,
    response: response,
    responseBody,
    shouldRetry: false,
    keyExhausted: false,
    keyInvalid: false
  };
}

/**
 * Increment success count for a key and global stats
 * @param {D1Database} db - D1 database instance
 * @param {number} keyId - Key ID
 * @returns {Promise<void>}
 */
async function recordSuccess(db, keyId) {
  await db.prepare(
    'UPDATE exa_keys SET success_count = success_count + 1 WHERE id = ?'
  ).bind(keyId).run();
  await db.prepare(
    'UPDATE request_stats SET total_success = total_success + 1 WHERE id = 1'
  ).run();
}

/**
 * Increment failure count in global stats
 * @param {D1Database} db - D1 database instance
 * @returns {Promise<void>}
 */
async function recordFailure(db) {
  await db.prepare(
    'UPDATE request_stats SET total_failure = total_failure + 1 WHERE id = 1'
  ).run();
}

/**
 * Execute a request with retry logic and key failure handling
 * @param {Env} env - Environment bindings
 * @param {function(string): Promise<{success: boolean, response: Response, shouldRetry: boolean, keyExhausted: boolean, keyInvalid: boolean}>} requestFn - Request function
 * @param {number} maxRetries - Maximum number of retries
 * @returns {Promise<Response>}
 */
async function executeWithRetry(env, requestFn, maxRetries = 3) {
  let attempts = 0;
  let lastResponse = null;
  
  while (attempts < maxRetries) {
    const keyData = await getNextKey(env.DB);
    
    if (!keyData) {
      await recordFailure(env.DB);
      return jsonResponse(
        { error: 'Service Unavailable', message: 'No API keys available' },
        503
      );
    }
    
    try {
      const result = await requestFn(keyData.key);
      
      if (result.success) {
        // Record success
        await recordSuccess(env.DB, keyData.id);
        // Return the successful response with proper headers
        const responseBody = result.responseBody || await result.response.text();
        return new Response(responseBody, {
          status: result.response.status,
          headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, Authorization, x-api-key'
          }
        });
      }
      
      lastResponse = result;
      
      // Mark key status based on error type
      if (result.keyExhausted) {
        await markKeyStatus(env.DB, keyData.id, 'exhausted', 'Insufficient balance');
      } else if (result.keyInvalid) {
        await markKeyStatus(env.DB, keyData.id, 'invalid', 'Invalid API key');
      }
      
      // If we shouldn't retry, return the error response
      if (!result.shouldRetry) {
        await recordFailure(env.DB);
        return new Response(result.responseBody || '{"error":"Unknown error"}', {
          status: result.response.status,
          headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, Authorization, x-api-key'
          }
        });
      }
      
    } catch (error) {
      console.error('Request error:', error);
    }
    
    attempts++;
  }
  
  // All retries exhausted - record failure
  await recordFailure(env.DB);
  
  if (lastResponse && lastResponse.responseBody) {
    return new Response(lastResponse.responseBody, {
      status: lastResponse.response.status,
      headers: {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*'
      }
    });
  }
  
  return jsonResponse(
    { error: 'Service Unavailable', message: 'All retry attempts failed' },
    503
  );
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Mask an API key for display, showing only the last 4 characters
 * @param {string} key - Full API key
 * @returns {string} - Masked key (e.g., "****abcd")
 */
function maskKey(key) {
  if (!key || typeof key !== 'string') {
    return '****';
  }
  
  if (key.length <= 4) {
    return '****';
  }
  
  const visiblePart = key.slice(-4);
  const maskedLength = key.length - 4;
  return '*'.repeat(Math.min(maskedLength, 20)) + visiblePart;
}

/**
 * Create a JSON response
 * @param {Object} data - Response data
 * @param {number} status - HTTP status code
 * @returns {Response}
 */
function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization, x-api-key'
    }
  });
}

/**
 * Handle CORS preflight requests
 * @returns {Response}
 */
function handleCORS() {
  return new Response(null, {
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization, x-api-key',
      'Access-Control-Max-Age': '86400'
    }
  });
}

// ============================================================================
// Main Worker Entry Point
// ============================================================================

export default {
  /**
   * Fetch event handler
   * @param {Request} request - Incoming request
   * @param {Env} env - Environment bindings
   * @param {ExecutionContext} ctx - Execution context
   * @returns {Promise<Response>}
   */
  async fetch(request, env, ctx) {
    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
      return handleCORS();
    }

    try {
      // Initialize database on first request
      await initializeDatabase(env.DB);

      // Match route
      const matched = matchRoute(request);
      
      if (!matched) {
        return jsonResponse(
          { error: 'Not Found', message: 'Endpoint not found' },
          404
        );
      }

      // Execute handler
      return await matched.handler(request, env, matched.params);
    } catch (error) {
      console.error('Worker error:', error);
      return jsonResponse(
        { error: 'Internal Server Error', message: 'An error occurred' },
        500
      );
    }
  }
};
