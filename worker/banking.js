/**
 * Cloudflare Worker — Enable Banking proxy for MoneyHolic
 *
 * Deploy:
 *   wrangler deploy
 *
 * Add the private key secret (paste the PEM content when prompted):
 *   wrangler secret put EB_PRIVATE_KEY
 *
 * Environment variables required:
 *   EB_PRIVATE_KEY  — RSA private key PEM (from Enable Banking dashboard)
 */

const APP_ID  = 'ebb70c5d-50cf-4615-960b-727cab05d1ba';
const EB_BASE = 'https://api.enablebanking.com';

const ALLOWED_ORIGINS = [
  'https://moneyholic.pt',
  'https://imma1988.github.io',
  'http://localhost:8080',
  'http://127.0.0.1:8080',
];

function corsHeaders(origin) {
  const allowed = ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0];
  return {
    'Access-Control-Allow-Origin':  allowed,
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  };
}

function jsonResp(data, status, cors) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...cors, 'Content-Type': 'application/json' },
  });
}

// base64url-encode a string or Uint8Array
function b64url(input) {
  const bytes = typeof input === 'string'
    ? new TextEncoder().encode(input)
    : input;
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

async function makeJWT(privateKeyPem) {
  const pemBody = privateKeyPem
    .replace(/-----BEGIN PRIVATE KEY-----/g, '')
    .replace(/-----END PRIVATE KEY-----/g, '')
    .replace(/\s/g, '');

  const derBytes = Uint8Array.from(atob(pemBody), c => c.charCodeAt(0));

  const key = await crypto.subtle.importKey(
    'pkcs8',
    derBytes.buffer,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const now = Math.floor(Date.now() / 1000);
  const header  = b64url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const payload = b64url(JSON.stringify({
    iss: APP_ID,
    iat: now,
    exp: now + 3600,
    jti: crypto.randomUUID(),
  }));

  const sigInput = `${header}.${payload}`;
  const sigBytes = await crypto.subtle.sign(
    'RSASSA-PKCS1-v1_5',
    key,
    new TextEncoder().encode(sigInput)
  );

  return `${sigInput}.${b64url(new Uint8Array(sigBytes))}`;
}

async function ebFetch(privateKey, method, path, body) {
  const jwt = await makeJWT(privateKey);
  return fetch(EB_BASE + path, {
    method,
    headers: {
      'Authorization': 'Bearer ' + jwt,
      'Content-Type':  'application/json',
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin') || '';
    const cors   = corsHeaders(origin);

    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: cors });
    }

    const url  = new URL(request.url);
    const path = url.pathname;

    const privateKey = env.EB_PRIVATE_KEY;
    if (!privateKey) {
      return jsonResp({ error: 'Open Banking not configured — set EB_PRIVATE_KEY secret' }, 503, cors);
    }

    try {
      // POST /auth — initiate bank authentication, returns redirect URL
      if (path === '/auth' && request.method === 'POST') {
        const body = await request.json();
        const res  = await ebFetch(privateKey, 'POST', '/auth', body);
        return jsonResp(await res.json(), res.status, cors);
      }

      // POST /session — exchange auth code for Enable Banking session
      if (path === '/session' && request.method === 'POST') {
        const body = await request.json();
        const res  = await ebFetch(privateKey, 'POST', '/sessions', body);
        return jsonResp(await res.json(), res.status, cors);
      }

      // GET /accounts?session_id=xxx — list PSU accounts
      if (path === '/accounts' && request.method === 'GET') {
        const sid = url.searchParams.get('session_id') || '';
        const qs  = sid ? `?session_id=${encodeURIComponent(sid)}` : '';
        const res = await ebFetch(privateKey, 'GET', '/accounts' + qs);
        return jsonResp(await res.json(), res.status, cors);
      }

      // GET /transactions?account_id=xxx&date_from=YYYY-MM-DD[&date_to=YYYY-MM-DD]
      if (path === '/transactions' && request.method === 'GET') {
        const accountId = url.searchParams.get('account_id');
        const dateFrom  = url.searchParams.get('date_from');
        const dateTo    = url.searchParams.get('date_to') || new Date().toISOString().slice(0, 10);
        if (!accountId || !dateFrom) {
          return jsonResp({ error: 'Missing account_id or date_from' }, 400, cors);
        }
        const ebPath = `/accounts/${encodeURIComponent(accountId)}/transactions?date_from=${dateFrom}&date_to=${dateTo}`;
        const res    = await ebFetch(privateKey, 'GET', ebPath);
        return jsonResp(await res.json(), res.status, cors);
      }

      return jsonResp({ error: 'Not found' }, 404, cors);
    } catch (e) {
      console.error('Banking Worker error:', e);
      return jsonResp({ error: e.message }, 500, cors);
    }
  },
};
