// ===== CORS =====
const ALLOWED_ORIGINS = [
  'https://moneyholic.pt',
  'https://imma1988.github.io',
];

function corsHeaders(origin) {
  const allowed = ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0];
  return {
    'Access-Control-Allow-Origin':  allowed,
    'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  };
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin') || '';
    const url = new URL(request.url);

    // CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders(origin) });
    }

    // /admin/api — JSON API for admin actions
    if (url.pathname === '/admin/api' && request.method === 'POST') {
      return handleAdminApi(request, env, origin);
    }

    // /admin — License management page
    if (url.pathname === '/admin') {
      return handleAdmin(request, env);
    }

    // /webhook — LemonSqueezy payment notification
    if (url.pathname === '/webhook' && request.method === 'POST') {
      return handleWebhook(request, env, origin);
    }

    // /verify — Check if email is licensed
    if (url.pathname === '/verify' && request.method === 'POST') {
      return handleVerify(request, env, origin);
    }

    // ===== OPEN BANKING (Enable Banking proxy) =====

    // POST /banking/auth — initiate bank OAuth, returns redirect URL
    if (url.pathname === '/banking/auth' && request.method === 'POST') {
      return handleBankingAuth(request, env, origin);
    }

    // POST /banking/session — exchange auth code for session
    if (url.pathname === '/banking/session' && request.method === 'POST') {
      return handleBankingSession(request, env, origin);
    }

    // GET /banking/accounts?session_id=xxx
    if (url.pathname === '/banking/accounts' && request.method === 'GET') {
      return handleBankingAccounts(request, env, origin);
    }

    // GET /banking/transactions?account_id=xxx&date_from=YYYY-MM-DD[&date_to=YYYY-MM-DD]
    if (url.pathname === '/banking/transactions' && request.method === 'GET') {
      return handleBankingTransactions(request, env, origin);
    }

    // Default — Gemini proxy
    if (request.method !== 'POST') {
      return new Response('Not found', { status: 404 });
    }

    return handleGemini(request, env, origin);
  }
};

// ===== GEMINI PROXY =====
async function handleGemini(request, env, origin) {
  const body = await request.json();
  const apiKey = body.geminiApiKey || env.GEMINI_API_KEY;
  delete body.geminiApiKey;

  const geminiUrl = 'https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=' + apiKey;

  const response = await fetch(geminiUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });

  const data = await response.json();
  return new Response(JSON.stringify(data), {
    headers: { ...corsHeaders(origin), 'Content-Type': 'application/json' }
  });
}

// ===== VERIFY LICENSE =====
async function handleVerify(request, env, origin) {
  try {
    const { email } = await request.json();
    if (!email) return jsonResponse({ licensed: false }, 400, origin);
    const val = await env.LICENSES.get('license:' + email.toLowerCase());
    return jsonResponse({ licensed: val !== null }, 200, origin);
  } catch (e) {
    return jsonResponse({ licensed: false, error: e.message }, 500, origin);
  }
}

// ===== LEMON SQUEEZY WEBHOOK =====
async function handleWebhook(request, env, origin) {
  try {
    const rawBody = await request.text();

    if (env.LEMON_WEBHOOK_SECRET) {
      const signature = request.headers.get('X-Signature');
      if (!signature) return new Response('Missing signature', { status: 401 });

      const encoder = new TextEncoder();
      const keyData  = encoder.encode(env.LEMON_WEBHOOK_SECRET);
      const msgData  = encoder.encode(rawBody);
      const cryptoKey = await crypto.subtle.importKey(
        'raw', keyData, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
      );
      const signatureBuffer = await crypto.subtle.sign('HMAC', cryptoKey, msgData);
      const expectedSig = Array.from(new Uint8Array(signatureBuffer))
        .map(b => b.toString(16).padStart(2, '0')).join('');

      if (signature !== expectedSig) {
        return new Response('Invalid signature', { status: 401 });
      }
    }

    const body = JSON.parse(rawBody);
    const email =
      body?.data?.attributes?.user_email ||
      body?.meta?.custom_data?.email ||
      body?.data?.attributes?.order_email;

    if (!email) return new Response('No email found', { status: 400 });

    const eventName = body?.meta?.event_name || '';
    if (eventName === 'order_created' || eventName === 'subscription_created') {
      await env.LICENSES.put('license:' + email.toLowerCase(), JSON.stringify({
        email,
        licensed_at: new Date().toISOString(),
        source: 'lemon_squeezy'
      }));
    }
    return new Response('OK', { status: 200 });
  } catch (e) {
    return new Response('Error: ' + e.message, { status: 500 });
  }
}

// ===== ADMIN API (JSON) =====
async function handleAdminApi(request, env, origin) {
  try {
    const cookies = parseCookies(request.headers.get('Cookie') || '');
    const sessionToken = cookies['admin_session'];
    const validSession = sessionToken ? await env.LICENSES.get('session:' + sessionToken) : null;
    if (!validSession) return jsonResponse({ error: 'Unauthorized' }, 401, origin);

    const body = await request.json();
    const action = body.action || '';
    const email  = (body.email || '').toLowerCase().trim();

    if (action === 'add' && email) {
      await env.LICENSES.put('license:' + email, JSON.stringify({
        email, licensed_at: new Date().toISOString(), source: 'manual'
      }));
      return jsonResponse({ ok: true }, 200, origin);
    }
    if (action === 'remove' && email) {
      await env.LICENSES.delete('license:' + email);
      return jsonResponse({ ok: true }, 200, origin);
    }
    if (action === 'logout') {
      await env.LICENSES.delete('session:' + sessionToken);
      return jsonResponse({ ok: true }, 200, origin);
    }
    return jsonResponse({ error: 'Unknown action' }, 400, origin);
  } catch(e) {
    return jsonResponse({ error: e.message }, 500, origin);
  }
}

// ===== ADMIN PAGE =====
const SESSION_TTL = 60 * 60 * 8; // 8 hours

async function handleAdmin(request, env) {
  const url = new URL(request.url);
  const cookies = parseCookies(request.headers.get('Cookie') || '');
  const sessionToken = cookies['admin_session'];

  const validSession = sessionToken
    ? await env.LICENSES.get('session:' + sessionToken)
    : null;

  if (!validSession) {
    if (request.method === 'POST') {
      const body = await request.text();
      const params = new URLSearchParams(body);
      if (params.get('pass') === env.ADMIN_PASSWORD) {
        const token = crypto.randomUUID();
        await env.LICENSES.put('session:' + token, '1', { expirationTtl: SESSION_TTL });
        return new Response('', {
          status: 302,
          headers: {
            Location: '/admin',
            'Set-Cookie': 'admin_session=' + token + '; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=' + SESSION_TTL
          }
        });
      }
      return htmlResponse(loginPage('Password incorreta.'));
    }
    return htmlResponse(loginPage(''));
  }

  const list = await env.LICENSES.list({ prefix: 'license:' });
  const licenses = await Promise.all(
    list.keys
      .filter(k => !k.name.startsWith('session:'))
      .map(async k => {
        const val = await env.LICENSES.get(k.name);
        try { return JSON.parse(val); } catch { return { email: k.name.replace('license:', ''), source: '?' }; }
      })
  );

  return htmlResponse(adminPage(licenses));
}

// ===== OPEN BANKING (Enable Banking) =====

const EB_APP_ID = 'ebb70c5d-50cf-4615-960b-727cab05d1ba';
const EB_BASE   = 'https://api.enablebanking.com';

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
    iss: EB_APP_ID,
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

async function handleBankingAuth(request, env, origin) {
  const privateKey = env.EB_PRIVATE_KEY;
  if (!privateKey) return jsonResponse({ error: 'EB_PRIVATE_KEY secret not configured' }, 503, origin);
  try {
    const body = await request.json();
    const res  = await ebFetch(privateKey, 'POST', '/auth', body);
    return jsonResponse(await res.json(), res.status, origin);
  } catch (e) {
    return jsonResponse({ error: e.message }, 500, origin);
  }
}

async function handleBankingSession(request, env, origin) {
  const privateKey = env.EB_PRIVATE_KEY;
  if (!privateKey) return jsonResponse({ error: 'EB_PRIVATE_KEY secret not configured' }, 503, origin);
  try {
    const body = await request.json();
    const res  = await ebFetch(privateKey, 'POST', '/sessions', body);
    return jsonResponse(await res.json(), res.status, origin);
  } catch (e) {
    return jsonResponse({ error: e.message }, 500, origin);
  }
}

async function handleBankingAccounts(request, env, origin) {
  const privateKey = env.EB_PRIVATE_KEY;
  if (!privateKey) return jsonResponse({ error: 'EB_PRIVATE_KEY secret not configured' }, 503, origin);
  try {
    const url = new URL(request.url);
    const sid = url.searchParams.get('session_id') || '';
    const qs  = sid ? `?session_id=${encodeURIComponent(sid)}` : '';
    const res = await ebFetch(privateKey, 'GET', '/accounts' + qs);
    return jsonResponse(await res.json(), res.status, origin);
  } catch (e) {
    return jsonResponse({ error: e.message }, 500, origin);
  }
}

async function handleBankingTransactions(request, env, origin) {
  const privateKey = env.EB_PRIVATE_KEY;
  if (!privateKey) return jsonResponse({ error: 'EB_PRIVATE_KEY secret not configured' }, 503, origin);
  try {
    const url       = new URL(request.url);
    const accountId = url.searchParams.get('account_id');
    const dateFrom  = url.searchParams.get('date_from');
    const dateTo    = url.searchParams.get('date_to') || new Date().toISOString().slice(0, 10);
    if (!accountId || !dateFrom) return jsonResponse({ error: 'Missing account_id or date_from' }, 400, origin);
    const ebPath = `/accounts/${encodeURIComponent(accountId)}/transactions?date_from=${dateFrom}&date_to=${dateTo}`;
    const res    = await ebFetch(privateKey, 'GET', ebPath);
    return jsonResponse(await res.json(), res.status, origin);
  } catch (e) {
    return jsonResponse({ error: e.message }, 500, origin);
  }
}

// ===== HELPERS =====

function parseCookies(cookieHeader) {
  const cookies = {};
  cookieHeader.split(';').forEach(c => {
    const [k, v] = c.trim().split('=');
    if (k) cookies[k.trim()] = (v || '').trim();
  });
  return cookies;
}

function jsonResponse(data, status = 200, origin = '') {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...corsHeaders(origin), 'Content-Type': 'application/json' }
  });
}

function htmlResponse(html) {
  return new Response(html, { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
}

function loginPage(error) {
  return `<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><title>Admin</title>
<style>
  body{font-family:system-ui;background:#0d0d0d;color:#f0f0f0;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;}
  .box{background:#161616;border:1px solid #2a2a2a;border-radius:16px;padding:32px;width:320px;}
  h2{margin:0 0 24px;color:#c8f135;}
  input{width:100%;background:#1e1e1e;border:1.5px solid #2a2a2a;border-radius:10px;color:#f0f0f0;padding:12px;font-size:15px;box-sizing:border-box;margin-bottom:12px;}
  button{width:100%;background:#c8f135;color:#0d0d0d;border:none;border-radius:10px;padding:14px;font-size:15px;font-weight:700;cursor:pointer;}
  .err{color:#ff5e5e;font-size:13px;margin-bottom:12px;}
</style></head>
<body>
  <div class="box">
    <h2>💸 Admin</h2>
    ${error ? `<div class="err">${error}</div>` : ''}
    <form method="POST">
      <input type="password" name="pass" placeholder="Password" autofocus>
      <button type="submit">Entrar</button>
    </form>
  </div>
</body></html>`;
}

function adminPage(licenses) {
  const initialData = JSON.stringify(licenses).replace(/</g, '<');
  return '<!DOCTYPE html>' +
'<html>' +
'<head><meta charset="UTF-8"><title>Admin - Financas Pessoais</title>' +
'<style>' +
'body{font-family:system-ui;background:#0d0d0d;color:#f0f0f0;margin:0;padding:24px;}' +
'.card{background:#161616;border:1px solid #2a2a2a;border-radius:12px;padding:20px;margin-bottom:20px;}' +
'h3{margin:0 0 16px;font-size:15px;color:#777;text-transform:uppercase;letter-spacing:1px;}' +
'#new-email{background:#1e1e1e;border:1.5px solid #2a2a2a;border-radius:8px;color:#f0f0f0;padding:10px 12px;font-size:14px;width:260px;}' +
'.btn-add{background:#c8f135;color:#0d0d0d;border:none;border-radius:8px;padding:10px 20px;font-size:14px;font-weight:700;cursor:pointer;margin-left:8px;}' +
'.btn-rem{background:#ff5e5e;color:#fff;border:none;border-radius:6px;padding:4px 10px;cursor:pointer;font-size:12px;}' +
'#btn-logout{background:#2a2a2a;color:#777;border:none;border-radius:8px;padding:8px 16px;cursor:pointer;font-size:13px;}' +
'table{width:100%;border-collapse:collapse;}' +
'th{text-align:left;font-size:12px;color:#777;text-transform:uppercase;letter-spacing:1px;padding:8px 12px;border-bottom:1px solid #2a2a2a;}' +
'td{padding:10px 12px;border-bottom:1px solid #1a1a1a;font-size:14px;}' +
'#count{color:#c8f135;font-size:13px;margin-bottom:12px;}' +
'.empty{color:#555;text-align:center;padding:20px;}' +
'</style></head>' +
'<body>' +
'<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:24px;">' +
'<h1 style="margin:0;color:#c8f135;">Financas Pessoais - Admin</h1>' +
'<button id="btn-logout">Sair</button>' +
'</div>' +
'<div class="card">' +
'<h3>Adicionar licenca</h3>' +
'<input type="email" id="new-email" placeholder="email@exemplo.com">' +
'<button class="btn-add" id="btn-add">+ Adicionar</button>' +
'</div>' +
'<div class="card">' +
'<h3>Licencas ativas</h3>' +
'<div id="count"></div>' +
'<table><thead><tr><th>Email</th><th>Origem</th><th>Data</th><th></th></tr></thead>' +
'<tbody id="tbody"></tbody></table>' +
'</div>' +
'<script>' +
'var licenses = ' + initialData + ';' +
'function api(data, cb) {' +
'  fetch("/admin/api", {method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(data)})' +
'  .then(function(r){ if(r.ok && cb) cb(); });' +
'}' +
'function render() {' +
'  var tbody = document.getElementById("tbody");' +
'  var count = document.getElementById("count");' +
'  count.textContent = licenses.length + " licenca" + (licenses.length !== 1 ? "s" : "");' +
'  if (!licenses.length) { tbody.innerHTML = "<tr><td colspan=4 class=empty>Sem licencas</td></tr>"; return; }' +
'  tbody.innerHTML = licenses.map(function(l) {' +
'    return "<tr><td>" + l.email + "</td><td>" + (l.source||"?") + "</td><td>" +' +
'    (l.licensed_at ? new Date(l.licensed_at).toLocaleDateString("pt-PT") : "?") +' +
'    "</td><td><button class=btn-rem data-email=" + l.email + ">Remover</button></td></tr>";' +
'  }).join("");' +
'  tbody.querySelectorAll(".btn-rem").forEach(function(btn) {' +
'    btn.addEventListener("click", function() {' +
'      var email = this.getAttribute("data-email");' +
'      if (!confirm("Remover licença de " + email + "?")) return;' +
'      api({action:"remove",email:email}, function() {' +
'        licenses = licenses.filter(function(l){ return l.email !== email; });' +
'        render();' +
'      });' +
'    });' +
'  });' +
'}' +
'document.getElementById("btn-add").addEventListener("click", function() {' +
'  var email = document.getElementById("new-email").value.trim().toLowerCase();' +
'  if (!email) return;' +
'  api({action:"add",email:email}, function() {' +
'    licenses.push({email:email,source:"manual",licensed_at:new Date().toISOString()});' +
'    document.getElementById("new-email").value = "";' +
'    render();' +
'  });' +
'});' +
'document.getElementById("btn-logout").addEventListener("click", function() {' +
'  api({action:"logout"}, function() { window.location.href = "/admin"; });' +
'});' +
'render();' +
'</script>' +
'</body></html>';
}
