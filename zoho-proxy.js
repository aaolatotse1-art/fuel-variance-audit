// Zoho Desk Proxy — Sky Bridge Logistics
// Run: node zoho-proxy.js
// Keep this terminal open while using the Fuel Variance Audit app.

const http  = require('http');
const https = require('https');

const PORT = 3030;

const server = http.createServer((req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, orgId, orgid');

  if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  if (req.url === '/ping') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok' }));
    return;
  }

  if (!req.url.startsWith('/zoho/')) { res.writeHead(404); res.end('Not found'); return; }

  const zohoPath = req.url.replace('/zoho', '/api');

  let body = '';
  req.on('data', chunk => body += chunk);
  req.on('end', () => {

    // ── Log the outgoing request so we can debug ──
    console.log(`\n[${new Date().toLocaleTimeString()}] ${req.method} https://desk.zoho.com${zohoPath}`);
    console.log('  orgId header :', req.headers['orgid'] || req.headers['orgId'] || '(none)');
    console.log('  Auth header  :', (req.headers['authorization'] || '(none)').slice(0, 40) + '...');
    if (body) {
      try {
        const parsed = JSON.parse(body);
        console.log('  Payload      :', JSON.stringify(parsed, null, 4));
      } catch(e) {
        console.log('  Body         :', body.slice(0, 300));
      }
    }

    const zohoOptions = {
      hostname: 'desk.zoho.com',
      path:     zohoPath,
      method:   req.method,
      headers: {
        'Content-Type':   'application/json',
        'Authorization':  req.headers['authorization'] || '',
        'orgId':          req.headers['orgid'] || req.headers['orgId'] || '',
        'Content-Length': Buffer.byteLength(body),
      },
    };

    const proxyReq = https.request(zohoOptions, (proxyRes) => {
      let data = '';
      proxyRes.on('data', chunk => data += chunk);
      proxyRes.on('end', () => {
        console.log(`  Zoho status  : ${proxyRes.statusCode}`);
        try {
          console.log('  Zoho response:', JSON.stringify(JSON.parse(data), null, 4));
        } catch(e) {
          console.log('  Zoho response:', data.slice(0, 300));
        }
        res.writeHead(proxyRes.statusCode, { 'Content-Type': 'application/json' });
        res.end(data);
      });
    });

    proxyReq.on('error', e => {
      console.error('  Proxy error:', e.message);
      res.writeHead(502, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: e.message }));
    });

    if (body) proxyReq.write(body);
    proxyReq.end();
  });
});

server.listen(PORT, () => {
  console.log('\n⛽  Zoho Proxy — Sky Bridge Logistics');
  console.log('━'.repeat(45));
  console.log(`✅  Proxy running on http://localhost:${PORT}`);
  console.log('    Full request/response logging enabled.');
  console.log('    Keep this window open while using the app.');
  console.log('    Press Ctrl+C to stop.');
  console.log('━'.repeat(45) + '\n');
});
