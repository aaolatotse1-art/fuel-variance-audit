// Zoho OAuth Server — Sky Bridge Logistics
// This runs a local web server that handles the OAuth redirect from Zoho
// and exchanges the code for a real access token automatically.
//
// HOW TO USE:
// 1. Run: node zoho-auth-server.js
// 2. It will print a URL — open it in your browser
// 3. Zoho will ask you to authorise — click Allow
// 4. You'll be redirected back and your access token prints in the terminal
// 5. Copy the token into Fuel Variance Audit → Settings → Access Token

const https = require('https');
const http  = require('http');
const url   = require('url');

// ── Paste your NEW Client ID and Secret from api-console.zoho.com ──
// Go to api-console.zoho.com → Add Client → Server-based Application
// Redirect URI to use: http://localhost:4242/callback
const CLIENT_ID     = '1000.NGDCOPKS9QZX1M1TQ1PCRMRX8RWQJR';
const CLIENT_SECRET = '4bbd3f4ee835c54aa6b8dbea953fbdd9494adc2507';
const REDIRECT_URI  = 'http://localhost:4242/callback';
const SCOPE         = 'Desk.tickets.ALL,Desk.basic.READ,Desk.contacts.READ,Desk.agents.READ';
const ORG_ID        = '914012724';

const PORT = 4242;

const server = http.createServer(async (req, res) => {
  const parsed = url.parse(req.url, true);

  if (parsed.pathname === '/') {
    const authUrl = `https://accounts.zoho.com/oauth/v2/auth?` +
      `response_type=code&client_id=${CLIENT_ID}&scope=${encodeURIComponent(SCOPE)}` +
      `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&access_type=offline`;

    res.writeHead(302, { Location: authUrl });
    res.end();
    return;
  }

  if (parsed.pathname === '/callback') {
    const code = parsed.query.code;
    if (!code) {
      res.writeHead(400); res.end('No code received');
      return;
    }

    console.log('\n✅ Got authorization code — exchanging for token...');

    const body = new URLSearchParams({
      code,
      grant_type:    'authorization_code',
      client_id:     CLIENT_ID,
      client_secret: CLIENT_SECRET,
      redirect_uri:  REDIRECT_URI,
    }).toString();

    const tokenReq = https.request({
      hostname: 'accounts.zoho.com',
      path:     '/oauth/v2/token',
      method:   'POST',
      headers: {
        'Content-Type':   'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(body),
      },
    }, (tokenRes) => {
      let d = ''; tokenRes.on('data', c => d += c);
      tokenRes.on('end', () => {
        const json = JSON.parse(d);
        if (json.access_token) {
          console.log('\n━'.repeat(50));
          console.log('✅ ACCESS TOKEN:');
          console.log(json.access_token);
          console.log('━'.repeat(50));
          if (json.refresh_token) {
            console.log('\n🔄 REFRESH TOKEN (never expires — save this!):');
            console.log(json.refresh_token);
          }
          console.log('\n📋 Paste the access token into:');
          console.log('   Fuel Variance Audit → Settings → Access Token\n');

          // Test it immediately
          testToken(json.access_token);

          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end(`<!DOCTYPE html><html><body style="font-family:sans-serif;padding:40px;background:#0f1419;color:#e7ebf0">
            <h2 style="color:#5fd3a3">✅ Token Generated Successfully!</h2>
            <p>Your access token has been printed in the terminal.</p>
            <p>Copy it and paste it into <strong>Fuel Variance Audit → Settings → Access Token</strong></p>
            <p style="color:#8b96a5;font-size:13px">You can close this tab and the terminal server (Ctrl+C).</p>
          </body></html>`);
        } else {
          console.log('❌ Token exchange failed:', JSON.stringify(json, null, 2));
          res.writeHead(400, { 'Content-Type': 'text/html' });
          res.end(`<pre style="color:red">${JSON.stringify(json, null, 2)}</pre>`);
        }
        setTimeout(() => server.close(), 3000);
      });
    });
    tokenReq.on('error', e => console.log('Token error:', e.message));
    tokenReq.write(body);
    tokenReq.end();
  }
});

function testToken(token) {
  const req = https.request({
    hostname: 'desk.zoho.com',
    path:     '/api/v1/myProfile',
    method:   'GET',
    headers: {
      'Authorization': `Zoho-oauthtoken ${token}`,
      'orgId': ORG_ID,
    },
  }, (res) => {
    let d = ''; res.on('data', c => d += c);
    res.on('end', () => {
      const json = JSON.parse(d);
      if (json.firstName) {
        console.log(`\n✅ Token verified! Logged in as: ${json.firstName} ${json.lastName}`);
      } else {
        console.log('\n⚠️  Token test:', JSON.stringify(json));
      }
    });
  });
  req.on('error', e => console.log('Test error:', e.message));
  req.end();
}

server.listen(PORT, () => {
  console.log('\n⛽  Zoho OAuth Server — Sky Bridge Logistics');
  console.log('━'.repeat(50));
  console.log(`\n📌 STEP 1: Create a Server-based OAuth app in Zoho:`);
  console.log(`   → https://api-console.zoho.com`);
  console.log(`   → Click "Add Client" → "Server-based Applications"`);
  console.log(`   → Homepage URL: http://localhost:4242`);
  console.log(`   → Redirect URI:  http://localhost:4242/callback`);
  console.log(`   → Copy the Client ID and Client Secret`);
  console.log(`   → Open this file in Notepad and paste them in`);
  console.log(`   → Save and re-run this script`);
  console.log(`\n📌 STEP 2: Once Client ID/Secret are filled in:`);
  console.log(`   → Open http://localhost:4242 in your browser`);
  console.log(`   → Log in with aolatotse@skybridge.co.bw`);
  console.log(`   → Click Allow`);
  console.log(`   → Your token will print here in the terminal`);
  console.log('\n━'.repeat(50));

  if (CLIENT_ID === 'PASTE_NEW_CLIENT_ID') {
    console.log('\n⚠️  Fill in CLIENT_ID and CLIENT_SECRET first (see steps above)\n');
  } else {
    console.log(`\n✅ Ready! Open http://localhost:${PORT} in your browser\n`);
  }
});
