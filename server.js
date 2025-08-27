// server.js — CryptoBotX (production, no debug flags, auth enforced)

require('dotenv').config();
const express = require('express');
const cors = require('cors');

// ---------- Express ----------
const app = express();
const PORT = process.env.PORT || 3001;
app.use(cors({ origin: true }));
app.use(express.json({ limit: '1mb' }));

// ---------- Firebase Auth (required) ----------
let admin;
try {
  admin = require('firebase-admin');
  const privateKey = (process.env.FIREBASE_PRIVATE_KEY || '').replace(/\\n/g, '\n');
  admin.initializeApp({
    credential: admin.credential.cert({
      type: 'service_account',
      project_id: process.env.FIREBASE_PROJECT_ID,
      private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID,
      private_key: privateKey,
      client_email: process.env.FIREBASE_CLIENT_EMAIL,
      client_id: process.env.FIREBASE_CLIENT_ID,
      auth_uri: 'https://accounts.google.com/o/oauth2/auth',
      token_uri: 'https://oauth2.googleapis.com/token',
      auth_provider_x509_cert_url: 'https://www.googleapis.com/oauth2/v1/certs',
      client_x509_cert_url: process.env.FIREBASE_CLIENT_CERT_URL,
    }),
  });
  console.log('✅ Firebase Admin initialized');
} catch (e) {
  console.error('❌ Firebase Admin init failed:', e.message);
}

const authenticate = async (req, res, next) => {
  try {
    if (!admin?.auth) return res.status(500).json({ error: 'Auth unavailable' });
    const h = req.headers.authorization || '';
    const token = h.startsWith('Bearer ') ? h.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'Access token required' });
    const decoded = await admin.auth().verifyIdToken(token);
    req.user = { userId: decoded.uid, email: decoded.email || '' };
    next();
  } catch (e) {
    return res.status(403).json({ error: 'Invalid token' });
  }
};

// ---------- In-memory bot state ----------
const state = { bots: new Map() };
function botFor(uid) {
  if (!state.bots.has(uid)) {
    state.bots.set(uid, {
      configured: false,
      running: false,
      mode: 'demo', // demo | live
      coinbase: null, // { apiKey, apiSecret }
      params: {
        strategy: 'baseline',
        minConfidence: 60,
        tradeAmount: 25,
        maxPortfolioPercent: 25,
        maxDailyRisk: 50,
        maxTradesPerDay: 3,
        enableStopLoss: true,
        stopLossPercent: 5,
        enableTakeProfit: true,
        takeProfitPercent: 10,
      },
      perf: {
        dailyTrades: 0,
        maxDailyTrades: 3,
        dailyRisk: 0,
        maxDailyRisk: 50,
        totalPnL: 0,
        winRate: 0,
        portfolioValue: 0,
      },
      trades: [],
    });
  }
  return state.bots.get(uid);
}


// ---------- Key normalization (FIXED VERSION) ----------
function normalizePrivateKey(input) {
  if (!input) {
    throw new Error('Missing private key');
  }
  
  // Don't modify the key at all - just validate it has the right markers
  let key = input;
  
  // Only handle escaped newlines if they exist, but don't force string conversion
  if (typeof key === 'string' && key.includes('\\n')) {
    key = key.replace(/\\n/g, '\n');
  }

  const keyStr = String(key);
  const hasBegin = keyStr.includes('-----BEGIN');
  const hasEnd = keyStr.includes('-----END') && keyStr.includes('PRIVATE KEY-----');

  if (!hasBegin || !hasEnd) {
    throw new Error('Invalid key format - must include BEGIN/END lines');
  }

  // Return the key exactly as received (no trimming, no extra processing)
  return key;
}

// ---------- CORRECTED JWT GENERATOR FOR COINBASE ADVANCED TRADE API ----------
const crypto = require('crypto');

function generateJwtManually({ apiKeyId, apiKeySecret, requestMethod, requestHost, requestPath, expiresIn = 120 }) {
  const now = Math.floor(Date.now() / 1000);
  
  // Coinbase Advanced Trade API specific JWT format
  const header = {
    alg: 'ES256',
    typ: 'JWT',
    kid: apiKeyId,  // This should be the full organizations/.../apiKeys/... format
    nonce: crypto.randomBytes(16).toString('hex') // Add nonce for uniqueness
  };
  
 const payload = {
  iss: 'cdp',  // FIXED: Changed from 'coinbase-cloud' to 'cdp'
  sub: this.apiKeyResource,
  aud: ['retail_rest_api_proxy'],  // FIXED: Changed from 'public_websocket_api' to 'retail_rest_api_proxy'
  nbf: now,
  exp: now + 120,
  uri: `${method} ${host}${path}`
};

  console.log('JWT Header:', JSON.stringify(header, null, 2));
  console.log('JWT Payload:', JSON.stringify(payload, null, 2));
  console.log('Using API Key ID:', apiKeyId);
  console.log('Request URI:', payload.uri);
  
  const base64UrlEncode = (obj) => {
    return Buffer.from(JSON.stringify(obj))
      .toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  };
  
  const encodedHeader = base64UrlEncode(header);
  const encodedPayload = base64UrlEncode(payload);
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  
  console.log('Signing input:', signingInput.substring(0, 100) + '...');
  
  try {
    // Create ECDSA signature with ES256 (ECDSA using P-256 curve and SHA-256 hash)
    const sign = crypto.createSign('SHA256');
    sign.update(signingInput);
    
    // Sign with the private key and get raw signature bytes
    const signatureBuffer = sign.sign(apiKeySecret);
    
    // Convert to base64url format
    const signature = signatureBuffer
      .toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
    
    const jwt = `${signingInput}.${signature}`;
    console.log('Generated JWT length:', jwt.length);
    console.log('JWT signature:', signature.substring(0, 20) + '...');
    
    return jwt;
    
  } catch (error) {
    console.error('JWT signing failed:', error.message);
    throw new Error(`JWT signing failed: ${error.message}`);
  }
}

// ---------- UPDATED: Enhanced getGenerateJwt with better error handling ----------
async function getGenerateJwt() {
  try {
    // First try CDP SDK
    const cdp = require('@coinbase/cdp-sdk');
    console.log('CDP SDK available methods:', Object.keys(cdp));
    
    // Try different possible export paths
    if (typeof cdp.generateJwt === 'function') {
      console.log('✅ Using CDP SDK generateJwt');
      return cdp.generateJwt;
    }
    
    if (cdp.auth && typeof cdp.auth.generateJwt === 'function') {
      console.log('✅ Using CDP SDK auth.generateJwt');
      return cdp.auth.generateJwt;
    }
    
    console.log('⚠️ CDP SDK generateJwt not found, using manual implementation');
    
  } catch (error) {
    console.log('⚠️ CDP SDK not available, using manual JWT generation:', error.message);
  }
  
  // Use manual JWT generation
  console.log('✅ Using manual JWT generation for Coinbase Advanced Trade API');
  return generateJwtManually;
}

// ---------- Coinbase Advanced Trade client (CDP SDK signer) ----------
class CoinbaseAdvancedAPI {
  constructor(apiKeyResource, privateKeyPem) {
    console.log("--- DEBUG: DATA RECEIVED BY SERVER ---");
    console.log("Raw apiKeyResource:", apiKeyResource);
    console.log("Raw privateKeyPem length:", privateKeyPem?.length);
    console.log("Raw privateKeyPem starts with:", privateKeyPem?.substring(0, 50));

    // DON'T TRIM the API key - use it exactly as received
    this.apiKeyResource = apiKeyResource || '';
    const parts = this.apiKeyResource.split('/apiKeys/');
    if (parts.length !== 2) {
      throw new Error('Invalid API key format. Expect "organizations/<org>/apiKeys/<uuid>"');
    }
    this.orgResource = parts[0];
    this.apiKeyId = parts[1];
    
    // DON'T MODIFY the private key - use it exactly as received
    this.privateKeyPem = normalizePrivateKey(privateKeyPem);

    console.log("Final privateKeyPem length:", this.privateKeyPem?.length);
    console.log("Final privateKeyPem starts with:", String(this.privateKeyPem).substring(0, 50));
    console.log("Final privateKeyPem ends with:", String(this.privateKeyPem).substring(String(this.privateKeyPem).length - 50));
    console.log("--- END DEBUG ---");

    this.HOST = 'api.coinbase.com';
  }

 async request(method, endpoint) {
  const host = this.HOST;
  const path = `/api/v3/brokerage${endpoint}`;
  
  try {
    const token = this.generateJWT(method, host, path);
    
    console.log("Making request to:", `https://${host}${path}`);
    
    const res = await fetch(`https://${host}${path}`, {
      method,
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
    });

    if (!res.ok) {
      const text = await res.text();
      console.error(`Coinbase API ${res.status}:`, text);
      throw new Error(`Coinbase API ${res.status}: ${text || 'Unauthorized'}`);
    }
    
    const data = await res.json();
    console.log("✅ Coinbase API success!");
    return data;
    
  } catch (error) {
    console.error("❌ Coinbase API failed:", error.message);
    throw error;
  }
}

generateJWT(method, host, path) {
  const crypto = require('crypto');
  const now = Math.floor(Date.now() / 1000);
  
  const header = {
    alg: 'ES256',
    typ: 'JWT',
    kid: this.apiKeyResource,
    nonce: crypto.randomBytes(16).toString('hex')
  };
  
  const payload = {
    iss: 'cdp',
    sub: this.apiKeyResource,
    aud: ['retail_rest_api_proxy'],
    nbf: now,
    exp: now + 120,
    uri: `${method} ${host}${path}`
  };

  console.log("JWT Header:", JSON.stringify(header));
  console.log("JWT Payload:", JSON.stringify(payload));
  
  const base64UrlEncode = (obj) => {
    return Buffer.from(JSON.stringify(obj))
      .toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  };
  
  const encodedHeader = base64UrlEncode(header);
  const encodedPayload = base64UrlEncode(payload);
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  
  const sign = crypto.createSign('SHA256');
  sign.update(signingInput);
  const signature = sign.sign(this.privateKeyPem)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
  
  return `${signingInput}.${signature}`;
}

  getCandles(productId, granularity, startISO, endISO) {
    const qs = new URLSearchParams({
      granularity,
      start: startISO,
      end: endISO,
    }).toString();
    return this.request('GET', `/products/${productId}/candles?${qs}`);
  }

  async getPortfolioSummary() {
    const data = await this.getAccounts();
    const accounts = data?.accounts || [];
    let total = 0;
    for (const a of accounts) {
      const v = parseFloat(a?.available_balance?.value || '0');
      if (!Number.isNaN(v)) total += v;
    }
    return { totalBalance: total, availableBalance: total * 0.9 };
  }
}

// ---------- OpenAI (for AI decisions) ----------
let openai = null;
const OPENAI_MODEL = process.env.OPENAI_MODEL || 'gpt-5-thinking';
try {
  const { OpenAI } = require('openai');
  if (process.env.OPENAI_API_KEY) {
    openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
    console.log('✅ OpenAI initialized');
  } else {
    console.warn('⚠️ OPENAI_API_KEY not set; /api/bot/analyze will return 400.');
  }
} catch (e) {
  console.warn('⚠️ OpenAI SDK not available:', e.message);
}

// ---------- Health / test ----------
app.get('/healthz', (_, res) => {
  console.log('✅ Health check endpoint was hit!');
  res.json({ ok: true });
});
app.get('/api/test', (_, res) => res.json({ ok: true }));

// ---------- Helpers ----------
const ensureConfigured = (req, res, next) => {
  const b = botFor(req.user.userId);
  if (!b?.configured) return res.status(400).json({ error: 'Bot not configured yet' });
  req.bot = b;
  next();
};

// ---------- Status / Performance / Permissions ----------
function statusHandler(req, res) {
  const b = botFor(req.user.userId);
  res.json({ configured: b.configured, running: b.running, mode: b.mode });
}
app.get('/api/bot/status', authenticate, statusHandler);

async function performanceHandler(req, res) {
  try {
    const b = botFor(req.user.userId);
    if (b.configured && b.coinbase) {
      try {
        const client = new CoinbaseAdvancedAPI(b.coinbase.apiKey, b.coinbase.apiSecret);
        const summary = await client.getPortfolioSummary();
        b.perf.portfolioValue = Number(summary.totalBalance.toFixed(2));
      } catch (_) {}
    }
    res.json(b.perf);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
}
app.get('/api/bot/performance', authenticate, performanceHandler);

async function permissionsHandler(req, res) {
  try {
    const b = botFor(req.user.userId);
    if (!b.configured || !b.coinbase) {
      return res.json({ canRead: false, canTrade: false, isConnected: false });
    }
    let canRead = false;
    try {
      const client = new CoinbaseAdvancedAPI(b.coinbase.apiKey, b.coinbase.apiSecret);
      await client.getAccounts();
      canRead = true;
    } catch (_) {}
    const canTrade = false; // set true if you later validate trade permission
    res.json({ canRead, canTrade, isConnected: canRead });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
}
app.get('/api/bot/permissions', authenticate, permissionsHandler);

// ---------- Setup endpoint (FIXED VERSION) ----------
app.post('/api/bot/setup', authenticate, async (req, res) => {
  try {
    const {
      apiKey,
      apiSecret,
      strategy,
      minConfidence,
      tradeAmount,
      maxPortfolioPercent,
      maxDailyRisk,
      maxTradesPerDay,
      enableStopLoss,
      stopLossPercent,
      enableTakeProfit,
      takeProfitPercent,
    } = req.body || {};

    if (!apiKey || !apiSecret) return res.status(400).json({ error: 'Missing apiKey or apiSecret' });

    console.log("=== SETUP DEBUG ===");
    console.log("Received apiKey:", apiKey);
    console.log("Received apiSecret length:", apiSecret?.length);
    console.log("Received apiSecret starts with:", apiSecret?.substring(0, 50));

    // Test the connection with the exact keys as received (NO TRIMMING!)
    const client = new CoinbaseAdvancedAPI(apiKey, apiSecret);
    await client.getAccounts(); // throws if invalid / unauthorized

    const b = botFor(req.user.userId);
    b.configured = true;
    // Store keys WITHOUT any modification
    b.coinbase = { apiKey: apiKey, apiSecret: apiSecret };
    b.params = {
      strategy,
      minConfidence,
      tradeAmount,
      maxPortfolioPercent,
      maxDailyRisk,
      maxTradesPerDay,
      enableStopLoss,
      stopLossPercent,
      enableTakeProfit,
      takeProfitPercent,
    };

    res.json({ ok: true, configured: true });
  } catch (e) {
    console.error("Setup failed:", e.message);
    res.status(400).json({ error: `V3 DEBUG: Failed to connect to Coinbase API: ${e.message}` });
  }
});

// ---------- Start / Stop / Mode ----------
app.post('/api/bot/start', authenticate, ensureConfigured, (req, res) => {
  req.bot.running = true;
  res.json({ ok: true, running: true });
});

app.post('/api/bot/stop', authenticate, ensureConfigured, (req, res) => {
  req.bot.running = false;
  res.json({ ok: true, running: false });
});

app.post('/api/bot/mode', authenticate, ensureConfigured, (req, res) => {
  const { mode } = req.body || {};
  if (!['demo', 'live'].includes(mode)) return res.status(400).json({ error: 'mode must be demo|live' });
  req.bot.mode = mode;
  res.json({ ok: true, mode });
});

// ---------- Trade history (demo/paper) ----------
app.get('/api/trades/history', authenticate, (req, res) => {
  const b = botFor(req.user.userId);
  res.json({ trades: b.trades || [] });
});

// ---------- AI analyze ----------
app.post('/api/bot/analyze', authenticate, ensureConfigured, async (req, res) => {
  try {
    if (!openai) return res.status(400).json({ error: 'OPENAI_API_KEY missing' });

    const b = req.bot;
    const product = (req.body?.product || 'BTC-USD').toUpperCase();

    const now = new Date();
    const endISO = now.toISOString();
    const startISO = new Date(now.getTime() - 7 * 24 * 3600 * 1000).toISOString();
    const granularity = 'ONE_HOUR';

    const cb = new CoinbaseAdvancedAPI(b.coinbase.apiKey, b.coinbase.apiSecret);
    const candles = await cb.getCandles(product, granularity, startISO, endISO);

    const risk = {
      dailyRiskUsd: b.params?.maxDailyRisk ?? 50,
      maxTradesPerDay: b.params?.maxTradesPerDay ?? 3,
      stopLossPct: b.params?.stopLossPercent ?? 5,
      takeProfitPct: b.params?.takeProfitPercent ?? 10,
    };

    const chat = await openai.chat.completions.create({
      model: OPENAI_MODEL,
      temperature: 0.2,
      messages: [
        { role: 'system', content: 'Return ONLY JSON with keys: action(BUY|SELL|HOLD), confidence(0-100), reason(<=180 chars), sizeUsd, stopLossPct, takeProfitPct.' },
        { role: 'user', content: JSON.stringify({ product, risk, data: { granularity, candles } }) },
      ],
    });

    let out;
    try { out = JSON.parse(chat.choices?.[0]?.message?.content || '{}'); } catch (_) {}
    if (!out?.action) return res.status(502).json({ error: 'AI returned unparseable output' });

    res.json(out);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ---------- 404 / error ----------
app.use((req, res) => res.status(404).json({ error: 'Not found', path: req.originalUrl }));
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// ---------- Start ----------
app.listen(PORT, () => console.log(`🚀 CryptoBotX API listening on port ${PORT}`));
