// server.js
import 'dotenv/config';
import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import crypto from 'node:crypto';

/* =========================
   Utils
========================= */
function toUtcString(d = new Date()) {
  const pad = n => String(n).padStart(2, '0');
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth()+1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`;
}
function getClientIp(req) {
  const xf = req.headers['x-forwarded-for'];
  return (typeof xf === 'string' && xf.split(',')[0].trim()) || req.socket?.remoteAddress || '0.0.0.0';
}

/* =========================
   CALLBACK fixo (hardcoded)
========================= */
// >>> edite aqui se mudar seu domínio <<<
const HARDCODED_CALLBACK = 'https://doacaopeluda.up.railway.app/webhooks/veopag';

function normalizeCallbackUrl(raw) {
  if (!raw) return null;
  let url = raw.trim();
  if (!/^https?:\/\//i.test(url)) url = 'https://' + url;
  url = url.replace(/\/+$/, '');
  if (!/\/webhooks\/veopag$/i.test(url)) url += '/webhooks/veopag';
  return url;
}
// Prioriza o hardcoded; se quiser manter ENV como fallback, troque a ordem
const CALLBACK_URL = normalizeCallbackUrl(HARDCODED_CALLBACK) || normalizeCallbackUrl(process.env.PUBLIC_CALLBACK_URL);
if (!CALLBACK_URL) throw new Error('Callback URL inválida');

/* =========================
   App & Middlewares
========================= */
const app = express();

// CORS bem permissivo por env (ou “*”)
const allowed = (process.env.CORS_ORIGINS || '*')
  .split(',')
  .map(s => s.trim().replace(/\/$/, ''))
  .filter(Boolean);

app.use((req, res, next) => {
  const origin = (req.headers.origin || '').replace(/\/$/, '');
  res.header('Vary', 'Origin, Access-Control-Request-Headers');
  res.header('Access-Control-Allow-Headers', 'Content-Type');
  res.header('Access-Control-Allow-Methods', 'GET,HEAD,PUT,PATCH,POST,DELETE,OPTIONS');

  let ok = false;
  if (allowed.includes('*')) {
    res.header('Access-Control-Allow-Origin', '*');
    ok = true;
  } else if (origin && (allowed.includes(origin) || allowed.some(a => a.includes('*') && new RegExp('^' + a.replace(/\./g,'\\.').replace('*','.*') + '$','i').test(origin)))) {
    res.header('Access-Control-Allow-Origin', origin);
    ok = true;
  }
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

app.use(helmet());
app.use(express.json({ limit: '1mb' }));
app.use(rateLimit({ windowMs: 60_000, max: 60 }));

/* =========================
   "DB" simples (memória)
========================= */
const db = new Map();

/* =========================
   Veopag
========================= */
const VEOPAG_AUTH = 'https://api.veopag.com/api/auth/login';
const VEOPAG_DEPOSIT = 'https://api.veopag.com/api/payments/deposit';

async function veopagToken() {
  const r = await fetch(VEOPAG_AUTH, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
    body: JSON.stringify({
      client_id: process.env.VEOPAG_CLIENT_ID,
      client_secret: process.env.VEOPAG_CLIENT_SECRET,
    }),
  });
  const raw = await r.text();
  if (process.env.DEBUG_VEOPAG === '1') console.log('[Veopag][auth][RAW]', r.status, raw);
  if (!r.ok) throw new Error(`Veopag auth ${r.status}: ${raw}`);
  const data = JSON.parse(raw);
  if (!data?.token) throw new Error('Veopag token ausente');
  return data.token;
}

// Parser flexível (pega EMV/QR em qualquer formato e por regex)
function parseVeopagDepositResponse(data) {
  const qrBlock = data?.qrCodeResponse || data?.qr_code_response || data?.qr || data?.data || data;
  const transactionId =
    qrBlock?.transactionId || qrBlock?.transaction_id || qrBlock?.id || data?.transactionId || data?.id || null;

  let qrCodeUrl =
    qrBlock?.qrCodeUrl || qrBlock?.qrcodeUrl || qrBlock?.qr_code_url ||
    qrBlock?.qrCode || qrBlock?.qrcode || qrBlock?.qr_url || qrBlock?.imageUrl || null;

  let copyPaste =
    qrBlock?.pixCopyPaste || qrBlock?.copyPaste || qrBlock?.emv || qrBlock?.payload ||
    qrBlock?.pixCode || qrBlock?.brCode || (typeof qrBlock?.qrcode === 'string' ? qrBlock.qrcode : null) ||
    (typeof qrBlock?.code === 'string' ? qrBlock.code : null);

  if (!copyPaste) {
    const raw = JSON.stringify(data);
    const m = raw.match(/000201[\s\S]*?6304[0-9A-Fa-f]{4}/);
    if (m) copyPaste = m[0];
  }
  if (!copyPaste && typeof qrCodeUrl === 'string' && qrCodeUrl.startsWith('000201')) {
    copyPaste = qrCodeUrl; qrCodeUrl = null;
  }
  const expiresAt = qrBlock?.expiresAt ?? qrBlock?.expires_at ?? null;
  return { transactionId, qrCodeUrl, copyPaste, expiresAt };
}

async function createDeposit({ amount, externalId }) {
  const token = await veopagToken();
  const payload = {
    amount,
    external_id: externalId,
    clientCallbackUrl: CALLBACK_URL, // <<< usa callback fixo
    payer: { name: 'Doação Anônima', email: 'anon@exemplo.com', document: '00000000000' }
  };
  const r = await fetch(VEOPAG_DEPOSIT, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Accept': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify(payload),
  });
  const raw = await r.text();
  if (process.env.DEBUG_VEOPAG === '1') {
    console.log('[Veopag][deposit][REQ]', JSON.stringify(payload));
    console.log('[Veopag][deposit][RAW]', r.status, raw);
  }
  if (!r.ok) throw new Error(`Veopag deposit ${r.status}: ${raw}`);
  const data = JSON.parse(raw);
  const parsed = parseVeopagDepositResponse(data);
  if (!parsed.transactionId || (!parsed.qrCodeUrl && !parsed.copyPaste)) {
    throw new Error(`Resposta Veopag sem EMV/QR: ${JSON.stringify(data)}`);
  }
  return parsed;
}

// Fallback para /sync: tenta vários endpoints de status
async function getDepositStatusFallback(transactionId) {
  const token = await veopagToken();
  const urls = [
    `https://api.veopag.com/api/payments/status/${transactionId}`,
    `https://api.veopag.com/api/payments/${transactionId}`,
    `https://api.veopag.com/api/payments/deposit/status/${transactionId}`,
    `https://api.veopag.com/api/payments/deposit/${transactionId}`,
  ];
  for (const url of urls) {
    const r = await fetch(url, { headers: { 'Accept': 'application/json', Authorization: `Bearer ${token}` } });
    const raw = await r.text();
    if (process.env.DEBUG_VEOPAG === '1') console.log('[Veopag][status][TRY]', url, r.status, raw);
    if (r.ok) {
      try {
        const data = JSON.parse(raw);
        return data?.status || data?.data?.status || data?.payment?.status || null;
      } catch { /* segue tentando */ }
    } else if (r.status !== 404) {
      throw new Error(`Veopag status ${r.status}: ${raw}`);
    }
  }
  throw new Error('Nenhum endpoint de status respondeu (fallback).');
}

/* =========================
   UTMify
========================= */
async function sendUtmifyOrder({
  apiToken,
  orderId,
  platform = 'AjudaPeluda',
  paymentMethod = 'pix',
  status,                 // 'waiting_payment' | 'paid'
  createdAtUtc,
  approvedDateUtc = null,
  amountInCents,
  transactionId,
  utm = null,
  isTest = false,
  customerEmail = 'anon@donations.local',
  customerIp = '0.0.0.0',
}) {
  const endpoint = 'https://api.utmify.com.br/api-credentials/orders';
  const body = {
    orderId,
    platform,
    paymentMethod,
    status,
    createdAt: createdAtUtc,
    approvedDate: approvedDateUtc,
    refundedAt: null,
    customer: { name: 'Doação Anônima', email: customerEmail, phone: null, document: null, country: 'BR', ip: customerIp },
    products: [{
      id: transactionId,
      name: 'Doação',
      planId: 'doacao_unica',
      planName: 'Doação Única',
      quantity: 1,
      priceInCents: amountInCents,
    }],
    trackingParameters: {
      src: null, sck: null,
      utm_source: utm?.source ?? null,
      utm_campaign: utm?.campaign ?? null,
      utm_medium: utm?.medium ?? null,
      utm_content: utm?.content ?? null,
      utm_term: utm?.term ?? null,
    },
    commission: { totalPriceInCents: amountInCents, gatewayFeeInCents: 0, userCommissionInCents: amountInCents },
    isTest,
  };
  if (process.env.DEBUG_UTMIFY === '1') console.log('[UTMify][REQ]', JSON.stringify(body, null, 2));
  const r = await fetch(endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-api-token': apiToken },
    body: JSON.stringify(body),
  });
  const text = await r.text();
  if (process.env.DEBUG_UTMIFY === '1') console.log('[UTMify][RES]', r.status, text);
  if (!r.ok) throw new Error(`UTMify ${r.status}: ${text}`);
}

/* =========================
   Rotas
========================= */
// health
app.get('/healthz', (_req, res) => res.json({ ok: true }));

// debug
app.get('/debug/veopag-auth', async (_req, res) => {
  try { const t = await veopagToken(); res.json({ ok: true, tokenPreview: t.slice(0, 12) + '...' }); }
  catch (e) { res.status(502).json({ ok: false, error: String(e.message || e) }); }
});
app.get('/debug/donations', (_req, res) => {
  const items = [];
  for (const [id, r] of db.entries()) items.push({ donationId: id, status: r.status, amount: r.amount, veopagTxId: r.veopagTxId, createdAtUtc: r.createdAtUtc });
  res.json({ count: items.length, items });
});
app.post('/debug/utmify-ping', async (req, res) => {
  try {
    const orderId = `debug_${crypto.randomUUID()}`;
    await sendUtmifyOrder({
      apiToken: process.env.UTMIFY_API_TOKEN,
      orderId,
      status: 'waiting_payment',
      createdAtUtc: toUtcString(),
      approvedDateUtc: null,
      amountInCents: 100,
      transactionId: 'tx_debug',
      utm: { source: 'debug', medium: 'local', campaign: 'ping' },
      isTest: true,
      customerEmail: 'anon@donations.local',
      customerIp: getClientIp(req),
    });
    res.json({ ok: true, orderId });
  } catch (e) { res.status(502).json({ ok: false, error: String(e.message || e) }); }
});

// criar doação
app.post('/donations', async (req, res) => {
  try {
    const amount = Number(req.body?.amount);
    if (!Number.isFinite(amount) || amount <= 0) return res.status(400).json({ error: 'amount inválido' });

    const utm = req.body?.utm || null;
    const donationId = crypto.randomUUID();
    const externalId = `donation_${donationId}`;

    const qr = await createDeposit({ amount, externalId }); // cria PIX na Veopag

    const createdAtUtc = toUtcString();
    db.set(donationId, {
      amount,
      status: 'pending',
      veopagTxId: qr.transactionId,
      qrCodeUrl: qr.qrCodeUrl,
      copyPaste: qr.copyPaste,
      utm,
      createdAtUtc,
    });

    // UTMify: waiting_payment (não bloqueia resposta)
    sendUtmifyOrder({
      apiToken: process.env.UTMIFY_API_TOKEN,
      orderId: externalId,
      status: 'waiting_payment',
      createdAtUtc,
      approvedDateUtc: null,
      amountInCents: Math.round(amount * 100),
      transactionId: qr.transactionId,
      utm,
      isTest: false,
      customerEmail: 'anon@donations.local',
      customerIp: getClientIp(req),
    }).catch(e => console.error('UTMify waiting_payment error:', e?.message || e));

    res.status(201).json({
      donationId,
      transactionId: qr.transactionId,
      qrCodeUrl: qr.qrCodeUrl,
      copyPaste: qr.copyPaste,
      expiresAt: qr.expiresAt ?? null,
    });
  } catch (e) {
    console.error('POST /donations error:', e);
    res.status(502).json({ error: String(e.message || e) });
  }
});

// consultar doação
app.get('/donations/:id', (req, res) => {
  const row = db.get(req.params.id);
  if (!row) return res.status(404).json({ error: 'not found' });
  res.json({
    donationId: req.params.id,
    status: row.status,
    amount: row.amount,
    qrCodeUrl: row.qrCodeUrl,
    copyPaste: row.copyPaste,
  });
});

// webhook Veopag (COMPLETED = paid)
app.post('/webhooks/veopag', async (req, res) => {
  try {
    const ev = req.body; // {transaction_id,status,amount,type}
    let donationId = null, row = null;
    for (const [id, rec] of db.entries()) if (rec.veopagTxId === ev.transaction_id) { donationId = id; row = rec; break; }
    if (!row) return res.status(404).json({ error: 'donation not found', received: ev });

    if (ev.status === 'COMPLETED' && row.status !== 'paid') {
      row.status = 'paid';
      db.set(donationId, row);
      // UTMify: paid
      sendUtmifyOrder({
        apiToken: process.env.UTMIFY_API_TOKEN,
        orderId: `donation_${donationId}`,
        status: 'paid',
        createdAtUtc: row.createdAtUtc,
        approvedDateUtc: toUtcString(),
        amountInCents: Math.round(row.amount * 100),
        transactionId: row.veopagTxId,
        utm: row.utm,
        isTest: false,
        customerEmail: 'anon@donations.local',
        customerIp: getClientIp(req),
      }).catch(e => console.error('UTMify paid error:', e?.message || e));
    }
    res.json({ received: true });
  } catch (e) {
    console.error('Webhook error:', e);
    res.status(500).json({ error: String(e.message || e) });
  }
});

// fallback de sincronização
app.post('/donations/:id/sync', async (req, res) => {
  try {
    const row = db.get(req.params.id);
    if (!row?.veopagTxId) return res.status(404).json({ error: 'not found' });

    const st = await getDepositStatusFallback(row.veopagTxId);
    if (st === 'COMPLETED' && row.status !== 'paid') {
      row.status = 'paid';
      db.set(req.params.id, row);
      await sendUtmifyOrder({
        apiToken: process.env.UTMIFY_API_TOKEN,
        orderId: `donation_${req.params.id}`,
        status: 'paid',
        createdAtUtc: row.createdAtUtc,
        approvedDateUtc: toUtcString(),
        amountInCents: Math.round(row.amount * 100),
        transactionId: row.veopagTxId,
        utm: row.utm,
        isTest: false,
        customerEmail: 'anon@donations.local',
        customerIp: getClientIp(req),
      });
    }
    res.json({ donationId: req.params.id, status: row.status, veopag: st });
  } catch (e) {
    res.status(502).json({ error: String(e.message || e) });
  }
});

/* =========================
   Start
========================= */
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`API up on :${PORT}`));
