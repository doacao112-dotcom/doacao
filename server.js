// server.js
import 'dotenv/config';
import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import crypto from 'node:crypto';

/* =========================
   Helpers
========================= */
function toUtcString(date = new Date()) {
  const pad = n => String(n).padStart(2, '0');
  const y = date.getUTCFullYear();
  const m = pad(date.getUTCMonth() + 1);
  const d = pad(date.getUTCDate());
  const hh = pad(date.getUTCHours());
  const mm = pad(date.getUTCMinutes());
  const ss = pad(date.getUTCSeconds());
  return `${y}-${m}-${d} ${hh}:${mm}:${ss}`;
}

function getClientIp(req) {
  const xf = req.headers['x-forwarded-for'];
  return (typeof xf === 'string' && xf.split(',')[0].trim())
      || req.socket?.remoteAddress
      || '0.0.0.0';
}

/* =========================
   App e Middlewares
========================= */
const app = express();

// ✅ CORS fix: whitelist explícita
app.use(cors({
  origin: (origin, callback) => {
    if (!origin) return callback(null, true); // requests sem Origin (ex: curl)
    const allowedOrigins = [
      "https://grand-brioche-edef86.netlify.app"
    ];
    if (allowedOrigins.includes(origin)) {
      return callback(null, true);
    } else {
      return callback(new Error("Not allowed by CORS: " + origin));
    }
  },
  methods: ["GET","HEAD","PUT","PATCH","POST","DELETE","OPTIONS"],
  allowedHeaders: ["Content-Type"],
  credentials: true
}));
app.options("*", cors());

// Segurança e limites
app.use(helmet());
app.use(express.json({ limit: '1mb' }));
app.use(rateLimit({ windowMs: 60_000, max: 60 }));

/* =========================
   "DB" simples (Map em memória)
========================= */
const db = new Map();

/* =========================
   Veopag
========================= */
const VEOPAG_AUTH    = 'https://api.veopag.com/api/auth/login';
const VEOPAG_DEPOSIT = 'https://api.veopag.com/api/payments/deposit';
const VEOPAG_STATUS  = (id) => `https://api.veopag.com/api/payments/status/${id}`;

async function veopagToken() {
  const r = await fetch(VEOPAG_AUTH, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      client_id: process.env.VEOPAG_CLIENT_ID,
      client_secret: process.env.VEOPAG_CLIENT_SECRET,
    }),
  });
  const raw = await r.text();
  if (!r.ok) throw new Error(`Veopag auth ${r.status}: ${raw}`);
  const data = JSON.parse(raw);
  return data.token;
}

function parseVeopagDepositResponse(data) {
  const qrBlock = data?.qrCodeResponse || data?.data || data;
  return {
    transactionId: qrBlock?.transactionId || data?.transactionId,
    qrCodeUrl: qrBlock?.qrCodeUrl || null,
    copyPaste: qrBlock?.pixCopyPaste || null,
    expiresAt: qrBlock?.expiresAt || null
  };
}

async function createDeposit({ amount, externalId }) {
  const token = await veopagToken();

  const payload = {
    amount,
    external_id: externalId,
    clientCallbackUrl: process.env.PUBLIC_CALLBACK_URL,
    payer: { name: 'Doação Anônima', email: 'anon@exemplo.com', document: '00000000000' }
  };

  const r = await fetch(VEOPAG_DEPOSIT, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify(payload),
  });

  const raw = await r.text();
  if (!r.ok) throw new Error(`Veopag deposit ${r.status}: ${raw}`);
  const data = JSON.parse(raw);

  return parseVeopagDepositResponse(data);
}

async function getDepositStatus(transactionId) {
  const token = await veopagToken();
  const r = await fetch(VEOPAG_STATUS(transactionId), {
    method: 'GET',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
  });
  const raw = await r.text();
  if (!r.ok) throw new Error(`Veopag status ${r.status}: ${raw}`);
  const data = JSON.parse(raw);
  return data?.status;
}

/* =========================
   UTMify
========================= */
async function sendUtmifyOrder({
  apiToken,
  orderId,
  status, // waiting_payment | paid
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
    platform: "AjudaPeluda",
    paymentMethod: "pix",
    status,
    createdAt: createdAtUtc,
    approvedDate: approvedDateUtc,
    refundedAt: null,
    customer: {
      name: "Doação Anônima",
      email: customerEmail,
      phone: null,
      document: null,
      country: "BR",
      ip: customerIp,
    },
    products: [{
      id: transactionId,
      name: "Doação",
      planId: "doacao_unica",     // ✅ NOVO: obrigatório p/ UTMify
      planName: "Doação Única",   // ✅ NOVO: obrigatório p/ UTMify
      quantity: 1,
      priceInCents: amountInCents,
    }],
    trackingParameters: {
      utm_source: utm?.source ?? null,
      utm_campaign: utm?.campaign ?? null,
      utm_medium: utm?.medium ?? null,
      utm_content: utm?.content ?? null,
      utm_term: utm?.term ?? null,
    },
    commission: {
      totalPriceInCents: amountInCents,
      gatewayFeeInCents: 0,
      userCommissionInCents: amountInCents,
    },
    isTest,
  };

  const r = await fetch(endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-api-token': apiToken },
    body: JSON.stringify(body),
  });

  if (!r.ok) {
    const txt = await r.text();
    throw new Error(`UTMify ${r.status}: ${txt}`);
  }
}

/* =========================
   Rotas
========================= */
app.get('/healthz', (_req, res) => res.json({ ok: true }));

// Criar doação
app.post('/donations', async (req, res) => {
  try {
    const amount = Number(req.body?.amount);
    if (!Number.isFinite(amount) || amount <= 0) {
      return res.status(400).json({ error: 'amount inválido' });
    }

    const utm = req.body?.utm || null;
    const donationId = crypto.randomUUID();
    const externalId = `donation_${donationId}`;

    const qr = await createDeposit({ amount, externalId });

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

    await sendUtmifyOrder({
      apiToken: process.env.UTMIFY_API_TOKEN,
      orderId: externalId,
      status: 'waiting_payment',
      createdAtUtc,
      amountInCents: Math.round(amount * 100),
      transactionId: qr.transactionId,
      utm,
      isTest: false,
      customerIp: getClientIp(req),
    });

    res.status(201).json({
      donationId,
      qrCodeUrl: qr.qrCodeUrl,
      copyPaste: qr.copyPaste,
      expiresAt: qr.expiresAt,
    });
  } catch (e) {
    res.status(502).json({ error: String(e.message || e) });
  }
});

// Consultar doação
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

// Webhook Veopag
app.post('/webhooks/veopag', async (req, res) => {
  try {
    const ev = req.body; // { transaction_id, status }

    let donationId = null;
    let row = null;
    for (const [id, rec] of db.entries()) {
      if (rec.veopagTxId === ev.transaction_id) {
        donationId = id;
        row = rec;
        break;
      }
    }
    if (!row) return res.status(404).json({ error: 'donation not found', received: ev });

    if (ev.status === 'COMPLETED' && row.status !== 'paid') {
      row.status = 'paid';
      db.set(donationId, row);

      await sendUtmifyOrder({
        apiToken: process.env.UTMIFY_API_TOKEN,
        orderId: `donation_${donationId}`,
        status: 'paid',
        createdAtUtc: row.createdAtUtc,
        approvedDateUtc: toUtcString(),
        amountInCents: Math.round(row.amount * 100),
        transactionId: row.veopagTxId,
        utm: row.utm,
        isTest: false,
        customerIp: getClientIp(req),
      });
    }

    res.json({ received: true });
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  }
});

/* =========================
   Start
========================= */
const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`API up on :${port}`));
