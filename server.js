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
  return `${y}-${m}-${d} ${hh}:${mm}:${ss}`; // "YYYY-MM-DD HH:MM:SS" (UTC)
}

function getClientIp(req) {
  const xf = req.headers['x-forwarded-for'];
  return (typeof xf === 'string' && xf.split(',')[0].trim())
      || req.socket?.remoteAddress
      || '0.0.0.0';
}

async function sendUtmifyOrder({
  apiToken,
  orderId,
  platform = 'AjudaPeluda',
  paymentMethod = 'pix',
  status,                 // 'waiting_payment' | 'paid'
  createdAtUtc,
  approvedDateUtc = null, // só no 'paid'
  amountInCents,
  transactionId,          // id da transação na Veopag (products.id)
  utm = null,             // {source, medium, campaign, content, term}
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
    customer: {
      name: 'Doação Anônima',
      email: customerEmail,
      phone: null,
      document: null,
      country: 'BR',
      ip: customerIp,
    },
    products: [{
      id: transactionId,
      name: 'Doação',
      planId: null,
      planName: null,
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
    commission: {
      totalPriceInCents: amountInCents,
      gatewayFeeInCents: 0,
      userCommissionInCents: amountInCents,
    },
    isTest,
  };

  if (process.env.DEBUG_UTMIFY === '1') {
    console.log('[UTMify][REQ]', JSON.stringify(body, null, 2));
  }

  const r = await fetch(endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-api-token': apiToken },
    body: JSON.stringify(body),
  });

  const text = await r.text();
  if (process.env.DEBUG_UTMIFY === '1') {
    console.log('[UTMify][RES]', r.status, text);
  }
  if (!r.ok) throw new Error(`UTMify ${r.status}: ${text}`);
}

/* =========================
   App e Middlewares
========================= */
const app = express();
app.use(helmet());
app.use(express.json({ limit: '1mb' }));
app.use(cors({ origin: (process.env.CORS_ORIGINS || '*').split(',') }));
app.use(rateLimit({ windowMs: 60_000, max: 60 }));

/* =========================
   "DB" simples (trocar por Postgres/SQLite em prod)
   donationId -> {
     amount, status, veopagTxId, qrCodeUrl, copyPaste, utm, createdAtUtc
   }
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
  let data; try { data = JSON.parse(raw); } catch { throw new Error(`Auth não-JSON: ${raw}`); }
  if (!data?.token) throw new Error('Veopag token ausente');
  return data.token;
}

// Parser flexível para aceitar diferentes formatos de resposta
function parseVeopagDepositResponse(data) {
  const qrBlock =
    data?.qrCodeResponse ||
    data?.qr_code_response ||
    data?.qr ||
    data?.data ||
    data;

  const transactionId =
    qrBlock?.transactionId ||
    qrBlock?.transaction_id ||
    qrBlock?.id ||
    data?.transactionId ||
    data?.id;

  const qrCodeUrl =
    qrBlock?.qrCodeUrl ||
    qrBlock?.qrcodeUrl ||
    qrBlock?.qr_code_url ||
    qrBlock?.qrCode ||
    qrBlock?.qrcode ||
    qrBlock?.qr_url ||
    qrBlock?.imageUrl ||
    null;

  const copyPaste =
    qrBlock?.pixCopyPaste ||
    qrBlock?.copyPaste ||
    qrBlock?.emv ||
    qrBlock?.payload ||
    (typeof data === 'string' && data.startsWith('0002') ? data : null) ||
    null;

  const expiresAt = qrBlock?.expiresAt ?? qrBlock?.expires_at ?? null;

  return { transactionId, qrCodeUrl, copyPaste, expiresAt };
}

async function createDeposit({ amount, externalId }) {
  const token = await veopagToken();

  const payload = {
    amount,
    external_id: externalId,
    clientCallbackUrl: process.env.PUBLIC_CALLBACK_URL, // webhook que receberá o COMPLETED
    payer: { name: 'Doação Anônima', email: 'anon@exemplo.com', document: '00000000000' }
  };

  const r = await fetch(VEOPAG_DEPOSIT, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify(payload),
  });

  const raw = await r.text();
  if (process.env.DEBUG_VEOPAG === '1') {
    console.log('[Veopag][deposit][REQ]', JSON.stringify(payload, null, 2));
    console.log('[Veopag][deposit][RAW]', raw);
  }
  if (!r.ok) throw new Error(`Veopag deposit ${r.status}: ${raw}`);

  let data;
  try { data = JSON.parse(raw); } catch { throw new Error(`Veopag retornou texto não-JSON: ${raw}`); }

  const { transactionId, qrCodeUrl, copyPaste, expiresAt } = parseVeopagDepositResponse(data);
  if (!transactionId || (!qrCodeUrl && !copyPaste)) {
    throw new Error(`Resposta Veopag inesperada: ${JSON.stringify(data)}`);
  }

  return { transactionId, qrCodeUrl: qrCodeUrl ?? null, copyPaste: copyPaste ?? null, expiresAt };
}

async function getDepositStatus(transactionId) {
  const token = await veopagToken();
  const r = await fetch(VEOPAG_STATUS(transactionId), {
    method: 'GET',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    },
  });
  const raw = await r.text();
  if (process.env.DEBUG_VEOPAG === '1') {
    console.log('[Veopag][status][RAW]', raw);
  }
  if (!r.ok) throw new Error(`Veopag status ${r.status}: ${raw}`);
  let data; try { data = JSON.parse(raw); } catch { throw new Error(`Status não-JSON: ${raw}`); }
  return data?.status; // 'PENDING' | 'COMPLETED' | ...
}

/* =========================
   Rotas
========================= */

// Healthcheck
app.get('/healthz', (_req, res) => res.json({ ok: true }));

// Debug: testar auth Veopag
app.get('/debug/veopag-auth', async (_req, res) => {
  try {
    const token = await veopagToken();
    res.json({ ok: true, tokenPreview: token.slice(0, 12) + '...' });
  } catch (e) {
    res.status(502).json({ ok: false, error: String(e.message || e) });
  }
});

// Debug: testar envio para UTMify (não mexe no "db")
app.post('/debug/utmify-ping', async (req, res) => {
  try {
    const orderId = `debug_${crypto.randomUUID()}`;
    const nowUtc = toUtcString();
    const clientIp = getClientIp(req);
    await sendUtmifyOrder({
      apiToken: process.env.UTMIFY_API_TOKEN,
      orderId,
      status: 'waiting_payment',
      createdAtUtc: nowUtc,
      approvedDateUtc: null,
      amountInCents: 100,
      transactionId: 'tx_debug',
      utm: { source: 'debug', medium: 'local', campaign: 'ping' },
      isTest: true,
      customerEmail: 'anon@donations.local',
      customerIp: clientIp || '127.0.0.1',
    });
    res.json({ ok: true, orderId });
  } catch (e) {
    res.status(502).json({ ok: false, error: String(e.message || e) });
  }
});

// Debug: listar doações em memória
app.get('/debug/donations', (_req, res) => {
  const out = [];
  for (const [id, r] of db.entries()) {
    out.push({
      donationId: id,
      status: r.status,
      amount: r.amount,
      veopagTxId: r.veopagTxId,
      createdAtUtc: r.createdAtUtc
    });
  }
  res.json({ count: out.length, items: out });
});

// 1) Criar doação — gera PIX + UTMify: waiting_payment
app.post('/donations', async (req, res) => {
  try {
    const amount = Number(req.body?.amount);
    if (!Number.isFinite(amount) || amount <= 0) {
      return res.status(400).json({ error: 'amount inválido' });
    }

    const utm = req.body?.utm || null; // {source, medium, campaign, content, term}
    const donationId = crypto.randomUUID();
    const externalId = `donation_${donationId}`;

    // cria cobrança PIX na Veopag
    const qr = await createDeposit({ amount, externalId });

    // guarda o pedido localmente
    const createdAtUtc = toUtcString();
    db.set(donationId, {
      amount,
      status: 'pending',
      veopagTxId: qr.transactionId, // importante p/ localizar no webhook oficial
      qrCodeUrl: qr.qrCodeUrl,
      copyPaste: qr.copyPaste,
      utm,
      createdAtUtc,
    });

    // Envia o "waiting_payment" à UTMify
    try {
      const clientIp = getClientIp(req);
      await sendUtmifyOrder({
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
        customerIp: clientIp,
      });
    } catch (e) {
      console.error('UTMify waiting_payment error:', e);
    }

    // retorna dados para o front
    res.status(201).json({
      donationId,
      qrCodeUrl: qr.qrCodeUrl, // pode ser EMV (textão)
      copyPaste: qr.copyPaste,  // EMV (se vier separado)
      expiresAt: qr.expiresAt,
    });
  } catch (e) {
    console.error('POST /donations error:', e);
    res.status(502).json({ error: String(e.message || e) });
  }
});

// 2) Consultar status
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

// 3) Webhook Veopag (OFICIAL) — usa transaction_id + status: COMPLETED
app.post('/webhooks/veopag', async (req, res) => {
  try {
    const ev = req.body; // { transaction_id, status, amount, type }

    // localizar doação pelo transaction_id
    let donationId = null;
    let row = null;
    for (const [id, rec] of db.entries()) {
      if (rec.veopagTxId === ev.transaction_id) {
        donationId = id;
        row = rec;
        break;
      }
    }

    if (!row) {
      return res.status(404).json({
        error: 'donation not found',
        received: ev
      });
    }

    if (ev.status === 'COMPLETED' && row.status !== 'paid') {
      row.status = 'paid';
      db.set(donationId, row);

      try {
        const clientIp = getClientIp(req);
        await sendUtmifyOrder({
          apiToken: process.env.UTMIFY_API_TOKEN,
          orderId: `donation_${donationId}`,
          status: 'paid',
          createdAtUtc: row.createdAtUtc, // mesmo createdAt
          approvedDateUtc: toUtcString(),
          amountInCents: Math.round(row.amount * 100),
          transactionId: row.veopagTxId,
          utm: row.utm,
          isTest: false,
          customerEmail: 'anon@donations.local',
          customerIp: clientIp,
        });
      } catch (e) {
        console.error('UTMify paid error:', e);
      }
    }

    res.json({ received: true });
  } catch (e) {
    console.error('Webhook error:', e);
    res.status(500).json({ error: String(e.message || e) });
  }
});

// 4) (Opcional) Fallback para sincronizar com a Veopag
app.post('/donations/:id/sync', async (req, res) => {
  try {
    const row = db.get(req.params.id);
    if (!row?.veopagTxId) return res.status(404).json({ error: 'not found' });

    const st = await getDepositStatus(row.veopagTxId);
    if (st === 'COMPLETED' && row.status !== 'paid') {
      row.status = 'paid';
      db.set(req.params.id, row);

      try {
        const clientIp = getClientIp(req);
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
          customerIp: clientIp,
        });
      } catch (e) {
        console.error('UTMify paid (sync) error:', e);
      }
    }

    res.json({ donationId: req.params.id, status: row.status });
  } catch (e) {
    res.status(502).json({ error: String(e.message || e) });
  }
});

/* =========================
   Start
========================= */
const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`API up on :${port}`));
