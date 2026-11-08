import 'dotenv/config';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import session from 'express-session';
import connectPgSimple from 'connect-pg-simple';
import pg from 'pg';
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const {
  DATABASE_URL,
  SESSION_SECRET,
  PORT = 3000,
  RP_ID = 'localhost',
  RP_NAME = 'Passkey Demo',
  ORIGIN = 'http://localhost:3000',
  PLATFORM_ONLY = 'true',
  NODE_ENV,
} = process.env;

if (!DATABASE_URL || !SESSION_SECRET) {
  console.error('DATABASE_URL と SESSION_SECRET を .env に設定してください。');
  process.exit(1);
}

const isProd = NODE_ENV === 'production';
const USERNAME_RE = /^[a-z0-9_.-]{3,32}$/;

// ---------- DB ----------
const pool = new pg.Pool({ connectionString: DATABASE_URL });
await pool.query(fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8'));

// ---------- App / Session ----------
const app = express();
if (isProd) app.set('trust proxy', 1);
app.use(express.json());

const PgStore = connectPgSimple(session);
app.use(
  session({
    store: new PgStore({ pool, createTableIfMissing: true }),
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: 'lax',
      secure: isProd, // 本番は HTTPS 必須
      maxAge: 1000 * 60 * 60 * 24 * 7,
    },
  }),
);

app.use(express.static(path.join(__dirname, 'public')));

// セッション固定化攻撃対策: ログイン成功時にセッションIDを作り直す
const startSession = (req, userId) =>
  new Promise((resolve, reject) => {
    req.session.regenerate((err) => {
      if (err) return reject(err);
      req.session.userId = userId;
      req.session.save((err2) => (err2 ? reject(err2) : resolve()));
    });
  });

const requireAuth = (req, res, next) =>
  req.session.userId ? next() : res.status(401).json({ error: 'ログインが必要です。' });

// ---------- 登録 (Passkey 作成) ----------
// 新規ユーザー登録、またはログイン中ユーザーが Passkey を追加する
app.post('/api/register/options', async (req, res) => {
  const username = String(req.body?.username ?? '').trim().toLowerCase();
  if (!USERNAME_RE.test(username)) {
    return res
      .status(400)
      .json({ error: 'ユーザー名は 3〜32 文字の半角英数字と _ . - が使えます。' });
  }

  const { rows } = await pool.query('select id from users where username = $1', [username]);
  const existing = rows[0];

  let userId;
  let excludeCredentials = [];

  if (existing) {
    // 既存ユーザーへの追加は本人（ログイン済み）のみ。未ログインでの乗っ取りを防ぐ
    if (req.session.userId !== existing.id) {
      return res.status(409).json({ error: 'このユーザー名は使用できません。' });
    }
    userId = existing.id;
    const creds = await pool.query('select id, transports from credentials where user_id = $1', [userId]);
    excludeCredentials = creds.rows.map((c) => ({ id: c.id, transports: c.transports ?? undefined }));
  } else {
    userId = crypto.randomUUID();
  }

  const options = await generateRegistrationOptions({
    rpName: RP_NAME,
    rpID: RP_ID,
    userName: username,
    userID: new TextEncoder().encode(userId),
    attestationType: 'none',
    excludeCredentials,
    authenticatorSelection: {
      residentKey: 'required', // Passkey (discoverable credential)
      userVerification: 'required', // Windows Hello の PIN/顔/指紋 を必須に
      ...(PLATFORM_ONLY === 'true' && { authenticatorAttachment: 'platform' }),
    },
  });

  req.session.registration = { challenge: options.challenge, userId, username, isNew: !existing };
  res.json(options);
});

app.post('/api/register/verify', async (req, res) => {
  const reg = req.session.registration;
  if (!reg) return res.status(400).json({ error: '登録セッションがありません。最初からやり直してください。' });
  delete req.session.registration;

  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response: req.body,
      expectedChallenge: reg.challenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
      requireUserVerification: true,
    });
  } catch (err) {
    console.error(err);
    return res.status(400).json({ error: 'Passkey の検証に失敗しました。' });
  }
  if (!verification.verified) return res.status(400).json({ error: 'Passkey の検証に失敗しました。' });

  const { credential, credentialDeviceType, credentialBackedUp } = verification.registrationInfo;

  const client = await pool.connect();
  try {
    await client.query('begin');
    if (reg.isNew) {
      await client.query('insert into users (id, username) values ($1, $2)', [reg.userId, reg.username]);
    }
    await client.query(
      `insert into credentials (id, user_id, public_key, counter, transports, device_type, backed_up)
       values ($1, $2, $3, $4, $5, $6, $7)`,
      [
        credential.id,
        reg.userId,
        Buffer.from(credential.publicKey),
        credential.counter,
        credential.transports ?? null,
        credentialDeviceType,
        credentialBackedUp,
      ],
    );
    await client.query('commit');
  } catch (err) {
    await client.query('rollback');
    if (err.code === '23505') return res.status(409).json({ error: 'このユーザー名は使用できません。' });
    throw err;
  } finally {
    client.release();
  }

  if (reg.isNew) await startSession(req, reg.userId);
  res.json({ verified: true, username: reg.username });
});

// ---------- ログイン (Passkey 認証) ----------
// ユーザー名不要。端末側に保存された Passkey から選ぶ (Windows Hello のダイアログ)
app.post('/api/login/options', async (req, res) => {
  const options = await generateAuthenticationOptions({
    rpID: RP_ID,
    userVerification: 'required',
  });
  req.session.authChallenge = options.challenge;
  res.json(options);
});

app.post('/api/login/verify', async (req, res) => {
  const expectedChallenge = req.session.authChallenge;
  delete req.session.authChallenge;
  if (!expectedChallenge) return res.status(400).json({ error: '認証セッションがありません。もう一度お試しください。' });

  const { rows } = await pool.query(
    `select c.id, c.user_id, c.public_key, c.counter, c.transports, u.username
       from credentials c join users u on u.id = c.user_id
      where c.id = $1`,
    [req.body?.id],
  );
  const row = rows[0];
  if (!row) return res.status(400).json({ error: '登録されていない Passkey です。' });

  let verification;
  try {
    verification = await verifyAuthenticationResponse({
      response: req.body,
      expectedChallenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
      requireUserVerification: true,
      credential: {
        id: row.id,
        publicKey: new Uint8Array(row.public_key),
        counter: Number(row.counter),
        transports: row.transports ?? undefined,
      },
    });
  } catch (err) {
    console.error(err);
    return res.status(400).json({ error: '認証に失敗しました。' });
  }
  if (!verification.verified) return res.status(400).json({ error: '認証に失敗しました。' });

  await pool.query('update credentials set counter = $1, last_used_at = now() where id = $2', [
    verification.authenticationInfo.newCounter,
    row.id,
  ]);

  await startSession(req, row.user_id);
  res.json({ verified: true, username: row.username });
});

// ---------- セッション ----------
app.get('/api/me', async (req, res) => {
  if (!req.session.userId) return res.json({ user: null });
  const { rows } = await pool.query('select id, username from users where id = $1', [req.session.userId]);
  res.json({ user: rows[0] ?? null });
});

app.get('/api/passkeys', requireAuth, async (req, res) => {
  const { rows } = await pool.query(
    `select id, device_type, backed_up, created_at, last_used_at
       from credentials where user_id = $1 order by created_at`,
    [req.session.userId],
  );
  res.json({ passkeys: rows });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('connect.sid');
    res.json({ ok: true });
  });
});

app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(500).json({ error: 'サーバーエラーが発生しました。' });
});

app.listen(PORT, () => console.log(`${ORIGIN} で起動しました (port ${PORT})`));
