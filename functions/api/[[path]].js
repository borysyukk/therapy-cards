const SESSION_COOKIE = 'tc_session';
const SESSION_DAYS = 30;
const PBKDF2_ITERATIONS = 12000;

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      ...headers,
    },
  });
}

function getPathParts(context) {
  const path = context.params.path;
  if (!path) return [];
  return Array.isArray(path) ? path : [path];
}

function parseCookies(request) {
  const header = request.headers.get('Cookie') || '';
  const cookies = {};
  header.split(';').forEach((part) => {
    const [name, ...rest] = part.trim().split('=');
    if (!name) return;
    cookies[name] = decodeURIComponent(rest.join('='));
  });
  return cookies;
}

function sessionCookie(token, maxAgeSeconds) {
  const parts = [
    `${SESSION_COOKIE}=${encodeURIComponent(token)}`,
    'Path=/',
    'HttpOnly',
    'Secure',
    'SameSite=Lax',
  ];
  if (maxAgeSeconds === 0) parts.push('Max-Age=0');
  else parts.push(`Max-Age=${maxAgeSeconds}`);
  return parts.join('; ');
}

function bytesToBase64(bytes) {
  let binary = '';
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return btoa(binary);
}

function base64ToBytes(value) {
  const binary = atob(value);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

async function hashPassword(password, salt) {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: PBKDF2_ITERATIONS },
    key,
    256,
  );
  return `pbkdf2$${PBKDF2_ITERATIONS}$${bytesToBase64(salt)}$${bytesToBase64(new Uint8Array(bits))}`;
}

async function verifyPassword(password, stored) {
  const [scheme, iterationsValue, saltB64, hashB64] = String(stored || '').split('$');
  if (scheme !== 'pbkdf2' || !saltB64 || !hashB64) return false;
  const encoder = new TextEncoder();
  const salt = base64ToBytes(saltB64);
  const iterations = Number(iterationsValue) || PBKDF2_ITERATIONS;
  const key = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
    key,
    256,
  );
  const actual = bytesToBase64(new Uint8Array(bits));
  return actual === hashB64;
}

function randomToken() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return [...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

function normalizeEmail(value) {
  return String(value || '').trim().toLowerCase();
}

async function readJson(request) {
  try {
    return await request.json();
  } catch {
    return {};
  }
}

function parseCardRow(row) {
  if (!row) return null;
  let textValues = {};
  try {
    textValues = JSON.parse(row.text_values || '{}');
  } catch {
    textValues = {};
  }
  return {
    id: row.id,
    created_at: row.created_at,
    template_id: row.template_id,
    template_name: row.template_name,
    text_values: textValues,
    is_read: Boolean(row.is_read),
    sort_order: row.sort_order,
  };
}

async function getUserFromSession(env, request) {
  const token = parseCookies(request)[SESSION_COOKIE];
  if (!token) return null;
  const now = Date.now();
  const row = await env.DB.prepare(
    'SELECT users.id, users.email FROM sessions JOIN users ON users.id = sessions.user_id WHERE sessions.token = ? AND sessions.expires_at > ?',
  ).bind(token, now).first();
  return row || null;
}

async function requireUser(env, request) {
  const user = await getUserFromSession(env, request);
  if (!user) {
    const error = new Error('Потрібен вхід в акаунт.');
    error.status = 401;
    throw error;
  }
  return user;
}

async function createSession(env, userId) {
  const token = randomToken();
  const expiresAt = Date.now() + SESSION_DAYS * 24 * 60 * 60 * 1000;
  await env.DB.prepare('INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)')
    .bind(token, userId, expiresAt)
    .run();
  return { token, expiresAt };
}

async function handleSignup(env, request) {
  const body = await readJson(request);
  const email = normalizeEmail(body.email);
  const password = String(body.password || '');
  if (!email || !email.includes('@')) return json({ error: 'Введіть коректний email.' }, 400);
  if (password.length < 8) return json({ error: 'Пароль має мати щонайменше 8 символів.' }, 400);

  const existing = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email).first();
  if (existing) return json({ error: 'Цей email уже зареєстрований.' }, 409);

  const salt = new Uint8Array(16);
  crypto.getRandomValues(salt);
  const user = {
    id: crypto.randomUUID(),
    email,
    password_hash: await hashPassword(password, salt),
    created_at: new Date().toISOString(),
  };
  await env.DB.prepare('INSERT INTO users (id, email, password_hash, created_at) VALUES (?, ?, ?, ?)')
    .bind(user.id, user.email, user.password_hash, user.created_at)
    .run();
  const session = await createSession(env, user.id);
  return json(
    { user: { id: user.id, email: user.email } },
    201,
    { 'Set-Cookie': sessionCookie(session.token, SESSION_DAYS * 24 * 60 * 60) },
  );
}

async function handleSignin(env, request) {
  const body = await readJson(request);
  const email = normalizeEmail(body.email);
  const password = String(body.password || '');
  if (!email || !password) return json({ error: 'Введіть email і пароль.' }, 400);

  const user = await env.DB.prepare('SELECT id, email, password_hash FROM users WHERE email = ?').bind(email).first();
  if (!user || !(await verifyPassword(password, user.password_hash))) {
    return json({ error: 'Невірний email або пароль.' }, 401);
  }
  const session = await createSession(env, user.id);
  return json(
    { user: { id: user.id, email: user.email } },
    200,
    { 'Set-Cookie': sessionCookie(session.token, SESSION_DAYS * 24 * 60 * 60) },
  );
}

async function handleSignout(env, request) {
  const token = parseCookies(request)[SESSION_COOKIE];
  if (token) {
    await env.DB.prepare('DELETE FROM sessions WHERE token = ?').bind(token).run();
  }
  return json({ ok: true }, 200, { 'Set-Cookie': sessionCookie('', 0) });
}

async function handleMe(env, request) {
  const user = await getUserFromSession(env, request);
  if (!user) return json({ user: null });
  return json({ user: { id: user.id, email: user.email } });
}

async function handleListCards(env, request, user) {
  const url = new URL(request.url);
  const templateId = url.searchParams.get('template_id') || 'thought';
  const page = Math.max(1, Number(url.searchParams.get('page')) || 1);
  const pageSize = Math.min(50, Math.max(1, Number(url.searchParams.get('page_size')) || 12));
  const offset = (page - 1) * pageSize;

  const totalRow = await env.DB.prepare(
    'SELECT COUNT(*) AS total FROM cards WHERE user_id = ? AND template_id = ?',
  ).bind(user.id, templateId).first();
  const rows = await env.DB.prepare(
    `SELECT id, created_at, template_id, template_name, text_values, is_read, sort_order
     FROM cards
     WHERE user_id = ? AND template_id = ?
     ORDER BY CASE WHEN sort_order IS NULL THEN 1 ELSE 0 END, sort_order ASC, created_at DESC
     LIMIT ? OFFSET ?`,
  ).bind(user.id, templateId, pageSize, offset).all();

  return json({
    total: Number(totalRow?.total || 0),
    items: (rows.results || []).map(parseCardRow),
  });
}

function cardPayload(body, fallbackId) {
  const textValues = body.text_values || body.textValues || {};
  return {
    id: String(body.id || fallbackId || crypto.randomUUID()),
    created_at: String(body.created_at || body.createdAt || new Date().toISOString()),
    template_id: String(body.template_id || body.templateId || 'thought'),
    template_name: String(body.template_name || body.templateName || 'Картка'),
    text_values: JSON.stringify(textValues),
    is_read: body.is_read || body.isRead ? 1 : 0,
    sort_order: Number.isFinite(body.sort_order) ? body.sort_order : Number(body.sortOrder),
  };
}

async function handleCreateCard(env, request, user) {
  const body = await readJson(request);
  const card = cardPayload(body);
  await env.DB.prepare(
    `INSERT INTO cards (id, user_id, created_at, template_id, template_name, text_values, is_read, sort_order)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
  ).bind(card.id, user.id, card.created_at, card.template_id, card.template_name, card.text_values, card.is_read, Number.isFinite(card.sort_order) ? card.sort_order : null).run();
  return json({ item: parseCardRow({ ...card, is_read: card.is_read }) }, 201);
}

async function handleCreateCardsBatch(env, request, user) {
  const body = await readJson(request);
  const items = Array.isArray(body.items) ? body.items : [];
  if (!items.length) return json({ error: 'Немає карток для перенесення.' }, 400);

  const statements = items.map((item) => {
    const card = cardPayload(item);
    return env.DB.prepare(
      `INSERT OR REPLACE INTO cards (id, user_id, created_at, template_id, template_name, text_values, is_read, sort_order)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    ).bind(card.id, user.id, card.created_at, card.template_id, card.template_name, card.text_values, card.is_read, Number.isFinite(card.sort_order) ? card.sort_order : null);
  });
  await env.DB.batch(statements);
  return json({ saved: items.length });
}

async function handleUpdateCard(env, request, user, id) {
  const existing = await env.DB.prepare('SELECT * FROM cards WHERE id = ? AND user_id = ?').bind(id, user.id).first();
  if (!existing) return json({ error: 'Картку не знайдено.' }, 404);

  const body = await readJson(request);
  const next = {
    template_id: body.template_id || body.templateId || existing.template_id,
    template_name: body.template_name || body.templateName || existing.template_name,
    text_values: body.text_values || body.textValues
      ? JSON.stringify(body.text_values || body.textValues)
      : existing.text_values,
    is_read: body.is_read === undefined && body.isRead === undefined
      ? existing.is_read
      : (body.is_read || body.isRead ? 1 : 0),
    sort_order: body.sort_order === undefined && body.sortOrder === undefined
      ? existing.sort_order
      : (Number.isFinite(body.sort_order) ? body.sort_order : Number(body.sortOrder)),
  };

  await env.DB.prepare(
    `UPDATE cards
     SET template_id = ?, template_name = ?, text_values = ?, is_read = ?, sort_order = ?
     WHERE id = ? AND user_id = ?`,
  ).bind(next.template_id, next.template_name, next.text_values, next.is_read, Number.isFinite(next.sort_order) ? next.sort_order : null, id, user.id).run();
  return json({ ok: true });
}

async function handleReorderCards(env, request, user) {
  const body = await readJson(request);
  const items = Array.isArray(body.items) ? body.items : [];
  if (!items.length) return json({ ok: true });
  const statements = items.map((item) => (
    env.DB.prepare('UPDATE cards SET sort_order = ? WHERE id = ? AND user_id = ?')
      .bind(Number(item.sort_order ?? item.sortOrder), String(item.id), user.id)
  ));
  await env.DB.batch(statements);
  return json({ ok: true });
}

async function handleDeleteCard(env, user, id) {
  const result = await env.DB.prepare('DELETE FROM cards WHERE id = ? AND user_id = ?').bind(id, user.id).run();
  if (!result.meta?.changes) return json({ error: 'Картку не знайдено.' }, 404);
  return json({ ok: true });
}

async function handleCreateShare(env, request) {
  const body = await readJson(request);
  const slug = String(body.slug || '').trim();
  if (!slug) return json({ error: 'Немає slug для лінка.' }, 400);
  const textValues = JSON.stringify(body.text_values || body.textValues || {});
  await env.DB.prepare(
    `INSERT INTO shared_cards (slug, created_at, template_id, template_name, description, text_values)
     VALUES (?, ?, ?, ?, ?, ?)`,
  ).bind(
    slug,
    new Date().toISOString(),
    String(body.template_id || body.templateId || 'thought'),
    String(body.template_name || body.templateName || 'Картка'),
    String(body.description || '').slice(0, 160),
    textValues,
  ).run();
  return json({ slug }, 201);
}

async function handleGetShare(env, slug) {
  const row = await env.DB.prepare(
    'SELECT slug, created_at, template_id, template_name, text_values FROM shared_cards WHERE slug = ?',
  ).bind(slug).first();
  if (!row) return json({ error: 'Картку не знайдено.' }, 404);
  return json({ item: parseCardRow({ ...row, id: row.slug || row.id }) });
}

export async function onRequest(context) {
  const { request, env } = context;
  const parts = getPathParts(context);
  const method = request.method.toUpperCase();

  try {
    if (!env.DB) return json({ error: 'Хмарну базу ще не підключено.' }, 500);

    if (parts[0] === 'auth' && parts[1] === 'signup' && method === 'POST') return handleSignup(env, request);
    if (parts[0] === 'auth' && parts[1] === 'signin' && method === 'POST') return handleSignin(env, request);
    if (parts[0] === 'auth' && parts[1] === 'signout' && method === 'POST') return handleSignout(env, request);
    if (parts[0] === 'auth' && parts[1] === 'me' && method === 'GET') return handleMe(env, request);

    if (parts[0] === 'share' && method === 'POST' && parts.length === 1) return handleCreateShare(env, request);
    if (parts[0] === 'share' && method === 'GET' && parts[1]) return handleGetShare(env, parts[1]);

    if (parts[0] === 'cards') {
      const user = await requireUser(env, request);
      if (parts.length === 1 && method === 'GET') return handleListCards(env, request, user);
      if (parts.length === 1 && method === 'POST') return handleCreateCard(env, request, user);
      if (parts[1] === 'batch' && method === 'POST') return handleCreateCardsBatch(env, request, user);
      if (parts[1] === 'reorder' && method === 'POST') return handleReorderCards(env, request, user);
      if (parts[1] && method === 'PATCH') return handleUpdateCard(env, request, user, parts[1]);
      if (parts[1] && method === 'DELETE') return handleDeleteCard(env, user, parts[1]);
    }

    return json({ error: 'Маршрут не знайдено.' }, 404);
  } catch (error) {
    const status = error.status || 500;
    return json({ error: status === 500 ? 'Сталася помилка сервера.' : error.message }, status);
  }
}
