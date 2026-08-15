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
    const error = new Error('Потрібен вхід у профіль.');
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
  if (url.searchParams.get('all') === '1') {
    const rows = await env.DB.prepare(
      `SELECT id, created_at, template_id, template_name, text_values, is_read, sort_order
       FROM cards
       WHERE user_id = ?
       ORDER BY created_at DESC`,
    ).bind(user.id).all();
    const items = (rows.results || []).map(parseCardRow);
    return json({ total: items.length, items });
  }

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

async function handleCardCounts(env, user) {
  const rows = await env.DB.prepare(
    'SELECT template_id, COUNT(*) AS total FROM cards WHERE user_id = ? GROUP BY template_id',
  ).bind(user.id).all();
  const counts = {};
  (rows.results || []).forEach((row) => {
    counts[row.template_id] = Number(row.total) || 0;
  });
  return json({ counts });
}

function cardPayload(body, fallbackId) {
  const textValues = body.text_values || body.textValues || {};
  return {
    id: String(body.id || fallbackId || crypto.randomUUID()),
    created_at: String(body.created_at || body.createdAt || new Date().toISOString()),
    template_id: String(body.template_id || body.templateId || 'thought'),
    template_name: String(body.template_name || body.templateName || 'Запис'),
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
  if (!items.length) return json({ error: 'Немає записів для перенесення.' }, 400);

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
  if (!existing) return json({ error: 'Запис не знайдено.' }, 404);

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
  if (!result.meta?.changes) return json({ error: 'Запис не знайдено.' }, 404);
  return json({ ok: true });
}

async function handleCreateShare(env, request) {
  const body = await readJson(request);
  const slug = String(body.slug || '').trim();
  if (!slug) return json({ error: 'Немає коду для посилання.' }, 400);
  const textValues = JSON.stringify(body.text_values || body.textValues || {});
  await env.DB.prepare(
    `INSERT INTO shared_cards (slug, created_at, template_id, template_name, description, text_values)
     VALUES (?, ?, ?, ?, ?, ?)`,
  ).bind(
    slug,
    new Date().toISOString(),
    String(body.template_id || body.templateId || 'thought'),
    String(body.template_name || body.templateName || 'Запис'),
    String(body.description || '').slice(0, 160),
    textValues,
  ).run();
  return json({ slug }, 201);
}

async function handleGetShare(env, slug) {
  const row = await env.DB.prepare(
    'SELECT slug, created_at, template_id, template_name, text_values FROM shared_cards WHERE slug = ?',
  ).bind(slug).first();
  if (!row) return json({ error: 'Запис не знайдено.' }, 404);
  return json({ item: parseCardRow({ ...row, id: row.slug || row.id }) });
}

function decodeXmlEntities(value) {
  return String(value || '')
    .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1')
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&apos;/g, "'")
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&#(\d+);/g, (_, code) => String.fromCharCode(Number(code)))
    .replace(/&#x([0-9a-f]+);/gi, (_, code) => String.fromCharCode(parseInt(code, 16)));
}

function unwrapNewsUrl(rawUrl) {
  const value = String(rawUrl || '').trim();
  if (!value) return '';
  try {
    const parsed = new URL(value);
    const nested = parsed.searchParams.get('url') || parsed.searchParams.get('q');
    if (nested && /^https?:\/\//i.test(nested) && !/bing\.com|google\.com|rss2json/i.test(nested)) {
      return nested;
    }
  } catch (error) {
    // Keep the original URL.
  }
  return value;
}

function stripHtml(value) {
  return decodeXmlEntities(value)
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function firstTag(block, names) {
  for (const name of names) {
    const match = block.match(new RegExp(`<${name}(?:\\s[^>]*)?>([\\s\\S]*?)</${name}>`, 'i'));
    if (match) return decodeXmlEntities(match[1]).trim();
  }
  return '';
}

function firstAttr(block, tagName, attrName) {
  const match = block.match(new RegExp(`<${tagName}[^>]*\\s${attrName}=["']([^"']+)["']`, 'i'));
  return match ? decodeXmlEntities(match[1]).trim() : '';
}

function extractImage(block) {
  const fromMedia = firstAttr(block, 'media:content', 'url')
    || firstAttr(block, 'media:thumbnail', 'url')
    || firstAttr(block, 'enclosure', 'url');
  if (fromMedia && /^https?:\/\//i.test(fromMedia)) return fromMedia;
  const html = firstTag(block, ['description', 'content:encoded', 'summary', 'content']);
  const img = html.match(/<img[^>]+src=["']([^"']+)["']/i);
  if (img && /^https?:\/\//i.test(img[1])) return img[1];
  return '';
}

function parseFeedItems(xml, sourceName) {
  const chunks = xml.match(/<item[\s\S]*?<\/item>/gi) || xml.match(/<entry[\s\S]*?<\/entry>/gi) || [];
  return chunks.map((block) => {
    const title = stripHtml(firstTag(block, ['title']));
    const url = unwrapNewsUrl(firstTag(block, ['link']) || firstAttr(block, 'link', 'href') || firstTag(block, ['guid']));
    const description = stripHtml(firstTag(block, ['description', 'content:encoded', 'summary', 'content'])).slice(0, 280);
    const publishedAt = firstTag(block, ['pubDate', 'published', 'updated', 'dc:date']);
    const source = stripHtml(firstTag(block, ['source'])) || sourceName;
    return {
      title,
      url,
      description,
      image: extractImage(block),
      source,
      publishedAt,
    };
  }).filter((item) => item.title && /^https?:\/\//i.test(item.url));
}

async function fetchFeed(feed) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 10000);
  try {
    const response = await fetch(feed.url, {
      signal: controller.signal,
      redirect: 'follow',
      headers: {
        Accept: 'application/rss+xml, application/atom+xml, application/xml, text/xml;q=0.9, */*;q=0.8',
        'Accept-Language': 'uk-UA,uk;q=0.9,en;q=0.6',
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
      },
    });
    if (!response.ok) return [];
    const body = await response.text();
    const trimmed = body.trim();
    if (trimmed.startsWith('{')) {
      try {
        const data = JSON.parse(trimmed);
        const rows = Array.isArray(data.items) ? data.items : [];
        return rows.map((row) => ({
          title: stripHtml(row.title || ''),
          url: unwrapNewsUrl(row.link || row.url || ''),
          description: stripHtml(row.description || row.content || '').slice(0, 280),
          image: row.thumbnail || row.enclosure?.link || '',
          source: stripHtml(row.author || row.source || feed.name),
          publishedAt: row.pubDate || row.published || '',
        })).filter((item) => item.title && /^https?:\/\//i.test(item.url));
      } catch (error) {
        return [];
      }
    }
    if (!/<item[\s\S]*?<\/item>|<entry[\s\S]*?<\/entry>/i.test(body)) return [];
    return parseFeedItems(body, feed.name);
  } catch (error) {
    return [];
  } finally {
    clearTimeout(timer);
  }
}

function parseFlexibleDate(text) {
  const value = String(text || '');
  let match = value.match(/(\d{1,2})\.(\d{1,2})\.(\d{4})/);
  if (match) return `${match[3]}-${match[2].padStart(2, '0')}-${match[1].padStart(2, '0')}T12:00:00`;
  match = value.match(/(\d{4})[/.](\d{2})[/.](\d{2})/);
  if (match) return `${match[1]}-${match[2]}-${match[3]}T12:00:00`;
  match = value.match(/(\d{1,2})\.(\d{1,2})\.(\d{2})(?!\d)/);
  if (match) return `20${match[3]}-${match[2].padStart(2, '0')}-${match[1].padStart(2, '0')}T12:00:00`;
  return '';
}

async function fetchPageText(url) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 10000);
  try {
    const response = await fetch(url, {
      signal: controller.signal,
      redirect: 'follow',
      headers: {
        Accept: 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'uk-UA,uk;q=0.9,en;q=0.6',
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
      },
    });
    if (!response.ok) return '';
    return await response.text();
  } catch (error) {
    return '';
  } finally {
    clearTimeout(timer);
  }
}

function dedupeItems(items) {
  const byUrl = new Map();
  items.forEach((item) => {
    const key = item.url.replace(/[?#].*$/, '');
    if (!byUrl.has(key)) byUrl.set(key, item);
  });
  return [...byUrl.values()];
}

function interleaveBySource(groups) {
  const queues = groups
    .map((group) => [...group])
    .filter((group) => group.length);
  const items = [];
  let added = true;
  while (added) {
    added = false;
    queues.forEach((queue) => {
      if (!queue.length) return;
      items.push(queue.shift());
      added = true;
    });
  }
  return items;
}

async function fetchUpsiholoha() {
  const origin = 'https://upsihologa.com.ua';
  const html = await fetchPageText(`${origin}/`);
  const articles = html.match(/<article[\s\S]*?<\/article>/gi) || [];
  return dedupeItems(articles.map((block) => {
    const href = (block.match(/href="(\/article\/[^"]+)"/i) || [])[1] || '';
    const title = stripHtml((block.match(/aria-label="Читати статтю:\s*([^"]+)"/i) || [])[1]
      || (block.match(/<h[1-3][^>]*>([\s\S]*?)<\/h[1-3]>/i) || [])[1]
      || '');
    const description = stripHtml((block.match(/<p[^>]*>([\s\S]*?)<\/p>/i) || [])[1] || '').slice(0, 280);
    const image = absoluteUrl((block.match(/<img[^>]+src="([^"]+)"/i) || [])[1] || '', origin);
    if (!href || !title) return null;
    return {
      title,
      url: absoluteUrl(href, origin),
      description,
      image,
      source: 'У Психолога',
      publishedAt: parseFlexibleDate(block),
      section: 'materials',
    };
  }).filter(Boolean));
}

async function fetchQuiBlog() {
  const origin = 'https://www.qui.help';
  const pages = await Promise.all([
    fetchPageText(`${origin}/blog`),
    fetchPageText(`${origin}/blog/all-articles/`),
  ]);
  const items = [];
  pages.forEach((html) => {
    const starts = [...html.matchAll(/href="(\/blog\/[^"]+)" class="preview-block/gi)];
    starts.forEach((match) => {
      const href = match[1] || '';
      if (!href || /\/blog\/(all-articles|category)\b/i.test(href)) return;
      const block = html.slice(match.index, match.index + 4500);
      const title = stripHtml((block.match(/class="prev-title">([\s\S]*?)<\/p>/i) || [])[1]
        || ((block.match(/alt="([^"]+)"/i) || [])[1] || '').replace(/^Ілюстрація статті$/i, '')
        || '');
      const description = stripHtml((block.match(/class="prev-text">([\s\S]*?)<\/p>/i) || [])[1] || '').slice(0, 280);
      const image = (block.match(/<img[^>]+src="([^"]+)"/i) || [])[1] || '';
      if (!title) return;
      items.push({
        title,
        url: absoluteUrl(href, origin),
        description,
        image,
        source: 'qui.help',
        publishedAt: parseFlexibleDate(block),
        section: 'materials',
      });
    });
  });
  return dedupeItems(items);
}

async function fetchDosebeBlog() {
  const origin = 'https://www.dosebe.com.ua';
  const html = await fetchPageText(`${origin}/blog`);
  const cards = html.split(/class="blog-article-card"/i).slice(1);
  return dedupeItems(cards.map((block) => {
    const href = (block.match(/href="(\/blog\/[^"]+)"/i) || [])[1] || '';
    const title = stripHtml((block.match(/blog-articles-heading">([\s\S]*?)<\/div>/i) || [])[1] || '');
    const description = stripHtml((block.match(/blog-article-descr">([\s\S]*?)<\/div>/i) || [])[1] || '').slice(0, 280);
    const image = (block.match(/<img[^>]+src="([^"]+)"/i) || [])[1] || '';
    if (!href || !title) return null;
    return {
      title,
      url: absoluteUrl(href, origin),
      description,
      image,
      source: 'До себе',
      publishedAt: parseFlexibleDate(block),
      section: 'materials',
    };
  }).filter(Boolean));
}

async function fetchMentolyBlog() {
  const origin = 'https://mentoly.com.ua';
  const html = await fetchPageText(`${origin}/blog`);
  const cards = html.split(/ArticleCard__root/i).slice(1);
  return dedupeItems(cards.map((block) => {
    const href = (block.match(/href="(\/blog\/[^"]+)"/i) || [])[1] || '';
    const title = stripHtml((block.match(/<h3[^>]*>([\s\S]*?)<\/h3>/i) || [])[1] || '');
    const image = absoluteUrl((block.match(/<img[^>]+src="([^"]+)"/i) || [])[1] || '', origin);
    if (!href || !title || /search=/i.test(href)) return null;
    return {
      title,
      url: absoluteUrl(href, origin),
      description: '',
      image,
      source: 'Mentoly',
      publishedAt: parseFlexibleDate(block),
      section: 'materials',
    };
  }).filter(Boolean));
}

function newestFirst(first, second) {
  const firstTime = Date.parse(first.publishedAt || '') || Number(first.sortId || 0);
  const secondTime = Date.parse(second.publishedAt || '') || Number(second.sortId || 0);
  return secondTime - firstTime;
}

function absoluteUrl(url, origin) {
  const value = String(url || '').trim();
  if (!value) return '';
  if (/^https?:\/\//i.test(value)) return value;
  if (value.startsWith('//')) return `https:${value}`;
  if (value.startsWith('/')) return `${origin}${value}`;
  return `${origin}/${value}`;
}

async function fetchHowareuSearch(type) {
  const origin = 'https://howareu.com';
  const items = [];
  let page = 1;
  let lastPage = 1;
  while (page <= lastPage && page <= 20) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 10000);
    try {
      const response = await fetch(`${origin}/api/search?type=${encodeURIComponent(type)}&per_page=50&page=${page}`, {
        signal: controller.signal,
        redirect: 'follow',
        headers: {
          Accept: 'application/json',
          'Accept-Language': 'uk-UA,uk;q=0.9',
          'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
        },
      });
      if (!response.ok) break;
      const data = await response.json();
      lastPage = Number(data.last_page || page);
      const rows = Array.isArray(data.data) ? data.data : [];
      rows.forEach((row) => {
        const title = stripHtml(row.title || '');
        const url = absoluteUrl(row.url, origin);
        if (!title || !/^https?:\/\//i.test(url)) return;
        items.push({
          title,
          url,
          description: stripHtml(row.excerpt || row.content || '').slice(0, 280),
          image: absoluteUrl(typeof row.image === 'string' ? row.image : row.image?.url, origin),
          source: 'Ти як?',
          publishedAt: row.published_at || row.published || row.created_at || '',
          sortId: Number(row.id || 0),
        });
      });
    } catch (error) {
      break;
    } finally {
      clearTimeout(timer);
    }
    page += 1;
  }
  return items;
}

async function fetchHowareuSelfHelp() {
  const origin = 'https://howareu.com';
  const items = [];
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 10000);
  try {
    const response = await fetch(`${origin}/self-help`, {
      signal: controller.signal,
      redirect: 'follow',
      headers: {
        Accept: 'text/html',
        'Accept-Language': 'uk-UA,uk;q=0.9',
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
      },
    });
    if (response.ok) {
      const html = await response.text();
      const cards = html.match(/<a href="https:\/\/howareu\.com\/[^"]+"[^>]*class="organizations-card"[\s\S]*?<\/a>/gi) || [];
      cards.forEach((block) => {
        const href = (block.match(/href="(https:\/\/howareu\.com\/[^"]+)"/i) || [])[1] || '';
        const title = stripHtml((block.match(/organizations-card-title">([\s\S]*?)<\/div>/i) || [])[1] || '');
        const description = stripHtml((block.match(/organizations-card-descr">([\s\S]*?)<\/div>/i) || [])[1] || '').slice(0, 280);
        const imageRaw = ((block.match(/background-image:\s*url\(([^)]+)\)/i) || [])[1] || '').replace(/['"]/g, '');
        if (!title || !href) return;
        items.push({
          title,
          url: href,
          description,
          image: absoluteUrl(imageRaw, origin),
          source: 'Ти як? Самодопомога',
          publishedAt: '',
          sortId: 0,
          section: 'selfHelp',
        });
      });
    }
  } catch (error) {
    // Hub HTML is optional if the pages API still works.
  } finally {
    clearTimeout(timer);
  }

  const pages = await fetchHowareuSearch('pages');
  const selfHelpPattern = /tekhnika|alhorytm|samodopomoh|stiikist|fizychne-zdorovia|korysne-myslennia|emotsiina-rehuliatsiia|efektyvna-povedinka|komponenty-zdorovia|vplyv-tryvaloho|navychky_samodopomoha|rozmova-iaka-ne-ranyt/i;
  const byUrl = new Map(items.map((item) => [item.url.replace(/[?#].*$/, ''), item]));
  pages.forEach((item) => {
    if (!selfHelpPattern.test(item.url)) return;
    const key = item.url.replace(/[?#].*$/, '');
    if (byUrl.has(key)) {
      const current = byUrl.get(key);
      if (!current.description && item.description) current.description = item.description;
      if (!current.image && item.image) current.image = item.image;
      if (!current.publishedAt && item.publishedAt) current.publishedAt = item.publishedAt;
      if (!current.sortId && item.sortId) current.sortId = item.sortId;
      return;
    }
    byUrl.set(key, { ...item, source: 'Ти як? Самодопомога', section: 'selfHelp' });
  });
  return [...byUrl.values()];
}

async function handleNews(request) {
  const requestUrl = new URL(request.url);
  const wantFresh = requestUrl.searchParams.has('fresh');
  const cache = caches.default;
  const cacheUrl = new URL(request.url);
  cacheUrl.searchParams.delete('fresh');
  cacheUrl.searchParams.set('v', 'uk-11');
  const cacheRequest = new Request(cacheUrl.toString(), { method: 'GET' });
  if (!wantFresh) {
    const cached = await cache.match(cacheRequest);
    if (cached) return cached;
  }

  const googleQueries = [
    'https://news.google.com/rss/search?q=%D0%BF%D1%81%D0%B8%D1%85%D0%BE%D0%BB%D0%BE%D0%B3%D1%96%D1%8F&hl=uk&gl=UA&ceid=UA:uk',
    'https://news.google.com/rss/search?q=%D0%BF%D1%81%D0%B8%D1%85%D0%BE%D1%82%D0%B5%D1%80%D0%B0%D0%BF%D1%96%D1%8F&hl=uk&gl=UA&ceid=UA:uk',
    'https://news.google.com/rss/search?q=%22%D0%BC%D0%B5%D0%BD%D1%82%D0%B0%D0%BB%D1%8C%D0%BD%D0%B5+%D0%B7%D0%B4%D0%BE%D1%80%D0%BE%D0%B2%27%D1%8F%22&hl=uk&gl=UA&ceid=UA:uk',
  ];
  const feeds = [
    ...googleQueries.map((url) => ({ name: 'Google News', url, trustSearch: true })),
    ...googleQueries.map((url) => ({
      name: 'Google News',
      url: `https://api.rss2json.com/v1/api.json?rss_url=${encodeURIComponent(url)}`,
      trustSearch: true,
    })),
    {
      name: 'Bing News',
      url: 'https://www.bing.com/news/search?q=%D0%BF%D1%81%D0%B8%D1%85%D0%BE%D0%BB%D0%BE%D0%B3%D1%96%D1%8F+%D0%A3%D0%BA%D1%80%D0%B0%D1%97%D0%BD%D0%B0&format=RSS&mkt=uk-UA',
      trustSearch: true,
    },
    {
      name: 'Bing News',
      url: 'https://www.bing.com/news/search?q=%D0%BF%D1%81%D0%B8%D1%85%D0%BE%D1%82%D0%B5%D1%80%D0%B0%D0%BF%D1%96%D1%8F&format=RSS&mkt=uk-UA',
      trustSearch: true,
    },
    {
      name: 'Bing News',
      url: 'https://www.bing.com/news/search?q=%D0%BC%D0%B5%D0%BD%D1%82%D0%B0%D0%BB%D1%8C%D0%BD%D0%B5+%D0%B7%D0%B4%D0%BE%D1%80%D0%BE%D0%B2%27%D1%8F&format=RSS&mkt=uk-UA',
      trustSearch: true,
    },
    {
      name: 'Українська правда. Життя',
      url: 'https://life.pravda.com.ua/rss/',
      trustSearch: false,
    },
    {
      name: 'BBC News Україна',
      url: 'https://feeds.bbci.co.uk/ukrainian/rss.xml',
      trustSearch: false,
    },
    {
      name: 'Радіо Свобода',
      url: 'https://www.radiosvoboda.org/api/zrqiteuuir',
      trustSearch: false,
    },
    {
      name: 'Суспільне',
      url: 'https://suspilne.media/rss/all.rss',
      trustSearch: false,
    },
    {
      name: 'Освіта.ua',
      url: 'https://www.osvita.ua/rss/',
      trustSearch: false,
    },
  ];

  const topicPattern = /психолог|психотерап|ментальн|психічн\w*\s+здоров|нейропсихол|психосомат|психоедукац|психоаналіз/i;

  function isUkrainianText(text) {
    return (String(text).match(/[А-Яа-яІіЇїЄєҐґ]/g) || []).length >= 8;
  }

  const [howareuMaterials, howareuNews, howareuSelfHelp, upsiItems, quiItems, dosebeItems, mentolyItems, ...groups] = await Promise.all([
    fetchHowareuSearch('materials'),
    fetchHowareuSearch('news'),
    fetchHowareuSelfHelp(),
    fetchUpsiholoha(),
    fetchQuiBlog(),
    fetchDosebeBlog(),
    fetchMentolyBlog(),
    ...feeds.map(async (feed) => {
      const items = await fetchFeed(feed);
      return items.filter((item) => {
        const text = `${item.title} ${item.description}`;
        if (!isUkrainianText(text)) return false;
        if (feed.trustSearch) return /психолог|психотерап|ментальн/i.test(text);
        return topicPattern.test(text);
      });
    }),
  ]);

  const selfHelp = howareuSelfHelp
    .map((item) => ({ ...item, section: 'selfHelp', source: item.source || 'Ти як? Самодопомога' }))
    .sort(newestFirst);
  const howareuGroup = [...howareuNews, ...howareuMaterials]
    .map((item) => ({ ...item, section: 'materials', source: item.source || 'Ти як?' }))
    .sort(newestFirst);
  const rssGroup = groups.flat().map((item) => ({ ...item, section: 'materials' })).sort(newestFirst);
  const blogGroups = [upsiItems, quiItems, dosebeItems, mentolyItems].map((group) => [...group].sort(newestFirst));
  const materials = interleaveBySource([howareuGroup, ...blogGroups, rssGroup]);
  const selfHelpUrls = new Set(selfHelp.map((item) => item.url.replace(/[?#].*$/, '')));
  const byUrl = new Map();
  [...selfHelp, ...materials].forEach((item) => {
    const key = `${item.title}::${item.url.replace(/[?#].*$/, '')}`;
    if (selfHelpUrls.has(item.url.replace(/[?#].*$/, ''))) {
      item.section = 'selfHelp';
    }
    if (!byUrl.has(key)) byUrl.set(key, item);
  });
  const merged = [...byUrl.values()];
  const items = [
    ...merged.filter((item) => item.section === 'selfHelp').sort(newestFirst),
    ...merged.filter((item) => item.section !== 'selfHelp'),
  ].slice(0, 320);

  const response = json({ items }, 200, { 'Cache-Control': wantFresh ? 'no-store' : 'public, max-age=300' });
  if (!wantFresh) {
    try {
      await cache.put(cacheRequest, response.clone());
    } catch (error) {
      // Cache is optional.
    }
  }
  return response;
}

export async function onRequest(context) {
  const { request, env } = context;
  const parts = getPathParts(context);
  const method = request.method.toUpperCase();

  try {
    if (parts[0] === 'news' && method === 'GET') return handleNews(request);
    if (!env.DB) return json({ error: 'Хмарну базу ще не підключено.' }, 500);

    if (parts[0] === 'auth' && parts[1] === 'signup' && method === 'POST') return handleSignup(env, request);
    if (parts[0] === 'auth' && parts[1] === 'signin' && method === 'POST') return handleSignin(env, request);
    if (parts[0] === 'auth' && parts[1] === 'signout' && method === 'POST') return handleSignout(env, request);
    if (parts[0] === 'auth' && parts[1] === 'me' && method === 'GET') return handleMe(env, request);

    if (parts[0] === 'share' && method === 'POST' && parts.length === 1) return handleCreateShare(env, request);
    if (parts[0] === 'share' && method === 'GET' && parts[1]) return handleGetShare(env, parts[1]);

    if (parts[0] === 'cards') {
      const user = await requireUser(env, request);
      if (parts[1] === 'counts' && method === 'GET') return handleCardCounts(env, user);
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
