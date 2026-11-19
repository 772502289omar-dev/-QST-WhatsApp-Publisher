import 'dotenv/config';
import express from 'express';
import session from 'express-session';
import connectPgSimple from 'connect-pg-simple';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import multer from 'multer';
import bcrypt from 'bcryptjs';
import { pool, query, initDb } from './src/db.js';
import { csrfProtection, requireAuth, makeCsrfToken, cleanText } from './src/security.js';

const app = express();
const PgStore = connectPgSimple(session);
const isProd = process.env.NODE_ENV === 'production';
if (isProd && (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32)) throw new Error('SESSION_SECRET must contain at least 32 characters in production.');
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 12 * 1024 * 1024, files: 3 } });

if (process.env.TRUST_PROXY === '1') app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(helmet({
  contentSecurityPolicy: { directives: {
    defaultSrc: ["'self'"], scriptSrc: ["'self'"],
    styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
    fontSrc: ["'self'", 'https://fonts.gstatic.com', 'data:'],
    imgSrc: ["'self'", 'data:', 'https:'], connectSrc: ["'self'"],
    objectSrc: ["'none'"], baseUri: ["'self'"], frameAncestors: ["'none'"]
  } }, crossOriginEmbedderPolicy: false
}));
app.use(express.json({ limit: '1mb' }));
app.use(session({
  store: new PgStore({ pool, tableName: 'user_sessions', createTableIfMissing: true }),
  name: 'qst.sid',
  secret: process.env.SESSION_SECRET || 'dev-only-change-this-before-deploy-please',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, secure: isProd, sameSite: 'lax', maxAge: 8 * 60 * 60 * 1000 }
}));
app.use('/api/login', rateLimit({ windowMs: 15 * 60 * 1000, limit: 8, standardHeaders: true, legacyHeaders: false }));
app.use('/api', (req, res, next) => {
  if (req.path === '/health' || req.path === '/csrf' || req.path === '/login') return next();
  return csrfProtection(req, res, next);
});
app.use(express.static('public', { extensions: ['html'] }));

const asyncRoute = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const notify = (kind, message) => query('INSERT INTO notifications(kind,message) VALUES($1,$2)', [kind, message]);
const getSetting = async key => (await query('SELECT value FROM app_settings WHERE key=$1', [key])).rows[0]?.value;

app.get('/api/health', (req, res) => res.json({ ok: true, name: 'QST WhatsApp Publisher', mode: 'manual_confirmation' }));
app.get('/api/csrf', (req, res) => {
  if (!req.session.csrfToken) req.session.csrfToken = makeCsrfToken();
  res.json({ token: req.session.csrfToken });
});
app.post('/api/login', asyncRoute(async (req, res) => {
  const username = cleanText(req.body?.username, 100);
  const password = String(req.body?.password ?? '');
  const found = await query('SELECT id,username,password_hash FROM managers WHERE username=$1', [username]);
  if (!found.rowCount || !(await bcrypt.compare(password, found.rows[0].password_hash))) {
    return res.status(401).json({ error: 'اسم المستخدم أو كلمة المرور غير صحيحة.' });
  }
  req.session.regenerate(err => {
    if (err) return res.status(500).json({ error: 'تعذر إنشاء جلسة الدخول.' });
    req.session.managerId = String(found.rows[0].id);
    req.session.username = found.rows[0].username;
    req.session.csrfToken = makeCsrfToken();
    req.session.save(saveErr => {
      if (saveErr) return res.status(500).json({ error: 'تعذر حفظ جلسة الدخول.' });
      res.json({ ok: true, username: found.rows[0].username, csrfToken: req.session.csrfToken });
    });
  });
}));
app.post('/api/logout', requireAuth, asyncRoute(async (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
}));
app.get('/api/me', requireAuth, (req, res) => res.json({ username: req.session.username }));

app.get('/api/dashboard', requireAuth, asyncRoute(async (req, res) => {
  const [groups, posts, deliveries, campaigns, last, unread] = await Promise.all([
    query('SELECT COUNT(*)::int AS total, COUNT(*) FILTER (WHERE selected AND is_active)::int AS selected FROM groups_manual WHERE is_active=true'),
    query('SELECT COUNT(*)::int AS total FROM posts'),
    query("SELECT COUNT(*) FILTER (WHERE status='sent_manual')::int AS sent, COUNT(*) FILTER (WHERE status='failed')::int AS failed, COUNT(*) FILTER (WHERE status='pending')::int AS pending FROM deliveries"),
    query("SELECT COUNT(*) FILTER (WHERE status IN ('queued','running','paused'))::int AS active FROM campaigns"),
    query('SELECT d.sent_at,g.name AS group_name,p.title AS post_title,d.status FROM deliveries d JOIN groups_manual g ON g.id=d.group_id JOIN campaigns c ON c.id=d.campaign_id JOIN posts p ON p.id=c.post_id WHERE d.sent_at IS NOT NULL ORDER BY d.sent_at DESC LIMIT 1'),
    query('SELECT COUNT(*)::int AS count FROM notifications WHERE is_read=false')
  ]);
  res.json({
    botStatus: 'manual_mode', whatsappStatus: 'not_linked',
    groups: groups.rows[0], posts: posts.rows[0], deliveries: deliveries.rows[0],
    activeCampaigns: campaigns.rows[0].active, lastDelivery: last.rows[0] || null,
    unreadNotifications: unread.rows[0].count
  });
}));

app.get('/api/groups', requireAuth, asyncRoute(async (req, res) => {
  const { rows } = await query('SELECT id,name,invite_url,note,selected,is_active,created_at FROM groups_manual ORDER BY name ASC');
  res.json(rows);
}));
app.post('/api/groups', requireAuth, asyncRoute(async (req, res) => {
  const name = cleanText(req.body?.name, 160);
  const invite = cleanText(req.body?.inviteUrl, 500);
  const note = cleanText(req.body?.note, 500);
  if (!name) return res.status(400).json({ error: 'اسم المجموعة مطلوب.' });
  if (invite && !/^https:\/\/(chat\.whatsapp\.com|wa\.me)\//i.test(invite)) return res.status(400).json({ error: 'رابط المجموعة غير صالح.' });
  const { rows } = await query('INSERT INTO groups_manual(name,invite_url,note) VALUES($1,$2,$3) RETURNING *', [name, invite || null, note]);
  res.status(201).json(rows[0]);
}));
app.patch('/api/groups/:id', requireAuth, asyncRoute(async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id)) return res.status(400).json({ error: 'معرّف غير صالح.' });
  const selected = typeof req.body?.selected === 'boolean' ? req.body.selected : null;
  const isActive = typeof req.body?.isActive === 'boolean' ? req.body.isActive : null;
  const { rows } = await query(`UPDATE groups_manual SET selected=COALESCE($2,selected),is_active=COALESCE($3,is_active) WHERE id=$1 RETURNING *`, [id, selected, isActive]);
  if (!rows[0]) return res.status(404).json({ error: 'المجموعة غير موجودة.' });
  res.json(rows[0]);
}));
app.delete('/api/groups/:id', requireAuth, asyncRoute(async (req, res) => {
  const id = Number(req.params.id);
  try {
    const result = await query('DELETE FROM groups_manual WHERE id=$1', [id]);
    if (!result.rowCount) return res.status(404).json({ error: 'المجموعة غير موجودة.' });
    res.json({ ok: true });
  } catch { res.status(409).json({ error: 'لا يمكن حذف مجموعة مرتبطة بسجل نشر. يمكنك إلغاء تفعيلها بدلاً من ذلك.' }); }
}));
app.post('/api/groups/select-all', requireAuth, asyncRoute(async (req, res) => {
  const selected = Boolean(req.body?.selected);
  await query('UPDATE groups_manual SET selected=$1 WHERE is_active=true', [selected]);
  res.json({ ok: true });
}));

app.get('/api/posts', requireAuth, asyncRoute(async (req, res) => {
  const { rows } = await query(`SELECT p.id,p.title,p.body,p.created_at,COUNT(f.id)::int AS files,
    COALESCE(json_agg(json_build_object('id',f.id,'filename',f.filename,'mime_type',f.mime_type,'size_bytes',f.size_bytes)) FILTER (WHERE f.id IS NOT NULL),'[]') AS attachments
    FROM posts p LEFT JOIN post_files f ON f.post_id=p.id GROUP BY p.id ORDER BY p.created_at DESC`);
  res.json(rows);
}));
app.post('/api/posts', requireAuth, upload.array('files', 3), asyncRoute(async (req, res) => {
  const title = cleanText(req.body?.title, 180);
  const body = cleanText(req.body?.body, 10000);
  const allowedMime = new Set(['image/jpeg','image/png','image/webp','image/gif','video/mp4','video/webm','video/quicktime','application/pdf','text/plain','application/zip','application/vnd.openxmlformats-officedocument.wordprocessingml.document','application/msword']);
  const invalidFile = (req.files || []).find(file => !allowedMime.has(file.mimetype));
  if (invalidFile) return res.status(400).json({ error: `نوع الملف غير مدعوم: ${invalidFile.mimetype}` });
  if (!title || (!body && !(req.files?.length))) return res.status(400).json({ error: 'أدخل عنواناً ونصاً أو أرفق ملفاً واحداً على الأقل.' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const post = await client.query('INSERT INTO posts(title,body) VALUES($1,$2) RETURNING id,title,body,created_at', [title, body]);
    for (const file of (req.files || [])) {
      await client.query('INSERT INTO post_files(post_id,filename,mime_type,size_bytes,data) VALUES($1,$2,$3,$4,$5)', [post.rows[0].id, file.originalname.slice(0,255), file.mimetype, file.size, file.buffer]);
    }
    await client.query('COMMIT');
    await notify('success', `تم حفظ المنشور: ${title}`);
    res.status(201).json(post.rows[0]);
  } catch (e) { await client.query('ROLLBACK'); throw e; }
  finally { client.release(); }
}));
app.get('/api/posts/:postId/files/:fileId', requireAuth, asyncRoute(async (req, res) => {
  const { rows } = await query('SELECT filename,mime_type,data FROM post_files WHERE id=$1 AND post_id=$2', [req.params.fileId, req.params.postId]);
  if (!rows[0]) return res.status(404).end();
  res.setHeader('Content-Type', rows[0].mime_type);
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Content-Disposition', `attachment; filename*=UTF-8''${encodeURIComponent(rows[0].filename)}`);
  res.send(rows[0].data);
}));
app.delete('/api/posts/:id', requireAuth, asyncRoute(async (req, res) => {
  const result = await query('DELETE FROM posts WHERE id=$1 AND NOT EXISTS(SELECT 1 FROM campaigns WHERE post_id=$1)', [req.params.id]);
  if (!result.rowCount) return res.status(409).json({ error: 'المنشور غير موجود أو مرتبط بحملة محفوظة.' });
  res.json({ ok: true });
}));

app.get('/api/campaigns', requireAuth, asyncRoute(async (req, res) => {
  const { rows } = await query(`SELECT c.id,c.status,c.interval_seconds,c.created_at,p.title AS post_title,
    COUNT(d.id)::int AS total,COUNT(d.id) FILTER (WHERE d.status='sent_manual')::int AS sent,
    COUNT(d.id) FILTER (WHERE d.status='pending')::int AS pending,COUNT(d.id) FILTER (WHERE d.status='failed')::int AS failed
    FROM campaigns c JOIN posts p ON p.id=c.post_id LEFT JOIN deliveries d ON d.campaign_id=c.id
    GROUP BY c.id,p.title ORDER BY c.created_at DESC`);
  res.json(rows);
}));
app.post('/api/campaigns', requireAuth, asyncRoute(async (req, res) => {
  const postId = Number(req.body?.postId);
  const interval = Number(req.body?.intervalSeconds || 60);
  const groupIds = Array.isArray(req.body?.groupIds) ? [...new Set(req.body.groupIds.map(Number).filter(Number.isSafeInteger))] : [];
  if (!Number.isSafeInteger(postId) || interval < 30 || interval > 86400 || !groupIds.length) return res.status(400).json({ error: 'حدد منشوراً ومجموعة واحدة على الأقل وفاصلاً بين 30 و86400 ثانية.' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const post = await client.query('SELECT id FROM posts WHERE id=$1', [postId]);
    if (!post.rowCount) throw Object.assign(new Error('المنشور غير موجود.'), { status: 404 });
    const groups = await client.query('SELECT id FROM groups_manual WHERE id=ANY($1::bigint[]) AND selected=true AND is_active=true', [groupIds]);
    if (groups.rowCount !== groupIds.length) throw Object.assign(new Error('يمكن اختيار المجموعات المفعلة والمحددة فقط.'), { status: 400 });
    const campaign = await client.query('INSERT INTO campaigns(post_id,status,interval_seconds) VALUES($1,\'queued\',$2) RETURNING *', [postId, interval]);
    for (const group of groups.rows) await client.query('INSERT INTO deliveries(campaign_id,group_id) VALUES($1,$2)', [campaign.rows[0].id, group.id]);
    await client.query('COMMIT');
    await notify('info', `تم إنشاء حملة تجهيز يدوي (#${campaign.rows[0].id}) لـ ${groups.rowCount} مجموعات. لا تُرسل الرسائل تلقائياً.`);
    res.status(201).json({ ...campaign.rows[0], total: groups.rowCount, mode: 'manual_confirmation' });
  } catch (e) { await client.query('ROLLBACK'); throw e; }
  finally { client.release(); }
}));
app.get('/api/campaigns/:id/deliveries', requireAuth, asyncRoute(async (req, res) => {
  const { rows } = await query(`SELECT d.id,d.status,d.not_before,d.sent_at,d.error_message,d.attempt_count,g.name AS group_name,g.invite_url,p.title AS post_title,p.body,p.id AS post_id,c.interval_seconds,c.status AS campaign_status,
    COALESCE(json_agg(json_build_object('id',f.id,'filename',f.filename)) FILTER (WHERE f.id IS NOT NULL),'[]') AS attachments
    FROM deliveries d JOIN groups_manual g ON g.id=d.group_id JOIN campaigns c ON c.id=d.campaign_id JOIN posts p ON p.id=c.post_id
    LEFT JOIN post_files f ON f.post_id=p.id WHERE c.id=$1
    GROUP BY d.id,g.name,g.invite_url,p.title,p.body,p.id,c.interval_seconds,c.status ORDER BY d.id`, [req.params.id]);
  res.json(rows);
}));
async function finalizeDelivery(deliveryId, outcome, reason = null) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const update = outcome === 'sent'
      ? `UPDATE deliveries d SET status='sent_manual',sent_at=NOW(),attempt_count=attempt_count+1,error_message=NULL
         WHERE d.id=$1 AND d.status IN ('pending','failed') AND d.not_before<=NOW()
         AND EXISTS (SELECT 1 FROM campaigns c WHERE c.id=d.campaign_id AND c.status IN ('queued','running'))
         AND NOT EXISTS (SELECT 1 FROM deliveries prev WHERE prev.campaign_id=d.campaign_id AND prev.id<d.id AND prev.status='pending')
         RETURNING d.*`
      : `UPDATE deliveries d SET status='failed',error_message=$2,attempt_count=attempt_count+1
         WHERE d.id=$1 AND d.status='pending' AND d.not_before<=NOW()
         AND EXISTS (SELECT 1 FROM campaigns c WHERE c.id=d.campaign_id AND c.status IN ('queued','running'))
         AND NOT EXISTS (SELECT 1 FROM deliveries prev WHERE prev.campaign_id=d.campaign_id AND prev.id<d.id AND prev.status='pending')
         RETURNING d.*`;
    const params = outcome === 'sent' ? [deliveryId] : [deliveryId, reason];
    const result = await client.query(update, params);
    if (!result.rowCount) {
      await client.query('ROLLBACK');
      return null;
    }
    const campaignId = result.rows[0].campaign_id;
    await client.query(`UPDATE deliveries SET not_before=NOW() + (SELECT interval_seconds FROM campaigns WHERE id=$1) * INTERVAL '1 second'
      WHERE id=(SELECT id FROM deliveries WHERE campaign_id=$1 AND status='pending' ORDER BY id LIMIT 1)`, [campaignId]);
    await client.query(`UPDATE campaigns SET status=CASE WHEN NOT EXISTS(SELECT 1 FROM deliveries WHERE campaign_id=$1 AND status IN ('pending','failed')) THEN 'completed' ELSE status END,updated_at=NOW() WHERE id=$1`, [campaignId]);
    await client.query('COMMIT');
    return result.rows[0];
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}
app.post('/api/deliveries/:id/mark-sent', requireAuth, asyncRoute(async (req, res) => {
  const result = await finalizeDelivery(req.params.id, 'sent');
  if (!result) return res.status(409).json({ error: 'الخطوة غير جاهزة بعد، أو لم تُنهَ الخطوة السابقة، أو تم تسجيلها مسبقاً.' });
  await notify('success', 'تم تسجيل الإرسال اليدوي بنجاح.');
  res.json(result);
}));
app.post('/api/deliveries/:id/mark-failed', requireAuth, asyncRoute(async (req, res) => {
  const reason = cleanText(req.body?.reason || 'فشل الإرسال اليدوي', 500);
  const result = await finalizeDelivery(req.params.id, 'failed', reason);
  if (!result) return res.status(409).json({ error: 'الخطوة غير جاهزة بعد، أو لم تُنهَ الخطوة السابقة، أو تم تسجيلها مسبقاً.' });
  await notify('warning', `تعذر الإرسال إلى إحدى المجموعات: ${reason}`);
  res.json(result);
}));
app.post('/api/campaigns/:id/status', requireAuth, asyncRoute(async (req, res) => {
  const status = cleanText(req.body?.status, 30);
  if (!['paused','queued','stopped'].includes(status)) return res.status(400).json({ error: 'حالة غير صالحة.' });
  const { rows } = await query('UPDATE campaigns SET status=$1,updated_at=NOW() WHERE id=$2 RETURNING *', [status, req.params.id]);
  if (!rows[0]) return res.status(404).json({ error: 'الحملة غير موجودة.' });
  res.json(rows[0]);
}));

app.get('/api/notifications', requireAuth, asyncRoute(async (req, res) => {
  const { rows } = await query('SELECT * FROM notifications ORDER BY created_at DESC LIMIT 60');
  res.json(rows);
}));
app.post('/api/notifications/read-all', requireAuth, asyncRoute(async (req, res) => {
  await query('UPDATE notifications SET is_read=true');
  res.json({ ok: true });
}));
app.get('/api/settings', requireAuth, asyncRoute(async (req, res) => {
  const { rows } = await query('SELECT key,value FROM app_settings ORDER BY key');
  res.json(Object.fromEntries(rows.map(row => [row.key, row.value])));
}));
app.put('/api/settings', requireAuth, asyncRoute(async (req, res) => {
  const appName = cleanText(req.body?.app_name, 100);
  const interval = Number(req.body?.default_interval_seconds);
  if (appName) await query("INSERT INTO app_settings(key,value) VALUES('app_name',$1) ON CONFLICT(key) DO UPDATE SET value=$1,updated_at=NOW()", [JSON.stringify(appName)]);
  if (Number.isInteger(interval) && interval >= 30 && interval <= 86400) await query("INSERT INTO app_settings(key,value) VALUES('default_interval_seconds',$1) ON CONFLICT(key) DO UPDATE SET value=$1,updated_at=NOW()", [JSON.stringify(interval)]);
  res.json({ ok: true });
}));
app.put('/api/settings/password', requireAuth, asyncRoute(async (req, res) => {
  const current = String(req.body?.currentPassword ?? '');
  const next = String(req.body?.newPassword ?? '');
  if (next.length < 12) return res.status(400).json({ error: 'يجب أن تتكون كلمة المرور الجديدة من 12 حرفاً على الأقل.' });
  const manager = await query('SELECT password_hash FROM managers WHERE id=$1', [req.session.managerId]);
  if (!manager.rowCount || !(await bcrypt.compare(current, manager.rows[0].password_hash))) return res.status(403).json({ error: 'كلمة المرور الحالية غير صحيحة.' });
  const hash = await bcrypt.hash(next, 12);
  await query('UPDATE managers SET password_hash=$1,updated_at=NOW() WHERE id=$2', [hash, req.session.managerId]);
  await notify('security', 'تم تغيير كلمة مرور المدير.');
  res.json({ ok: true });
}));
app.get('/api/logs', requireAuth, asyncRoute(async (req, res) => {
  const { rows } = await query(`SELECT d.id,d.status,d.sent_at,d.error_message,d.attempt_count,g.name AS group_name,p.title AS post_title,d.created_at
    FROM deliveries d JOIN groups_manual g ON g.id=d.group_id JOIN campaigns c ON c.id=d.campaign_id JOIN posts p ON p.id=c.post_id
    ORDER BY COALESCE(d.sent_at,d.created_at) DESC LIMIT 500`);
  res.json(rows);
}));
app.get('/api/logs.csv', requireAuth, asyncRoute(async (req, res) => {
  const { rows } = await query(`SELECT d.id,g.name AS group_name,p.title AS post_title,d.status,d.sent_at,d.error_message,d.attempt_count
    FROM deliveries d JOIN groups_manual g ON g.id=d.group_id JOIN campaigns c ON c.id=d.campaign_id JOIN posts p ON p.id=c.post_id ORDER BY d.created_at DESC`);
  const quote = v => `"${String(v ?? '').replaceAll('"','""')}"`;
  const csv = ['id,group,post,status,sent_at,error,attempts', ...rows.map(r => [r.id,r.group_name,r.post_title,r.status,r.sent_at?.toISOString?.() || '',r.error_message,r.attempt_count].map(quote).join(','))].join('\r\n');
  res.setHeader('Content-Type','text/csv; charset=utf-8');
  res.setHeader('Content-Disposition','attachment; filename="qst-publishing-log.csv"');
  res.send('\uFEFF' + csv);
}));

app.use((err, req, res, next) => {
  console.error('[QST]', err?.message || 'Unknown error');
  if (res.headersSent) return next(err);
  const status = Number(err.status) || (err instanceof multer.MulterError ? 400 : 500);
  res.status(status).json({ error: status === 500 ? 'حدث خطأ داخلي. راجع سجل الخادم دون مشاركة بيانات الجلسة.' : err.message });
});

const port = Number(process.env.PORT || 3000);
await initDb();
app.listen(port, '0.0.0.0', () => console.log(`QST WhatsApp Publisher listening on ${port}`));
