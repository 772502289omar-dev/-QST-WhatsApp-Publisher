import crypto from 'node:crypto';

export function safeEqual(a, b) {
  const aa = Buffer.from(String(a ?? ''));
  const bb = Buffer.from(String(b ?? ''));
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}

export function makeCsrfToken() {
  return crypto.randomBytes(32).toString('hex');
}

export function csrfProtection(req, res, next) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  const sent = req.get('x-csrf-token');
  if (!sent || !req.session?.csrfToken || !safeEqual(sent, req.session.csrfToken)) {
    return res.status(403).json({ error: 'انتهت صلاحية الطلب. حدّث الصفحة ثم أعد المحاولة.' });
  }
  next();
}

export function requireAuth(req, res, next) {
  if (req.session?.managerId) return next();
  return res.status(401).json({ error: 'يرجى تسجيل الدخول أولاً.' });
}

export function cleanText(value, max = 5000) {
  return String(value ?? '').trim().slice(0, max);
}
