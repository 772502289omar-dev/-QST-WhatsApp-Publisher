import pg from 'pg';
import bcrypt from 'bcryptjs';

const { Pool } = pg;

if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL is required. Configure a persistent PostgreSQL database.');

export const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL.includes('supabase') || process.env.DATABASE_URL.includes('sslmode=require')
    ? { rejectUnauthorized: false }
    : undefined,
  max: 5,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

export async function query(text, params = []) {
  return pool.query(text, params);
}

export async function initDb() {
  await query(`
    CREATE TABLE IF NOT EXISTS managers (
      id BIGSERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS app_settings (
      key TEXT PRIMARY KEY,
      value JSONB NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS groups_manual (
      id BIGSERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      invite_url TEXT,
      note TEXT DEFAULT '',
      selected BOOLEAN NOT NULL DEFAULT FALSE,
      is_active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS posts (
      id BIGSERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      body TEXT NOT NULL DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS post_files (
      id BIGSERIAL PRIMARY KEY,
      post_id BIGINT NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
      filename TEXT NOT NULL,
      mime_type TEXT NOT NULL,
      size_bytes BIGINT NOT NULL,
      data BYTEA NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS campaigns (
      id BIGSERIAL PRIMARY KEY,
      post_id BIGINT NOT NULL REFERENCES posts(id) ON DELETE RESTRICT,
      status TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued','running','paused','stopped','completed')),
      interval_seconds INTEGER NOT NULL DEFAULT 60 CHECK (interval_seconds >= 30),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS deliveries (
      id BIGSERIAL PRIMARY KEY,
      campaign_id BIGINT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
      group_id BIGINT NOT NULL REFERENCES groups_manual(id) ON DELETE RESTRICT,
      status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','sent_manual','failed','skipped')),
      not_before TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      sent_at TIMESTAMPTZ,
      error_message TEXT,
      attempt_count INTEGER NOT NULL DEFAULT 0,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE (campaign_id, group_id)
    );
    CREATE TABLE IF NOT EXISTS notifications (
      id BIGSERIAL PRIMARY KEY,
      kind TEXT NOT NULL,
      message TEXT NOT NULL,
      is_read BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    ALTER TABLE deliveries ADD COLUMN IF NOT EXISTS not_before TIMESTAMPTZ NOT NULL DEFAULT NOW();
    CREATE INDEX IF NOT EXISTS idx_deliveries_campaign ON deliveries(campaign_id);
    CREATE INDEX IF NOT EXISTS idx_deliveries_status ON deliveries(status);
    CREATE INDEX IF NOT EXISTS idx_posts_created ON posts(created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_notifications_unread ON notifications(is_read, created_at DESC);
  `);

  const username = process.env.ADMIN_USERNAME || 'admin';
  const password = process.env.ADMIN_PASSWORD;
  const found = await query('SELECT id FROM managers LIMIT 1');
  if (!found.rowCount) {
    if (!password || password.length < 12) {
      throw new Error('First-run setup requires ADMIN_PASSWORD with at least 12 characters. Set it in environment variables.');
    }
    const hash = await bcrypt.hash(password, 12);
    await query('INSERT INTO managers(username,password_hash) VALUES($1,$2)', [username, hash]);
    await query("INSERT INTO notifications(kind,message) VALUES('system','تم إنشاء حساب المدير الأول. غيّر كلمة المرور من الإعدادات بعد تسجيل الدخول.')");
  }

  const defaults = {
    app_name: process.env.APP_NAME || 'QST WhatsApp Publisher',
    default_interval_seconds: 60,
    connection_status: 'not_connected',
    whatsapp_integration: 'disabled_unofficial_sender_not_enabled',
    publisher_mode: 'manual_confirmation'
  };
  for (const [key, value] of Object.entries(defaults)) {
    await query('INSERT INTO app_settings(key,value) VALUES($1,$2) ON CONFLICT(key) DO NOTHING', [key, JSON.stringify(value)]);
  }
}
