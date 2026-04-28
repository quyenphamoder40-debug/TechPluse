/**
 * TechPulse Backend - backend.js
 * Node.js + Express + SQLite (better-sqlite3)
 *
 * Cai dat:
 *   npm install express bcryptjs jsonwebtoken cors better-sqlite3 multer
 *
 * Chay:
 *   node backend.js
 *
 * DB file: ./techpulse.db  (restart khong mat data)
 * Base URL: http://localhost:3000
 *
 * ============================================================
 * API ROUTES
 * ============================================================
 * PUBLIC
 *   GET    /health                       (require admin token)
 *   GET    /api/categories
 *   GET    /api/articles                 ?page&limit&category&featured&hot&sort
 *   GET    /api/articles/search          ?q&page&limit&category&sort
 *   GET    /api/articles/trending        ?limit
 *   GET    /api/articles/:id
 *   GET    /api/articles/:id/related
 *   GET    /api/articles/:id/comments    ?page&limit
 *   POST   /api/search                   { q, category?, page?, limit? }  AI semantic
 *
 * AUTH
 *   POST   /api/auth/register            { name, email, password }
 *   POST   /api/auth/login               { email, password }
 *   POST   /api/auth/forgot-password     { email }
 *   POST   /api/auth/refresh             { token }
 *
 * USER (JWT required)
 *   GET    /api/auth/me
 *   PUT    /api/auth/me                  { name?, avatar? }
 *   PUT    /api/auth/me/password         { currentPassword, newPassword }
 *   GET    /api/user/bookmarks
 *   POST   /api/user/bookmarks/:id       toggle
 *   GET    /api/user/notifications
 *   PUT    /api/user/notifications       { email?, breaking?, weekly?, marketing? }
 *   POST   /api/articles/:id/comments    { content }
 *   DELETE /api/comments/:id             (own comment or admin)
 *
 * UPLOAD
 *   POST   /api/upload                   multipart/form-data, field: file
 *
 * NEWSLETTER (public)
 *   POST   /api/newsletter/subscribe     { email, frequency, topics[] }
 *
 * ADMIN (JWT + role=admin)
 *   GET    /api/admin/articles           ?page&limit&status&category
 *   POST   /api/admin/articles           { ...fields }
 *   PUT    /api/admin/articles/:id       { ...fields }
 *   DELETE /api/admin/articles/:id
 *   GET    /api/admin/stats
 *   GET    /api/admin/traffic            ?period=7d|30d
 *   GET    /api/admin/users              ?page&limit&role&status
 *   PATCH  /api/admin/users/:id          { role?, status?, name?, email? }
 *   DELETE /api/admin/users/:id
 *   GET    /api/admin/settings
 *   PUT    /api/admin/settings           { siteName, domain, email, ... }
 * ============================================================
 */

'use strict';

const express  = require('express');
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
const cors     = require('cors');
const Database = require('better-sqlite3');
const path     = require('path');
const fs       = require('fs');
const https    = require('https');
const multer   = require('multer');
const crypto   = require('crypto');

const app = express();
const PORT        = process.env.PORT        || 3000;
const JWT_SECRET  = process.env.JWT_SECRET  || 'techpulse-secret-change-in-prod';
const JWT_EXPIRES = '7d';
const AUTH_COOKIE_NAME = process.env.AUTH_COOKIE_NAME || 'tp_token';
const DB_PATH     = path.join(__dirname, 'techpulse.db');
const UPLOAD_DIR  = path.join(__dirname, 'uploads');
const ALLOWED_ORIGINS   = (process.env.ALLOWED_ORIGINS   || '').split(',').map(s => s.trim()).filter(Boolean);
const GOOGLE_CLIENT_ID  = process.env.GOOGLE_CLIENT_ID   || '';

// Tạo thư mục uploads nếu chưa có
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// ============================================================
// MIDDLEWARE
// ============================================================

app.use(cors({
  origin: function(origin, cb) {
    // Cho phép request không có origin (curl, mobile app, same-origin)
    if (!origin) return cb(null, true);
    // Nếu chưa set hoặc là '*' -> cho phep tat ca
    if (!ALLOWED_ORIGINS.length) return cb(null, true);
    if (ALLOWED_ORIGINS.includes('*')) return cb(null, true);
    if (ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
    cb(new Error('CORS: origin không được phép'));
  },
  credentials: true,
}));

app.use(express.json({ limit: '10mb' }));
app.use('/uploads', express.static(UPLOAD_DIR));

app.use(function(req, res, next) {
  res.setTimeout(15000, function() {
    if (!res.headersSent) res.status(503).json({ success: false, error: 'Request timeout' });
  });
  next();
});

// Security headers co ban cho API
app.use(function(_req, res, next) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  next();
});

function enforcePayloadLimit(maxBytes) {
  return function(req, res, next) {
    var len = parseInt(req.headers['content-length'] || '0', 10);
    if (len > maxBytes) return res_err(res, 'Payload quá lớn', 413);
    next();
  };
}

// Multer config: chi nhan anh, max 5MB
const storage = multer.diskStorage({
  destination: function(_req, _file, cb) { cb(null, UPLOAD_DIR); },
  filename: function(_req, file, cb) {
    var ext = path.extname(file.originalname).toLowerCase() || '.jpg';
    cb(null, Date.now() + '-' + Math.random().toString(36).slice(2) + ext);
  },
});
const upload = multer({
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: function(_req, file, cb) {
    var ok = /^image\/(jpeg|png|gif|webp)$/.test(file.mimetype);
    cb(ok ? null : new Error('Chỉ chấp nhận file ảnh (jpg, png, gif, webp)'), ok);
  },
});

// ============================================================
// DATABASE INIT
// ============================================================

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.pragma('busy_timeout = 5000');

db.exec(`
  CREATE TABLE IF NOT EXISTS articles (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    slug           TEXT    UNIQUE NOT NULL,
    category       TEXT    NOT NULL,
    category_label TEXT    NOT NULL,
    title          TEXT    NOT NULL,
    excerpt        TEXT,
    content        TEXT,
    author         TEXT,
    author_avatar  TEXT,
    date           TEXT    NOT NULL DEFAULT (datetime('now')),
    read_time      INTEGER DEFAULT 4,
    views          INTEGER DEFAULT 0,
    total_views    INTEGER DEFAULT 0,
    shares         INTEGER DEFAULT 0,
    bounce_rate    REAL    DEFAULT 0,
    thumbnail      TEXT,
    tags           TEXT    DEFAULT '[]',
    is_featured    INTEGER DEFAULT 0,
    is_hot         INTEGER DEFAULT 0,
    status         TEXT    DEFAULT 'published',
    deleted_at     TEXT    DEFAULT NULL
  );

  CREATE TABLE IF NOT EXISTS users (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL,
    email       TEXT    UNIQUE NOT NULL,
    password    TEXT    NOT NULL,
    avatar      TEXT,
    role        TEXT    DEFAULT 'user',
    status      TEXT    DEFAULT 'active',
    phone       TEXT,
    last_ip     TEXT,
    last_device TEXT,
    created_at  TEXT    DEFAULT (datetime('now')),
    updated_at  TEXT
  );

  CREATE TABLE IF NOT EXISTS user_sessions (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL,
    token_hash    TEXT NOT NULL,
    ip            TEXT,
    user_agent    TEXT,
    created_at    TEXT DEFAULT (datetime('now')),
    expires_at    TEXT,
    revoked_at    TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS user_activity_log (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL,
    activity_type TEXT NOT NULL,
    payload_json  TEXT DEFAULT '{}',
    created_at    TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS bookmarks (
    user_id    INTEGER NOT NULL,
    article_id INTEGER NOT NULL,
    created_at TEXT DEFAULT (datetime('now')),
    PRIMARY KEY (user_id, article_id),
    FOREIGN KEY (user_id)    REFERENCES users(id)    ON DELETE CASCADE,
    FOREIGN KEY (article_id) REFERENCES articles(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS comments (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    article_id INTEGER NOT NULL,
    user_id    INTEGER NOT NULL,
    content    TEXT    NOT NULL,
    created_at TEXT    DEFAULT (datetime('now')),
    deleted_at TEXT    DEFAULT NULL,
    FOREIGN KEY (article_id) REFERENCES articles(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id)    REFERENCES users(id)    ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS newsletters (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    email      TEXT UNIQUE NOT NULL,
    frequency  TEXT DEFAULT 'daily',
    topics     TEXT DEFAULT '[]',
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT
  );

  CREATE TABLE IF NOT EXISTS notification_settings (
    user_id   INTEGER PRIMARY KEY,
    email_on  INTEGER DEFAULT 1,
    breaking  INTEGER DEFAULT 1,
    weekly    INTEGER DEFAULT 0,
    marketing INTEGER DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS view_log (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    article_id   INTEGER NOT NULL,
    user_id      INTEGER,
    ip           TEXT,
    user_agent   TEXT,
    duration_sec INTEGER DEFAULT NULL,
    created_at   TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (article_id) REFERENCES articles(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS ads (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    platform   TEXT    NOT NULL,
    revenue    REAL    DEFAULT 0,
    clicks     INTEGER DEFAULT 0,
    impressions INTEGER DEFAULT 0,
    ctr        REAL    DEFAULT 0,
    rpm        REAL    DEFAULT 0,
    period     TEXT    NOT NULL,
    created_at TEXT    DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS ad_campaigns (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT NOT NULL,
    platform     TEXT NOT NULL,
    status       TEXT DEFAULT 'active',
    budget       REAL DEFAULT 0,
    spent        REAL DEFAULT 0,
    revenue      REAL DEFAULT 0,
    impressions  INTEGER DEFAULT 0,
    clicks       INTEGER DEFAULT 0,
    ctr          REAL DEFAULT 0,
    target_tags  TEXT DEFAULT '[]',
    starts_at    TEXT,
    ends_at      TEXT,
    created_at   TEXT DEFAULT (datetime('now')),
    updated_at   TEXT
  );
    db.run(`CREATE TABLE IF NOT EXISTS ad_creatives (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      campaign_id INTEGER REFERENCES ad_campaigns(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      type TEXT DEFAULT 'banner',
      format TEXT DEFAULT '300x250',
      headline TEXT,
      body TEXT,
      cta_text TEXT,
      image_url TEXT,
      video_url TEXT,
      landing_url TEXT,
      status TEXT DEFAULT 'active',
      quality_score REAL DEFAULT 0,
      avg_attention_time REAL DEFAULT 0,
      avg_completion_rate REAL DEFAULT 0,
      total_impressions INTEGER DEFAULT 0,
      total_clicks INTEGER DEFAULT 0,
      total_views INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS ad_placements (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      page_type TEXT DEFAULT 'article',
      position TEXT DEFAULT 'sidebar',
      size TEXT DEFAULT '300x250',
      context_tags TEXT DEFAULT '[]',
      quality_score REAL DEFAULT 0,
      avg_ctr REAL DEFAULT 0,
      avg_attention_time REAL DEFAULT 0,
      fill_rate REAL DEFAULT 0,
      total_requests INTEGER DEFAULT 0,
      total_served INTEGER DEFAULT 0,
      status TEXT DEFAULT 'active',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS ad_impressions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      campaign_id INTEGER REFERENCES ad_campaigns(id),
      creative_id INTEGER REFERENCES ad_creatives(id),
      placement_id INTEGER REFERENCES ad_placements(id),
      user_id TEXT,
      session_id TEXT,
      content_id INTEGER,
      event_type TEXT NOT NULL,
      attention_time REAL DEFAULT 0,
      scroll_depth REAL DEFAULT 0,
      viewport_pct REAL DEFAULT 0,
      is_viewable INTEGER DEFAULT 0,
      is_click INTEGER DEFAULT 0,
      is_dismiss INTEGER DEFAULT 0,
      post_view_action TEXT,
      device_type TEXT DEFAULT 'desktop',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS ad_impressions_daily (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      campaign_id INTEGER REFERENCES ad_campaigns(id),
      creative_id INTEGER,
      placement_id INTEGER,
      date TEXT NOT NULL,
      impressions INTEGER DEFAULT 0,
      viewable_impressions INTEGER DEFAULT 0,
      clicks INTEGER DEFAULT 0,
      dismissals INTEGER DEFAULT 0,
      total_attention_time REAL DEFAULT 0,
      avg_attention_time REAL DEFAULT 0,
      ctr REAL DEFAULT 0,
      vtr REAL DEFAULT 0,
      revenue REAL DEFAULT 0,
      UNIQUE(campaign_id, creative_id, placement_id, date)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS ad_frequency_caps (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT NOT NULL,
      campaign_id INTEGER REFERENCES ad_campaigns(id),
      creative_id INTEGER,
      impressions_1h INTEGER DEFAULT 0,
      impressions_24h INTEGER DEFAULT 0,
      impressions_7d INTEGER DEFAULT 0,
      last_seen_at DATETIME,
      fatigue_score REAL DEFAULT 0,
      is_fatigued INTEGER DEFAULT 0,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(user_id, campaign_id)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS ad_attention_metrics (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      campaign_id INTEGER REFERENCES ad_campaigns(id),
      creative_id INTEGER,
      placement_id INTEGER,
      date TEXT NOT NULL,
      avg_attention_time REAL DEFAULT 0,
      p50_attention REAL DEFAULT 0,
      p90_attention REAL DEFAULT 0,
      high_attention_rate REAL DEFAULT 0,
      low_attention_rate REAL DEFAULT 0,
      avg_scroll_depth REAL DEFAULT 0,
      avg_viewport_pct REAL DEFAULT 0,
      UNIQUE(campaign_id, creative_id, placement_id, date)
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS ad_post_view_behavior (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      campaign_id INTEGER REFERENCES ad_campaigns(id),
      creative_id INTEGER,
      user_id TEXT,
      impression_id INTEGER,
      action TEXT,
      content_id INTEGER,
      time_to_action INTEGER DEFAULT 0,
      session_depth INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

  CREATE TABLE IF NOT EXISTS ad_events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id  INTEGER NOT NULL,
    user_id      INTEGER,
    event_type   TEXT NOT NULL, -- impression|click|conversion
    value        REAL DEFAULT 0,
    created_at   TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (campaign_id) REFERENCES ad_campaigns(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
  );

  CREATE TABLE IF NOT EXISTS products (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT NOT NULL,
    category     TEXT NOT NULL,
    tags         TEXT DEFAULT '[]',
    price        REAL DEFAULT 0,
    stock        INTEGER DEFAULT 0,
    trend_score  REAL DEFAULT 0,
    season_tags  TEXT DEFAULT '[]',
    status       TEXT DEFAULT 'active',
    created_at   TEXT DEFAULT (datetime('now')),
    updated_at   TEXT
  );

  CREATE TABLE IF NOT EXISTS user_interests (
    user_id    INTEGER NOT NULL,
    category   TEXT    NOT NULL,
    score      INTEGER DEFAULT 1,
    updated_at TEXT    DEFAULT (datetime('now')),
    PRIMARY KEY (user_id, category),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS user_stats (
    user_id      INTEGER PRIMARY KEY,
    total_views  INTEGER DEFAULT 0,
    total_comments INTEGER DEFAULT 0,
    total_shares INTEGER DEFAULT 0,
    avg_read_time TEXT    DEFAULT '0:00',
    updated_at   TEXT    DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS user_analytics_events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL,
    actor_name    TEXT    NOT NULL,
    event_type    TEXT    NOT NULL,
    event_target  TEXT,
    metadata_json TEXT    DEFAULT '{}',
    source        TEXT    DEFAULT 'ui',
    created_at    TEXT    DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS analytics_sync_requests (
    request_id     TEXT PRIMARY KEY,
    user_id        INTEGER NOT NULL,
    source         TEXT    DEFAULT 'ui',
    input_json     TEXT    DEFAULT '{}',
    result_json    TEXT    DEFAULT '{}',
    status         TEXT    DEFAULT 'processed',
    error_message  TEXT,
    created_at     TEXT    DEFAULT (datetime('now')),
    processed_at   TEXT    DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS stats_daily (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    day            TEXT NOT NULL,
    metric_group   TEXT NOT NULL,
    metric_key     TEXT NOT NULL,
    metric_value   REAL DEFAULT 0,
    created_at     TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS site_settings (
    key   TEXT PRIMARY KEY,
    value TEXT
  );

  -- Indexes
  CREATE INDEX IF NOT EXISTS idx_articles_status   ON articles(status);
  CREATE INDEX IF NOT EXISTS idx_articles_category ON articles(category);
  CREATE INDEX IF NOT EXISTS idx_articles_views    ON articles(views DESC);
  CREATE INDEX IF NOT EXISTS idx_articles_date     ON articles(date DESC);
  CREATE INDEX IF NOT EXISTS idx_articles_hot      ON articles(is_hot);
  CREATE INDEX IF NOT EXISTS idx_articles_featured ON articles(is_featured);
  CREATE INDEX IF NOT EXISTS idx_view_log_article  ON view_log(article_id);
  CREATE INDEX IF NOT EXISTS idx_view_log_date     ON view_log(created_at);
  CREATE INDEX IF NOT EXISTS idx_comments_article  ON comments(article_id);
  CREATE INDEX IF NOT EXISTS idx_uae_user_created  ON user_analytics_events(user_id, created_at DESC);
  CREATE INDEX IF NOT EXISTS idx_uae_type          ON user_analytics_events(event_type);
  CREATE INDEX IF NOT EXISTS idx_asr_user_time     ON analytics_sync_requests(user_id, created_at DESC);
  CREATE INDEX IF NOT EXISTS idx_session_user_time ON user_sessions(user_id, created_at DESC);
  CREATE INDEX IF NOT EXISTS idx_user_activity     ON user_activity_log(user_id, created_at DESC);
  CREATE INDEX IF NOT EXISTS idx_stats_daily       ON stats_daily(day, metric_group);
  CREATE INDEX IF NOT EXISTS idx_ad_campaign_status ON ad_campaigns(status);
  CREATE INDEX IF NOT EXISTS idx_ad_event_time      ON ad_events(created_at);
  CREATE INDEX IF NOT EXISTS idx_ad_event_campaign  ON ad_events(campaign_id);
  CREATE INDEX IF NOT EXISTS idx_products_status     ON products(status);
  CREATE INDEX IF NOT EXISTS idx_products_category   ON products(category);
`);

// Migration: them cac column moi neu chua co (cho DB cu)
var existingCols = db.pragma('table_info(articles)').map(function(c) { return c.name; });
if (!existingCols.includes('shares'))      db.exec('ALTER TABLE articles ADD COLUMN shares INTEGER DEFAULT 0');
if (!existingCols.includes('bounce_rate')) db.exec('ALTER TABLE articles ADD COLUMN bounce_rate REAL DEFAULT 0');
if (!existingCols.includes('deleted_at'))  db.exec('ALTER TABLE articles ADD COLUMN deleted_at TEXT DEFAULT NULL');
if (!existingCols.includes('total_views')) db.exec('ALTER TABLE articles ADD COLUMN total_views INTEGER DEFAULT 0');
db.exec('UPDATE articles SET total_views = CASE WHEN total_views > views THEN total_views ELSE views END');
db.exec('UPDATE articles SET views = total_views');
db.exec('CREATE INDEX IF NOT EXISTS idx_articles_total_views ON articles(total_views DESC)');

var existingUserCols = db.pragma('table_info(users)').map(function(c) { return c.name; });
if (!existingUserCols.includes('status'))      db.exec("ALTER TABLE users ADD COLUMN status TEXT DEFAULT 'active'");
if (!existingUserCols.includes('phone'))       db.exec('ALTER TABLE users ADD COLUMN phone TEXT');
if (!existingUserCols.includes('last_ip'))     db.exec('ALTER TABLE users ADD COLUMN last_ip TEXT');
if (!existingUserCols.includes('last_device')) db.exec('ALTER TABLE users ADD COLUMN last_device TEXT');

var existingCommentCols = db.pragma('table_info(comments)').map(function(c) { return c.name; });
if (!existingCommentCols.includes('deleted_at')) db.exec('ALTER TABLE comments ADD COLUMN deleted_at TEXT DEFAULT NULL');

// Them cac column moi vao view_log neu chua co
var existingVLCols = db.pragma('table_info(view_log)').map(function(c) { return c.name; });
if (!existingVLCols.includes('user_id'))      db.exec('ALTER TABLE view_log ADD COLUMN user_id INTEGER');
if (!existingVLCols.includes('user_agent'))   db.exec('ALTER TABLE view_log ADD COLUMN user_agent TEXT');
if (!existingVLCols.includes('duration_sec')) db.exec('ALTER TABLE view_log ADD COLUMN duration_sec INTEGER DEFAULT NULL');

// Migration: them frequency_cap vao ad_campaigns neu chua co
var existingAdCols = db.pragma('table_info(ad_campaigns)').map(function(c) { return c.name; });
if (!existingAdCols.includes('frequency_cap')) db.exec('ALTER TABLE ad_campaigns ADD COLUMN frequency_cap INTEGER DEFAULT 3');
if (!existingAdCols.includes('daily_cap'))     db.exec('ALTER TABLE ad_campaigns ADD COLUMN daily_cap INTEGER DEFAULT 1000');

// Migration: them dismissed vao impression_log neu chua co
var existingImpCols = db.pragma('table_info(impression_log)').map(function(c) { return c.name; }).catch ? [] : db.pragma('table_info(impression_log)').map(function(c) { return c.name; });
try {
  var impCols = db.pragma('table_info(impression_log)').map(function(c) { return c.name; });
  if (!impCols.includes('dismissed')) db.exec('ALTER TABLE impression_log ADD COLUMN dismissed INTEGER DEFAULT 0');
} catch(_e) {}

// ============================================================
// SEED DATA
// ============================================================

if (db.prepare('SELECT COUNT(*) as c FROM articles').get().c === 0) {
  var ins = db.prepare(`
    INSERT INTO articles
      (slug,category,category_label,title,excerpt,content,author,author_avatar,
       date,read_time,views,thumbnail,tags,is_featured,is_hot)
    VALUES
      (@slug,@category,@category_label,@title,@excerpt,@content,@author,@author_avatar,
       @date,@read_time,@views,@thumbnail,@tags,@is_featured,@is_hot)
  `);

  db.transaction(function(rows) { for (var r of rows) ins.run(r); })([
    {
      slug:'thanh-tri-galaxy-quick-share-iphone', category:'mobile', category_label:'Mobile',
      title:'"Thanh trì" cuối cùng ngăn người dùng iPhone chuyển sang Galaxy vừa bị phá vỡ',
      excerpt:'Samsung Galaxy S26 hỗ trợ Quick Share với iPhone, không cần app trung gian.',
      content:'<p>Samsung vừa công bố tính năng Quick Share mở rộng trên Galaxy S26, cho phép chia sẻ file trực tiếp với iPhone. Tốc độ đạt 480 Mbps qua Wi-Fi Direct + Bluetooth LE.</p>',
      author:'Minh Khoa', author_avatar:'https://i.pravatar.cc/40?img=11',
      date:'2026-03-25T09:00:00Z', read_time:4, views:18420,
      thumbnail:'https://images.unsplash.com/photo-1610945265064-0e34e5519bbf?w=800&q=80',
      tags:JSON.stringify(['Samsung','Quick Share','iPhone','Galaxy S26']), is_featured:1, is_hot:1,
    },
    {
      slug:'openai-ket-thuc-sora-disney', category:'ai', category_label:'AI',
      title:'OpenAI đột ngột khai tử công cụ tạo video Sora, Disney mất 1 tỷ USD',
      excerpt:'Quyết định đóng cửa Sora chỉ sau 4 tháng khiến nhiều đối tác phải xem xét lại kế hoạch.',
      content:'<p>OpenAI ngừng dịch vụ Sora chỉ 4 tháng sau khi ra mắt. Chi phí mỗi phút video gần 40 USD khiến mô hình kinh doanh không khả thi.</p>',
      author:'Thanh Truc', author_avatar:'https://i.pravatar.cc/40?img=22',
      date:'2026-03-25T07:30:00Z', read_time:3, views:24103,
      thumbnail:'https://images.unsplash.com/photo-1677442135703-1787eea5ce01?w=800&q=80',
      tags:JSON.stringify(['OpenAI','Sora','AI','Disney']), is_featured:1, is_hot:1,
    },
    {
      slug:'intel-core-ultra-7-270k-plus', category:'tin-ict', category_label:'Tin ICT',
      title:'Intel Core Ultra 7 270K Plus: Lời khẳng định "Chúng tôi đã trở lại"',
      excerpt:'Core Ultra 7 270K Plus cải thiện hiệu năng gaming đáng kể so với thế hệ trước.',
      content:'<p>Intel ra mắt Core Ultra 7 270K Plus, xung boost 6.2 GHz. Vượt Ryzen 9 9950X 8–12% trong gaming 1080p.</p>',
      author:'Duc Anh', author_avatar:'https://i.pravatar.cc/40?img=33',
      date:'2026-03-23T10:15:00Z', read_time:5, views:11250,
      thumbnail:'https://images.unsplash.com/photo-1591370874773-6702e8f12fd8?w=800&q=80',
      tags:JSON.stringify(['Intel','CPU','Gaming','Arrow Lake']), is_featured:0, is_hot:0,
    },
    {
      slug:'honor-top3-antutu-2026', category:'mobile', category_label:'Mobile',
      title:'HONOR trở lại mạnh mẽ: Top 3 model thống trị bảng xếp hạng AnTuTu',
      excerpt:'HONOR đang khiến cả thị trường smartphone phải ngoái nhìn với màn lột xác ngoạn mục.',
      content:'<p>HONOR lần đầu có ba model lọt top 5 AnTuTu cùng tháng. Magic7 Pro, Magic7 RSR và GT Neo dẫn đầu phân khúc tương ứng.</p>',
      author:'Minh Khoa', author_avatar:'https://i.pravatar.cc/40?img=11',
      date:'2026-03-23T08:00:00Z', read_time:3, views:9870,
      thumbnail:'https://images.unsplash.com/photo-1607252650355-f7fd0460ccdb?w=800&q=80',
      tags:JSON.stringify(['HONOR','AnTuTu','Smartphone','Android']), is_featured:0, is_hot:0,
    },
    {
      slug:'microsoft-don-dep-copilot-windows-11', category:'internet', category_label:'Internet',
      title:'Microsoft dọn dẹp mớ bòng bong AI trên Windows 11',
      excerpt:'Sau nhiều năm nhồi nhét Copilot vào mọi ngóc ngách, Microsoft thừa nhận sai lầm.',
      content:'<p>Microsoft gộp toàn bộ điểm AI trên Windows 11 thành một Copilot duy nhất sau phản hồi tiêu cực từ người dùng toàn cầu.</p>',
      author:'Lan Anh', author_avatar:'https://i.pravatar.cc/40?img=44',
      date:'2026-03-24T11:00:00Z', read_time:4, views:15600,
      thumbnail:'https://images.unsplash.com/photo-1593642632559-0c6d3fc62b89?w=800&q=80',
      tags:JSON.stringify(['Microsoft','Windows 11','Copilot','AI']), is_featured:0, is_hot:1,
    },
    {
      slug:'macbook-neo-8gb-60-apps', category:'do-choi-so', category_label:'Đồ chơi số',
      title:'MacBook Neo 8GB mở 60 ứng dụng cùng lúc không sập, laptop Windows sập màn hình',
      excerpt:'Hardware Canucks thử nghiệm thực tế cho kết quả bất ngờ về khả năng quản lý RAM.',
      content:'<p>Hardware Canucks mở đồng thời 60 app trên MacBook Neo 8GB và laptop Windows 16GB. Apple unified memory xử lý mượt; Windows crash ở app thứ 47.</p>',
      author:'Duc Anh', author_avatar:'https://i.pravatar.cc/40?img=33',
      date:'2026-03-24T09:30:00Z', read_time:3, views:22400,
      thumbnail:'https://images.unsplash.com/photo-1558618666-fcd25c85cd64?w=800&q=80',
      tags:JSON.stringify(['MacBook','Apple','RAM','Benchmark']), is_featured:0, is_hot:0,
    },
    {
      slug:'bitcoin-184ty-mot-ngay-mat-sach', category:'tra-da-cn', category_label:'Trà đá CN',
      title:'Người đào được 184 tỷ Bitcoin trong một ngày và mất sạch chỉ sau vài giờ',
      excerpt:'Sự cố suýt khai tử Bitcoin ngay từ giai đoạn mới khai sinh.',
      content:'<p>Năm 2010, lỗ hổng code Bitcoin cho phép tạo ra 184 tỷ BTC trong một block. Satoshi và cộng đồng emergency fork trong 5 giờ.</p>',
      author:'Thanh Truc', author_avatar:'https://i.pravatar.cc/40?img=22',
      date:'2026-03-23T14:00:00Z', read_time:6, views:31800,
      thumbnail:'https://images.unsplash.com/photo-1639762681485-074b7f938ba0?w=800&q=80',
      tags:JSON.stringify(['Bitcoin','Crypto','Lich su','Satoshi']), is_featured:0, is_hot:0,
    },
    {
      slug:'suzuki-haojue-uhr350-honda-adv350', category:'xe', category_label:'Xe',
      title:'Suzuki Haojue UHR350: Đủ sức đánh bại Honda ADV350 và Yamaha XMAX?',
      excerpt:'Mẫu xe tay ga côn lai 350cc mới với nền tảng kỹ thuật Suzuki, giá cạnh tranh.',
      content:'<p>Suzuki Haojue UHR350 ra mắt Đông Nam Á, giá dự kiến 85–90 triệu đồng tại Việt Nam. Động cơ 350cc DOHC 4 van, 29 mã lực, ABS 2 kênh.</p>',
      author:'Quoc Huy', author_avatar:'https://i.pravatar.cc/40?img=55',
      date:'2026-03-24T13:00:00Z', read_time:4, views:8900,
      thumbnail:'https://images.unsplash.com/photo-1558981403-c5f9899a28bc?w=800&q=80',
      tags:JSON.stringify(['Xe','Suzuki','Honda ADV','Yamaha XMAX']), is_featured:0, is_hot:0,
    },
    // ─── thêm 14 bài nữa ────────────────────────────────
    {
      slug:'google-gemini-2-flash-mien-phi', category:'ai', category_label:'AI',
      title:'Google mở miễn phí Gemini 2.0 Flash: Nhanh hơn GPT-4o, dùng không giới hạn',
      excerpt:'Google bất ngờ cho phép tất cả người dùng truy cập Gemini 2.0 Flash không cần trả phí.',
      content:'<p>Google vừa công bố Gemini 2.0 Flash sẽ miễn phí cho toàn bộ người dùng từ tháng 4/2026. Model mới xử lý văn bản, hình ảnh và audio trong một lần gọi API duy nhất, tốc độ phản hồi nhanh hơn GPT-4o khoảng 40% theo benchmark nội bộ.</p><p>Đây là động thái cạnh tranh trực tiếp với OpenAI và Anthropic khi thị trường AI đang bão hòa ở phân khúc trả phí. Google kỳ vọng thu hút developer quay về hệ sinh thái của mình.</p><h3>Điểm nổi bật</h3><p>Gemini 2.0 Flash hỗ trợ ngữ cảnh 1 triệu token, tích hợp Google Search theo thời gian thực và có thể tạo code, phân tích dữ liệu trong một session duy nhất.</p>',
      author:'Thanh Trúc', author_avatar:'https://i.pravatar.cc/40?img=22',
      date:'2026-04-01T08:00:00Z', read_time:4, views:41200,
      thumbnail:'https://images.unsplash.com/photo-1555255707-c07966088b7b?w=800&q=80',
      tags:JSON.stringify(['Google','Gemini','AI','Miễn phí']), is_featured:1, is_hot:1,
    },
    {
      slug:'apple-iphone-17-pro-camera-periscope', category:'mobile', category_label:'Mobile',
      title:'iPhone 17 Pro lộ thiết kế camera periscope 5x hoàn toàn mới, mỏng nhất từ trước đến nay',
      excerpt:'Rò rỉ từ chuỗi cung ứng cho thấy Apple sẽ trang bị zoom periscope cho cả iPhone 17 Pro và Pro Max.',
      content:'<p>Theo thông tin từ Ross Young và Ming-Chi Kuo, iPhone 17 Pro sẽ là thiết bị mỏng nhất Apple từng sản xuất với độ dày chỉ 7.2mm. Camera sau được thiết kế lại hoàn toàn với cụm periscope 5x cho cả hai model Pro.</p><p>Màn hình sẽ được nâng cấp lên OLED ProMotion 2000 nit với refresh rate thích ứng 1-120Hz. Chip A19 Pro sản xuất trên tiến trình 3nm thế hệ hai của TSMC hứa hẹn tiết kiệm năng lượng tốt hơn 20%.</p><h3>Giá dự kiến</h3><p>iPhone 17 Pro dự kiến khởi điểm từ 1.099 USD, tăng 100 USD so với thế hệ trước do chi phí camera mới.</p>',
      author:'Minh Khoa', author_avatar:'https://i.pravatar.cc/40?img=11',
      date:'2026-03-31T10:30:00Z', read_time:3, views:29800,
      thumbnail:'https://images.unsplash.com/photo-1512941937669-90a1b58e7e9c?w=800&q=80',
      tags:JSON.stringify(['Apple','iPhone 17','Camera','Periscope']), is_featured:0, is_hot:1,
    },
    {
      slug:'tiktok-ban-my-chinh-thuc-quay-lai', category:'internet', category_label:'Internet',
      title:'TikTok chính thức quay lại Mỹ sau 3 tháng bị cấm, đạt 10 triệu lượt tải trong 24h',
      excerpt:'ByteDance đạt thỏa thuận với chính phủ Mỹ, TikTok được phép hoạt động trở lại với điều kiện chia sẻ dữ liệu.',
      content:'<p>Sau ba tháng bị gỡ khỏi App Store và Google Play tại Mỹ, TikTok chính thức quay trở lại sau khi ByteDance đạt thỏa thuận với Bộ Tư pháp Mỹ. Theo đó, dữ liệu người dùng Mỹ sẽ được lưu trữ hoàn toàn trên máy chủ Oracle tại Hoa Kỳ.</p><p>Trong 24 giờ đầu sau khi quay lại, TikTok đạt 10 triệu lượt tải — con số kỷ lục chưa từng có với bất kỳ app nào. Giá cổ phiếu Snap và Meta giảm lần lượt 8% và 4% sau thông tin này.</p>',
      author:'Lan Anh', author_avatar:'https://i.pravatar.cc/40?img=44',
      date:'2026-03-30T14:00:00Z', read_time:3, views:55600,
      thumbnail:'https://images.unsplash.com/photo-1611162616475-46b635cb6868?w=800&q=80',
      tags:JSON.stringify(['TikTok','Mỹ','ByteDance','Mạng xã hội']), is_featured:0, is_hot:1,
    },
    {
      slug:'nvidia-rtx-5090-review-viet-nam', category:'do-choi-so', category_label:'Đồ chơi số',
      title:'RTX 5090 về Việt Nam: Đỉnh cao GPU nhưng giá 90 triệu có đáng không?',
      excerpt:'Chúng tôi đã test RTX 5090 trong 2 tuần — đây là kết quả thực tế nhất bạn có thể tìm thấy.',
      content:'<p>RTX 5090 là card đồ họa nhanh nhất thế giới hiện tại, không có gì để bàn cãi. Trong các bài test 4K gaming, card này đạt trung bình 180fps ở Cyberpunk 2077 với tất cả setting max, vượt RTX 4090 khoảng 65%.</p><p>Tuy nhiên, với mức giá 90 triệu đồng tại thị trường Việt Nam, câu hỏi thực sự là: ai cần card này? Với 99% game thủ, RTX 5080 ở mức 45 triệu cho hiệu năng 85% mà giá chỉ bằng một nửa.</p><h3>Kết luận</h3><p>RTX 5090 dành cho content creator và AI researcher hơn là game thủ thông thường. Nếu bạn cần render video 8K hay chạy model AI local, đây là khoản đầu tư hợp lý.</p>',
      author:'Đức Anh', author_avatar:'https://i.pravatar.cc/40?img=33',
      date:'2026-03-29T09:00:00Z', read_time:6, views:19300,
      thumbnail:'https://images.unsplash.com/photo-1591488320449-011701bb6704?w=800&q=80',
      tags:JSON.stringify(['NVIDIA','RTX 5090','GPU','Review']), is_featured:0, is_hot:0,
    },
    {
      slug:'xe-dien-vinfast-vf9-ban-chay-dong-nam-a', category:'xe', category_label:'Xe',
      title:'VinFast VF 9 bán chạy nhất Đông Nam Á Q1/2026, vượt Tesla Model Y',
      excerpt:'VinFast lần đầu vượt Tesla tại thị trường Đông Nam Á với doanh số 12.400 xe trong quý đầu năm.',
      content:'<p>Theo báo cáo từ Hiệp hội Ô tô Đông Nam Á, VinFast VF 9 đạt doanh số 12.400 xe trong Q1/2026, vượt Tesla Model Y ở mức 11.800 xe. Đây là lần đầu tiên một thương hiệu xe điện Việt Nam dẫn đầu thị trường khu vực.</p><p>Giá VF 9 tại Indonesia và Thái Lan thấp hơn Model Y khoảng 15%, kết hợp với chính sách bảo hành pin 10 năm và mạng lưới trạm sạc đang mở rộng nhanh, là những yếu tố then chốt.</p>',
      author:'Quốc Huy', author_avatar:'https://i.pravatar.cc/40?img=55',
      date:'2026-03-28T11:00:00Z', read_time:4, views:14700,
      thumbnail:'https://images.unsplash.com/photo-1593941707882-a5bba14938c7?w=800&q=80',
      tags:JSON.stringify(['VinFast','VF9','Xe điện','Đông Nam Á']), is_featured:0, is_hot:0,
    },
    {
      slug:'deepseek-r2-benchmark-gpt5', category:'ai', category_label:'AI',
      title:'DeepSeek R2 ra mắt: Vượt GPT-5 ở toán học, chi phí rẻ hơn 30 lần',
      excerpt:'Model AI Trung Quốc tiếp tục gây sốc khi DeepSeek R2 đạt điểm toán học cao hơn cả GPT-5.',
      content:'<p>DeepSeek vừa phát hành R2, model AI mới nhất với điểm MATH-500 đạt 97.3%, vượt GPT-5 ở mức 96.1%. Đặc biệt, chi phí API của R2 chỉ bằng 1/30 so với GPT-5 do kiến trúc Mixture of Experts tối ưu hơn.</p><p>Phát hành mã nguồn mở toàn bộ, DeepSeek R2 đã có hơn 200.000 lượt fork trên GitHub chỉ trong 48 giờ đầu. Cổ phiếu NVDA giảm 6% trong phiên giao dịch ngay sau thông báo.</p><h3>Tác động đến thị trường</h3><p>Nhiều công ty AI Mỹ đang xem xét lại chiến lược định giá sau sự kiện này. OpenAI đã hạ giá API GPT-4o xuống 50% vào tuần trước, động thái được cho là phản ứng với áp lực từ DeepSeek.</p>',
      author:'Thanh Trúc', author_avatar:'https://i.pravatar.cc/40?img=22',
      date:'2026-03-27T07:00:00Z', read_time:5, views:38900,
      thumbnail:'https://images.unsplash.com/photo-1620712943543-bcc4688e7485?w=800&q=80',
      tags:JSON.stringify(['DeepSeek','AI','GPT-5','Benchmark']), is_featured:1, is_hot:1,
    },
    {
      slug:'grab-sap-nhap-gojek-dong-nam-a', category:'internet', category_label:'Internet',
      title:'Grab và Gojek sắp sáp nhập? Thương vụ 18 tỷ USD định hình lại Đông Nam Á',
      excerpt:'Bloomberg đưa tin hai siêu app lớn nhất Đông Nam Á đang trong giai đoạn đàm phán sáp nhập cuối cùng.',
      content:'<p>Bloomberg đưa tin Grab và Gojek đang trong vòng đàm phán cuối cùng cho thương vụ sáp nhập trị giá 18 tỷ USD. Nếu thành công, công ty mới sẽ phục vụ hơn 620 triệu người dùng tại 8 quốc gia Đông Nam Á.</p><p>Đây là thương vụ startup lớn nhất lịch sử khu vực, vượt qua thương vụ Lazada–Alibaba năm 2016. Các cơ quan quản lý cạnh tranh tại Singapore, Indonesia và Việt Nam sẽ cần phê duyệt trước khi thỏa thuận có hiệu lực.</p>',
      author:'Lan Anh', author_avatar:'https://i.pravatar.cc/40?img=44',
      date:'2026-03-26T16:00:00Z', read_time:3, views:27400,
      thumbnail:'https://images.unsplash.com/photo-1556742049-0cfed4f6a45d?w=800&q=80',
      tags:JSON.stringify(['Grab','Gojek','Sáp nhập','Đông Nam Á']), is_featured:0, is_hot:1,
    },
    {
      slug:'pubg-mobile-5-ty-luot-tai', category:'apps-game', category_label:'Apps & Game',
      title:'PUBG Mobile cán mốc 5 tỷ lượt tải — tựa game mobile đầu tiên trong lịch sử',
      excerpt:'Krafton công bố PUBG Mobile vượt mốc 5 tỷ lượt tải toàn cầu, một kỳ tích chưa từng có.',
      content:'<p>Krafton vừa công bố PUBG Mobile đã đạt 5 tỷ lượt tải toàn cầu, trở thành tựa game di động đầu tiên trong lịch sử vượt mốc này. Ấn Độ chiếm 30% tổng lượt tải, tiếp theo là Brazil và Indonesia.</p><p>Con số ấn tượng này đạt được dù game bị cấm tại Ấn Độ trong giai đoạn 2020-2022. Phiên bản Battlegrounds Mobile India (BGMI) thay thế giúp Krafton giữ chân người dùng nước này.</p>',
      author:'Đức Anh', author_avatar:'https://i.pravatar.cc/40?img=33',
      date:'2026-03-26T10:00:00Z', read_time:3, views:16200,
      thumbnail:'https://images.unsplash.com/photo-1493711662062-fa541adb3fc8?w=800&q=80',
      tags:JSON.stringify(['PUBG Mobile','Game','Kỷ lục','Krafton']), is_featured:0, is_hot:0,
    },
    {
      slug:'fiber-quang-viet-nam-10gbps-fpt', category:'tin-ict', category_label:'Tin ICT',
      title:'FPT triển khai gói cáp quang 10Gbps tại Hà Nội và TP.HCM, giá chỉ 599.000đ/tháng',
      excerpt:'FPT Telecom chính thức thương mại hóa Internet 10Gbps cho hộ gia đình — nhanh gấp 10 lần gói hiện tại.',
      content:'<p>FPT Telecom vừa công bố gói Internet cáp quang 10Gbps dành cho hộ gia đình tại Hà Nội và TP.HCM với giá 599.000 đồng/tháng. Gói này nhanh gấp 10 lần gói 1Gbps phổ biến nhất hiện tại và được quảng cáo phù hợp cho hộ gia đình nhiều thiết bị 8K streaming và gaming chuyên nghiệp.</p><p>Hạ tầng GPON XGS-PON được triển khai tại 50 quận/huyện trong giai đoạn đầu. Viettel và VNPT dự kiến ra mắt gói tương tự trong Q3/2026.</p>',
      author:'Minh Khoa', author_avatar:'https://i.pravatar.cc/40?img=11',
      date:'2026-03-25T15:00:00Z', read_time:3, views:12100,
      thumbnail:'https://images.unsplash.com/photo-1558494949-ef010cbdcc31?w=800&q=80',
      tags:JSON.stringify(['FPT','Internet','Cáp quang','10Gbps']), is_featured:0, is_hot:0,
    },
    {
      slug:'facebook-thiet-ke-moi-2026', category:'internet', category_label:'Internet',
      title:'Facebook ra mắt giao diện hoàn toàn mới — lần đầu thiết kế lại toàn diện sau 6 năm',
      excerpt:'Meta công bố Facebook redesign 2026 với feed thông minh hơn, stories biến mất và Reels chiếm vị trí trung tâm.',
      content:'<p>Meta vừa giới thiệu giao diện mới hoàn toàn cho Facebook, lần đầu tiên kể từ thiết kế năm 2020. Thay đổi lớn nhất là Stories không còn xuất hiện ở đầu feed — thay vào đó, Reels chiếm toàn bộ cột bên phải trên desktop.</p><p>Feed chính được tổ chức lại theo thuật toán "Relevant to You" thay vì chronological, gây ra làn sóng phản đối từ người dùng cũ. Tuy nhiên, Meta cho biết thời gian sử dụng tăng 22% trong giai đoạn thử nghiệm.</p>',
      author:'Lan Anh', author_avatar:'https://i.pravatar.cc/40?img=44',
      date:'2026-03-24T08:00:00Z', read_time:3, views:21500,
      thumbnail:'https://images.unsplash.com/photo-1611162617213-7d7a39e9b1d7?w=800&q=80',
      tags:JSON.stringify(['Facebook','Meta','Thiết kế','Mạng xã hội']), is_featured:0, is_hot:0,
    },
    {
      slug:'viet-nam-trung-tam-ai-dong-nam-a', category:'tin-ict', category_label:'Tin ICT',
      title:'Việt Nam lọt top 3 quốc gia phát triển AI nhanh nhất Đông Nam Á năm 2026',
      excerpt:'Báo cáo của Google và Temasek xếp Việt Nam thứ ba về tốc độ tăng trưởng hệ sinh thái AI trong khu vực.',
      content:'<p>Theo báo cáo e-Conomy SEA 2026 của Google, Temasek và Bain & Company, Việt Nam đứng thứ ba Đông Nam Á về tốc độ phát triển hệ sinh thái AI, chỉ sau Singapore và Indonesia. Số lượng startup AI Việt Nam tăng 340% trong 2 năm qua.</p><p>Các yếu tố được ghi nhận bao gồm: chính sách thu hút đầu tư AI của chính phủ, nguồn nhân lực STEM trẻ và chi phí vận hành thấp hơn 60% so với Singapore. FPT, VNG và VinAI đang dẫn đầu làn sóng này.</p>',
      author:'Quốc Huy', author_avatar:'https://i.pravatar.cc/40?img=55',
      date:'2026-03-22T09:00:00Z', read_time:5, views:8900,
      thumbnail:'https://images.unsplash.com/photo-1451187580459-43490279c0fa?w=800&q=80',
      tags:JSON.stringify(['Việt Nam','AI','Đông Nam Á','Startup']), is_featured:0, is_hot:0,
    },
    {
      slug:'claude-4-anthropic-ra-mat', category:'ai', category_label:'AI',
      title:'Anthropic ra mắt Claude 4: Vượt GPT-5 ở lập luận, từ chối viết malware dù bị ép buộc',
      excerpt:'Claude 4 của Anthropic đánh dấu bước tiến về safety AI — model đầu tiên có thể giải thích lý do từ chối.',
      content:'<p>Anthropic vừa phát hành Claude 4 với điểm benchmark MMLU đạt 92.4%, vượt GPT-5 ở các tác vụ lập luận đa bước và phân tích pháp lý. Điểm đặc biệt là Claude 4 có thể giải thích chi tiết lý do từ chối các yêu cầu vi phạm nguyên tắc an toàn.</p><p>Trong bài test red-teaming độc lập, Claude 4 từ chối 100% yêu cầu viết malware và tổng hợp hóa chất nguy hiểm, kể cả khi người dùng dùng các kỹ thuật jailbreak phức tạp. Đây là lần đầu tiên một model đạt tỷ lệ từ chối hoàn hảo trong danh mục này.</p>',
      author:'Thanh Trúc', author_avatar:'https://i.pravatar.cc/40?img=22',
      date:'2026-03-21T11:00:00Z', read_time:5, views:33100,
      thumbnail:'https://images.unsplash.com/photo-1668854270929-ef9b4943dcd6?w=800&q=80',
      tags:JSON.stringify(['Anthropic','Claude 4','AI','Safety']), is_featured:0, is_hot:0,
    },
    {
      slug:'khong-gian-tam-ly-cong-nghe-nguoi-dung', category:'kham-pha', category_label:'Khám phá',
      title:'Nghiên cứu mới: Người dùng smartphone trung bình chạm vào màn hình 2.617 lần mỗi ngày',
      excerpt:'Dữ liệu từ 50.000 người dùng Android tiết lộ thói quen sử dụng điện thoại đáng kinh ngạc của con người hiện đại.',
      content:'<p>Nghiên cứu mới nhất từ Đại học Humboldt (Đức) theo dõi 50.000 người dùng Android trong 6 tháng cho thấy số lần chạm màn hình trung bình là 2.617 lần/ngày — tương đương 3 tiếng 15 phút tổng thời gian tương tác thực tế.</p><p>Điều thú vị là 47% lần mở điện thoại không có mục đích rõ ràng — người dùng chỉ mở ra và đóng lại trong vòng 15 giây. Nhóm tuổi 18-24 có số lần chạm cao gấp đôi nhóm 45-54 tuổi.</p><h3>Ứng dụng gây nghiện nhất</h3><p>TikTok dẫn đầu với 89 phút/ngày trung bình, tiếp theo là Instagram (64 phút) và YouTube (58 phút). Facebook lần đầu tiên rời top 3 sau 10 năm liên tiếp.</p>',
      author:'Minh Khoa', author_avatar:'https://i.pravatar.cc/40?img=11',
      date:'2026-03-20T14:00:00Z', read_time:5, views:24600,
      thumbnail:'https://images.unsplash.com/photo-1512428559087-560fa5ceab42?w=800&q=80',
      tags:JSON.stringify(['Nghiên cứu','Smartphone','Tâm lý học','Thói quen']), is_featured:0, is_hot:0,
    },
  ]);
  console.log('[seed] 22 bài viết');

  // ── Seed view_log: tạo lịch sử xem thực tế dựa trên views đã seed ──
  // Thay vì hardcode views=18420, tạo view_log records để số liệu có nguồn gốc thật
  var seededArticles = db.prepare('SELECT id, views, shares FROM articles').all();
  var logView = db.prepare('INSERT OR IGNORE INTO view_log (article_id, ip, created_at) VALUES (?,?,?)');
  var ips = [
    '118.70.1.','203.162.4.','171.244.2.','14.160.3.','42.114.5.',
    '113.160.6.','27.72.7.','115.79.8.','1.55.9.','222.252.10.',
  ];

  // Tạo view_log cho 30 ngày qua — phân phối theo views đã seed
  db.transaction(function() {
    var now = Date.now();
    var day = 86400000;
    seededArticles.forEach(function(art) {
      // Phân phối views ngẫu nhiên trong 30 ngày, nhiều hơn ở ngày đầu
      var totalViews = Math.min(art.views, 200); // giới hạn records để không quá nặng
      for (var v = 0; v < totalViews; v++) {
        var daysAgo = Math.floor(Math.pow(Math.random(), 2) * 30); // exponential decay
        var ts = new Date(now - daysAgo * day - Math.random() * day);
        var ipBase = ips[Math.floor(Math.random() * ips.length)];
        var ip = ipBase + (Math.floor(Math.random() * 254) + 1);
        logView.run(art.id, ip, ts.toISOString());
      }
    });
  })();
  console.log('[seed] Đã tạo lịch sử lượt xem');
}

// Seed admin user
if (db.prepare("SELECT COUNT(*) as c FROM users WHERE role='admin'").get().c === 0) {
  var hash = bcrypt.hashSync('admin123456', 10);
  db.prepare("INSERT INTO users (name,email,password,avatar,role,status) VALUES (?,?,?,?,?,?)")
    .run('Admin', 'admin@techpulse.vn', hash, 'https://i.pravatar.cc/80?img=1', 'admin', 'active');
  console.log('[seed] Đã tạo tài khoản admin');
}

// Seed default site settings
if (db.prepare("SELECT COUNT(*) as c FROM site_settings").get().c === 0) {
  var settingInsert = db.prepare("INSERT OR IGNORE INTO site_settings (key, value) VALUES (?, ?)");
  db.transaction(function(rows) { for (var r of rows) settingInsert.run(r.k, r.v); })([
    { k:'siteName',    v:'TechPulse' },
    { k:'domain',      v:'techpulse.vn' },
    { k:'email',       v:'noreply@techpulse.vn' },
    { k:'description', v:'Tin tức công nghệ mới nhất' },
  ]);
  console.log('[seed] Đã tạo cài đặt hệ thống');
}

if (db.prepare("SELECT COUNT(*) as c FROM products").get().c === 0) {
  var insProduct = db.prepare(`
    INSERT INTO products (name, category, tags, price, stock, trend_score, season_tags, status, updated_at)
    VALUES (?,?,?,?,?,?,?, 'active', datetime('now'))
  `);
  db.transaction(function(rows) { rows.forEach(function(r) { insProduct.run(r.name, r.category, r.tags, r.price, r.stock, r.trend, r.season); }); })([
    { name: 'iPhone 15 Pro Ốp lưng', category: 'mobile', tags: JSON.stringify(['iphone','apple','op-lung']), price: 390000, stock: 100, trend: 72, season: JSON.stringify(['all']) },
    { name: 'Tai nghe Bluetooth ANC', category: 'do-choi-so', tags: JSON.stringify(['audio','bluetooth','anc']), price: 1490000, stock: 50, trend: 66, season: JSON.stringify(['all']) },
    { name: 'Áo khoác công nghệ giữ nhiệt', category: 'kham-pha', tags: JSON.stringify(['ao-khoac','mua-dong','fashion-tech']), price: 890000, stock: 40, trend: 58, season: JSON.stringify(['winter']) },
    { name: 'Gói camera hành trình AI', category: 'xe', tags: JSON.stringify(['xe','camera','ai']), price: 2590000, stock: 25, trend: 61, season: JSON.stringify(['all']) },
    { name: 'Combo pin sạc dự phòng 20k', category: 'mobile', tags: JSON.stringify(['pin','sac-nhanh','travel']), price: 690000, stock: 70, trend: 54, season: JSON.stringify(['summer']) },
  ]);
  console.log('[seed] Đã tạo product catalog mẫu');
}

// ============================================================
// SYNC VIEWS TỪ VIEW_LOG THỰC TẾ (chạy mỗi lần khởi động)
// ============================================================
(function syncViewsFromLog() {
  try {
    // Chỉ backfill 1 lần khi boot: total_views không bao giờ giảm
    var realViews = db.prepare(`
      SELECT article_id, COUNT(*) as real_views
      FROM view_log
      GROUP BY article_id
    `).all();

    var update = db.prepare(`
      UPDATE articles
      SET total_views = CASE WHEN ? > total_views THEN ? ELSE total_views END,
          views = CASE WHEN ? > views THEN ? ELSE views END
      WHERE id = ?
    `);
    db.transaction(function() {
      realViews.forEach(function(row) {
        update.run(row.real_views, row.real_views, row.real_views, row.real_views, row.article_id);
      });
    })();

    db.prepare(`
      UPDATE articles SET
        is_hot = CASE
          WHEN (
            (SELECT COUNT(*) FROM view_log
             WHERE article_id = articles.id
             AND created_at > datetime('now', '-24 hours')) * 3
            + shares * 5
            + (total_views / 100) * 2
          ) > 50 THEN 1
          ELSE is_hot
        END
      WHERE status = 'published' AND deleted_at IS NULL
    `).run();

    console.log('[sync] Đã backfill total_views từ view_log (' + realViews.length + ' bài)');
  } catch(e) {
    console.warn('[sync] Lỗi đồng bộ views:', e.message);
  }
})();

// ── Bounce rate: tính từ view_log (duration_sec < 30s = bounce) ─────────────
setInterval(function() {
  try {
    db.prepare(`
      UPDATE articles SET bounce_rate = (
        SELECT ROUND(
          100.0 * SUM(CASE WHEN duration_sec < 30 THEN 1 ELSE 0 END)
          / NULLIF(COUNT(*), 0)
        , 1)
        FROM view_log WHERE article_id = articles.id
      )
      WHERE status = 'published'
    `).run();
  } catch(e) {}
}, 15 * 60 * 1000); // mỗi 15 phút

// Job tong hop stats theo ngay (moi 10 phut cap nhat 1 lan)
setInterval(function() {
  try {
    db.exec('UPDATE articles SET views = total_views');
    var day = new Date().toISOString().slice(0, 10);
    var upsertDaily = db.prepare(`
      INSERT INTO stats_daily (day, metric_group, metric_key, metric_value, created_at)
      VALUES (?, ?, ?, ?, datetime('now'))
    `);
    var totals = {
      users: db.prepare('SELECT COUNT(*) as c FROM users').get().c || 0,
      views: db.prepare('SELECT COUNT(*) as c FROM view_log WHERE created_at >= datetime(\'now\', \'-1 day\')').get().c || 0,
      comments: db.prepare('SELECT COUNT(*) as c FROM comments WHERE deleted_at IS NULL').get().c || 0,
      ads_revenue: db.prepare('SELECT COALESCE(SUM(revenue),0) as v FROM ad_campaigns').get().v || 0,
    };
    db.transaction(function() {
      db.prepare('DELETE FROM stats_daily WHERE day=?').run(day);
      Object.keys(totals).forEach(function(k) {
        upsertDaily.run(day, 'system', k, totals[k]);
      });
    })();
  } catch (_e) {}
}, 10 * 60 * 1000);

// ============================================================
// PREPARED STATEMENTS
// ============================================================

const stmt = {
  // Articles
  articleById:   db.prepare('SELECT * FROM articles WHERE id=? AND deleted_at IS NULL'),
  articleBySlug: db.prepare('SELECT * FROM articles WHERE slug=? AND deleted_at IS NULL'),
  incrViews:     db.prepare('UPDATE articles SET total_views=total_views+1, views=total_views+1 WHERE id=?'),
  incrShares:    db.prepare('UPDATE articles SET shares=shares+1 WHERE id=?'),
  softDelete:    db.prepare("UPDATE articles SET deleted_at=datetime('now'), status='archived' WHERE id=?"),
  hardDelete:    db.prepare('DELETE FROM articles WHERE id=?'),
  related:       db.prepare("SELECT * FROM articles WHERE category=? AND id!=? AND status='published' AND deleted_at IS NULL ORDER BY total_views DESC LIMIT 4"),
  trending:      db.prepare("SELECT * FROM articles WHERE status='published' AND deleted_at IS NULL ORDER BY total_views DESC LIMIT ?"),
  searchArticles:db.prepare("SELECT * FROM articles WHERE status='published' AND deleted_at IS NULL AND (title LIKE ? OR excerpt LIKE ? OR content LIKE ? OR tags LIKE ?) ORDER BY date DESC"),

  // Users
  userById:      db.prepare('SELECT * FROM users WHERE id=?'),
  userByEmail:   db.prepare('SELECT * FROM users WHERE email=?'),
  insertUser:    db.prepare('INSERT INTO users (name,email,password,avatar) VALUES (?,?,?,?)'),
  updateProfile: db.prepare("UPDATE users SET name=?,avatar=?,updated_at=datetime('now') WHERE id=?"),
  updatePw:      db.prepare('UPDATE users SET password=? WHERE id=?'),
  updateLastSeen:db.prepare("UPDATE users SET last_ip=?,last_device=?,updated_at=datetime('now') WHERE id=?"),
  allUsers:      db.prepare('SELECT id,name,email,avatar,role,status,phone,last_ip,last_device,created_at,updated_at FROM users ORDER BY id DESC'),
  countUsers:    db.prepare('SELECT COUNT(*) as c FROM users'),

  // Bookmarks
  getBookmarks:  db.prepare('SELECT article_id FROM bookmarks WHERE user_id=?'),
  hasBookmark:   db.prepare('SELECT 1 FROM bookmarks WHERE user_id=? AND article_id=?'),
  addBookmark:   db.prepare('INSERT OR IGNORE INTO bookmarks (user_id,article_id) VALUES (?,?)'),
  delBookmark:   db.prepare('DELETE FROM bookmarks WHERE user_id=? AND article_id=?'),

  // Comments
  getComments:   db.prepare(`
    SELECT c.id, c.content, c.created_at, c.deleted_at,
           u.id as user_id, u.name as user_name, u.avatar as user_avatar
    FROM comments c JOIN users u ON c.user_id=u.id
    WHERE c.article_id=? AND c.deleted_at IS NULL
    ORDER BY c.created_at DESC
    LIMIT ? OFFSET ?
  `),
  countComments:    db.prepare('SELECT COUNT(*) as c FROM comments WHERE article_id=? AND deleted_at IS NULL'),
  addComment:       db.prepare('INSERT INTO comments (article_id,user_id,content) VALUES (?,?,?)'),
  commentById:      db.prepare('SELECT * FROM comments WHERE id=? AND deleted_at IS NULL'),
  softDelComment:   db.prepare("UPDATE comments SET deleted_at=datetime('now') WHERE id=?"),

  // Newsletters
  nlByEmail:     db.prepare('SELECT * FROM newsletters WHERE email=?'),
  nlInsert:      db.prepare('INSERT INTO newsletters (email,frequency,topics) VALUES (?,?,?)'),
  nlUpdate:      db.prepare("UPDATE newsletters SET frequency=?,topics=?,updated_at=datetime('now') WHERE email=?"),

  // Notifications
  getNotif:      db.prepare('SELECT * FROM notification_settings WHERE user_id=?'),
  upsertNotif:   db.prepare(`
    INSERT INTO notification_settings (user_id,email_on,breaking,weekly,marketing) VALUES (?,?,?,?,?)
    ON CONFLICT(user_id) DO UPDATE SET
      email_on=excluded.email_on, breaking=excluded.breaking,
      weekly=excluded.weekly, marketing=excluded.marketing
  `),

  // View log
  logView:              db.prepare('INSERT INTO view_log (article_id, user_id, ip, user_agent) VALUES (?,?,?,?)'),
  updateViewDuration:   db.prepare("UPDATE view_log SET duration_sec=? WHERE id=(SELECT id FROM view_log WHERE article_id=? AND ip=? AND duration_sec IS NULL ORDER BY created_at DESC LIMIT 1)"),
  hasViewedRecently:    db.prepare("SELECT 1 FROM view_log WHERE article_id=? AND ip=? AND created_at > datetime('now','-1 hour')"),

  // User stats
  upsertUserStats: db.prepare(`
    INSERT INTO user_stats (user_id, total_views, total_comments, total_shares)
      VALUES (?,?,?,?)
    ON CONFLICT(user_id) DO UPDATE SET
      total_views    = excluded.total_views,
      total_comments = excluded.total_comments,
      total_shares   = excluded.total_shares,
      updated_at     = datetime('now')
  `),

  // User interests
  upsertInterest: db.prepare(`
    INSERT INTO user_interests (user_id, category, score)
      VALUES (?,?,1)
    ON CONFLICT(user_id, category) DO UPDATE SET
      score      = score + 1,
      updated_at = datetime('now')
  `),
  upsertInterestWeighted: db.prepare(`
    INSERT INTO user_interests (user_id, category, score)
      VALUES (?,?,?)
    ON CONFLICT(user_id, category) DO UPDATE SET
      score      = score + excluded.score,
      updated_at = datetime('now')
  `),
  getUserInterests: db.prepare('SELECT category, score FROM user_interests WHERE user_id=? ORDER BY score DESC'),

  // User analytics events
  insertAnalyticsEvent: db.prepare(`
    INSERT INTO user_analytics_events
      (user_id, actor_name, event_type, event_target, metadata_json, source, created_at)
    VALUES (?,?,?,?,?,?,?)
  `),
  recentAnalyticsEvents: db.prepare(`
    SELECT id, event_type, event_target, metadata_json, source, created_at
    FROM user_analytics_events
    WHERE user_id=?
    ORDER BY datetime(created_at) DESC
    LIMIT ?
  `),
  countAnalyticsEventsToday: db.prepare(`
    SELECT COUNT(*) as c
    FROM user_analytics_events
    WHERE user_id=?
      AND created_at >= datetime('now', 'start of day')
  `),
  insertAnalyticsSyncRequest: db.prepare(`
    INSERT INTO analytics_sync_requests
      (request_id, user_id, source, input_json, result_json, status, error_message, created_at, processed_at)
    VALUES (?,?,?,?,?,?,?,?,?)
  `),
  updateAnalyticsSyncRequest: db.prepare(`
    UPDATE analytics_sync_requests
    SET result_json=?, status=?, error_message=?, processed_at=?
    WHERE request_id=?
  `),
  analyticsSyncByRequestId: db.prepare(`
    SELECT request_id, user_id, source, input_json, result_json, status, error_message, created_at, processed_at
    FROM analytics_sync_requests
    WHERE request_id=?
  `),
  analyticsSyncRecentByUser: db.prepare(`
    SELECT request_id, source, status, error_message, created_at, processed_at
    FROM analytics_sync_requests
    WHERE user_id=?
    ORDER BY datetime(created_at) DESC
    LIMIT ?
  `),
  // Ads
  adCampaigns: db.prepare(`
    SELECT id, name, platform, status, budget, spent, revenue, impressions, clicks, ctr, target_tags, starts_at, ends_at, created_at, updated_at
    FROM ad_campaigns
    ORDER BY id DESC
    LIMIT ? OFFSET ?
  `),
  adCampaignCount: db.prepare('SELECT COUNT(*) as c FROM ad_campaigns'),
  adCampaignById: db.prepare('SELECT * FROM ad_campaigns WHERE id=?'),
  addCampaign: db.prepare(`
    INSERT INTO ad_campaigns
      (name, platform, status, budget, spent, revenue, impressions, clicks, ctr, target_tags, starts_at, ends_at, updated_at)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,datetime('now'))
  `),
  updateCampaign: db.prepare(`
    UPDATE ad_campaigns SET
      name=?, platform=?, status=?, budget=?, spent=?, revenue=?, impressions=?, clicks=?, ctr=?, target_tags=?, starts_at=?, ends_at=?, updated_at=datetime('now')
    WHERE id=?
  `),
  delCampaign: db.prepare('DELETE FROM ad_campaigns WHERE id=?'),
  addAdEvent: db.prepare(`
    INSERT INTO ad_events (campaign_id, user_id, event_type, value, created_at)
    VALUES (?,?,?,?,?)
  `),
  productList: db.prepare(`
    SELECT id, name, category, tags, price, stock, trend_score, season_tags, status, created_at, updated_at
    FROM products
    WHERE status='active' AND stock > 0
    ORDER BY trend_score DESC, id DESC
    LIMIT ?
  `),
  productById: db.prepare('SELECT * FROM products WHERE id=?'),
  adminProductList: db.prepare(`
    SELECT id, name, category, tags, price, stock, trend_score, season_tags, status, created_at, updated_at
    FROM products
    ORDER BY id DESC
    LIMIT ? OFFSET ?
  `),
  adminProductCount: db.prepare('SELECT COUNT(*) as c FROM products'),
  addProduct: db.prepare(`
    INSERT INTO products (name, category, tags, price, stock, trend_score, season_tags, status, updated_at)
    VALUES (?,?,?,?,?,?,?,?,datetime('now'))
  `),
  updateProduct: db.prepare(`
    UPDATE products SET
      name=?, category=?, tags=?, price=?, stock=?, trend_score=?, season_tags=?, status=?, updated_at=datetime('now')
    WHERE id=?
  `),
  delProduct: db.prepare('DELETE FROM products WHERE id=?'),
  // Sessions + activity
  addSession: db.prepare(`
    INSERT INTO user_sessions (user_id, token_hash, ip, user_agent, created_at, expires_at)
    VALUES (?,?,?,?,?,?)
  `),
  revokeSessionByHash: db.prepare("UPDATE user_sessions SET revoked_at=datetime('now') WHERE token_hash=?"),
  addUserActivity: db.prepare(`
    INSERT INTO user_activity_log (user_id, activity_type, payload_json, created_at)
    VALUES (?,?,?,?)
  `),
};

// ============================================================
// HELPERS
// ============================================================

const CATEGORIES = [
  { id:'mobile',     label:'Mobile' },
  { id:'ai',         label:'AI' },
  { id:'tin-ict',    label:'Tin ICT' },
  { id:'internet',   label:'Internet' },
  { id:'kham-pha',   label:'Kham pha' },
  { id:'xe',         label:'Xe' },
  { id:'apps-game',  label:'Apps & Game' },
  { id:'do-choi-so', label:'Đồ chơi số' },
  { id:'tra-da-cn',  label:'Trà đá CN' },
];
const VALID_CATEGORY_IDS = new Set(CATEGORIES.map(function(c) { return c.id; }));
const VALID_STATUSES = new Set(['published', 'draft', 'archived']);
const VALID_ROLES    = new Set(['admin', 'editor', 'premium', 'user']);
const VALID_USER_STATUSES = new Set(['active', 'premium', 'pending', 'banned']);
const VALID_ANALYTICS_EVENT_TYPES = new Set([
  'click', 'read', 'share', 'view_article', 'bookmark', 'comment', 'search', 'login'
]);
const MAX_ANALYTICS_EVENTS_PER_USER_PER_DAY = parseInt(process.env.MAX_ANALYTICS_EVENTS_PER_USER_PER_DAY || '5000', 10);
const LOG_RETENTION_DAYS = parseInt(process.env.LOG_RETENTION_DAYS || '90', 10);
const INTEREST_DECAY_RATE = parseFloat(process.env.INTEREST_DECAY_RATE || '0.95'); // giảm 5%
const INTEREST_DECAY_INTERVAL_MS = parseInt(process.env.INTEREST_DECAY_INTERVAL_MS || String(10 * 60 * 1000), 10);

function res_ok(res, data, status) {
  return res.status(status || 200).json({ success: true, data: data });
}
function res_err(res, message, status) {
  return res.status(status || 400).json({ success: false, error: message });
}

function stripHtml(html) {
  return (html || '').replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
}

function safeText(input, maxLen) {
  return String(input || '')
    .replace(/[\u0000-\u001f\u007f]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, maxLen || 255);
}

function buildRequestId(prefix) {
  var p = safeText(prefix || 'req', 20).toLowerCase() || 'req';
  return p + '-' + Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 10);
}

function defaultDisplayName(user) {
  var name = safeText(user && user.name, 100);
  if (name) return name;
  var email = safeText(user && user.email, 200);
  if (email.includes('@')) return email.split('@')[0].slice(0, 100);
  return 'user-' + String(user && user.id || 'unknown');
}

function normalizeInterests(rawInterests) {
  if (!Array.isArray(rawInterests)) return [];
  var seen = new Set();
  var out = [];
  rawInterests.forEach(function(item) {
    var normalized = safeText(item, 50).toLowerCase();
    if (!normalized || seen.has(normalized)) return;
    seen.add(normalized);
    out.push(normalized);
  });
  return out.slice(0, 20);
}

function normalizeActivities(rawActivities) {
  if (!Array.isArray(rawActivities)) return [];
  var out = [];
  rawActivities.slice(0, 100).forEach(function(item) {
    item = item || {};
    var ts = item.timestamp ? new Date(item.timestamp) : new Date();
    if (isNaN(ts.getTime())) ts = new Date();
    var type = safeText(item.type || item.action || 'unknown', 50).toLowerCase();
    if (!VALID_ANALYTICS_EVENT_TYPES.has(type)) return;
    var metadata = item.metadata && typeof item.metadata === 'object' ? item.metadata : {};
    var metadataJson = JSON.stringify(metadata || {});
    if (metadataJson.length > 2000) return;
    out.push({
      type: type,
      target: safeText(item.target || '', 120) || null,
      metadata: JSON.parse(metadataJson),
      timestamp: ts.toISOString(),
    });
  });
  return out;
}

function safeJsonArrayText(raw, limit) {
  if (!Array.isArray(raw)) return [];
  return raw.map(function(v) { return safeText(v, 50).toLowerCase(); }).filter(Boolean).slice(0, limit || 20);
}

function parseJsonArraySafe(text) {
  try {
    var arr = JSON.parse(text || '[]');
    return Array.isArray(arr) ? arr : [];
  } catch (_e) {
    return [];
  }
}

function getSeasonHints() {
  var m = new Date().getMonth() + 1;
  if ([11, 12, 1].includes(m)) return ['winter', 'mua-dong', 'tet', 'new-year'];
  if ([2, 3, 4].includes(m)) return ['spring', 'mua-xuan', 'travel'];
  if ([5, 6, 7].includes(m)) return ['summer', 'mua-he', 'du-lich', 'beach'];
  return ['autumn', 'mua-thu', 'back-to-school'];
}

function interestWeightForAction(actionType) {
  if (actionType === 'read' || actionType === 'view_article') return 10;
  if (actionType === 'share') return 12;
  if (actionType === 'bookmark') return 8;
  if (actionType === 'click') return 5;
  return 3;
}

function buildShopRecommendations(userId, limit) {
  var lim = Math.min(20, Math.max(1, parseInt(limit, 10) || 8));
  var interests = stmt.getUserInterests.all(userId).slice(0, 50);
  var interestMap = {};
  var maxInterest = 1;
  interests.forEach(function(r) {
    var key = safeText(r.category, 50).toLowerCase();
    var score = Number(r.score || 0);
    interestMap[key] = score;
    if (score > maxInterest) maxInterest = score;
  });

  var trendingSignals = {};
  db.prepare(`
    SELECT a.category, COUNT(*) as c
    FROM view_log vl JOIN articles a ON a.id = vl.article_id
    WHERE vl.created_at >= datetime('now', '-7 days')
    GROUP BY a.category
    ORDER BY c DESC
    LIMIT 12
  `).all().forEach(function(r) { trendingSignals[safeText(r.category, 50).toLowerCase()] = Number(r.c || 0); });
  var maxTrend = Math.max(1, Object.values(trendingSignals).reduce(function(a, b) { return Math.max(a, b); }, 1));

  var collaborative = {};
  db.prepare(`
    SELECT ui2.category, SUM(ui2.score) as s
    FROM user_interests ui1
    JOIN user_interests ui2 ON ui1.category = ui2.category AND ui1.user_id != ui2.user_id
    WHERE ui1.user_id = ?
    GROUP BY ui2.category
    ORDER BY s DESC
    LIMIT 15
  `).all(userId).forEach(function(r) {
    collaborative[safeText(r.category, 50).toLowerCase()] = Number(r.s || 0);
  });
  var seasonHints = getSeasonHints();

  var products = stmt.productList.all(300).map(function(p) {
    var tags = [];
    var seasonTags = [];
    try { tags = safeJsonArrayText(JSON.parse(p.tags || '[]'), 20); } catch (_e) {}
    try { seasonTags = safeJsonArrayText(JSON.parse(p.season_tags || '[]'), 20); } catch (_e) {}

    var topicTokens = [safeText(p.category, 50).toLowerCase()].concat(tags);
    var maxMatched = 0;
    topicTokens.forEach(function(t) { if (interestMap[t] && interestMap[t] > maxMatched) maxMatched = interestMap[t]; });
    var interestScore = Math.round((maxMatched / maxInterest) * 100);

    var trendScoreBase = Number(p.trend_score || 0);
    topicTokens.forEach(function(t) {
      if (trendingSignals[t]) trendScoreBase += (trendingSignals[t] / maxTrend) * 25;
    });
    var trendingScore = Math.max(0, Math.min(100, Math.round(trendScoreBase)));

    var seasonalScore = 30;
    if (!seasonTags.length || seasonTags.includes('all')) seasonalScore = 70;
    if (seasonTags.some(function(t) { return seasonHints.includes(t); })) seasonalScore = 100;

    var collaborativeBonus = 0;
    topicTokens.forEach(function(t) {
      if (collaborative[t]) collaborativeBonus = Math.max(collaborativeBonus, Math.min(15, Math.round(collaborative[t] / 20)));
    });

    var finalScore = (interestScore * 0.5) + (trendingScore * 0.3) + (seasonalScore * 0.2) + collaborativeBonus;
    return {
      id: p.id,
      name: p.name,
      category: p.category,
      tags: tags,
      price: p.price,
      stock: p.stock,
      trendScore: Number(p.trend_score || 0),
      score: Math.round(finalScore * 100) / 100,
      scoreDetail: {
        interest: interestScore,
        trending: trendingScore,
        seasonal: seasonalScore,
        collaborativeBonus: collaborativeBonus,
      },
    };
  });

  return products.sort(function(a, b) { return b.score - a.score; }).slice(0, lim);
}

function buildRuntimeCache(dbRef) {
  dbRef.exec(`
    CREATE TABLE IF NOT EXISTS runtime_cache (
      cache_key   TEXT PRIMARY KEY,
      value_json  TEXT NOT NULL,
      expires_at  TEXT NOT NULL,
      updated_at  TEXT DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_runtime_cache_expires ON runtime_cache(expires_at);
  `);

  return {
    get: function(key) {
      var row = dbRef.prepare('SELECT value_json, expires_at FROM runtime_cache WHERE cache_key=?').get(key);
      if (!row) return null;
      if (new Date(row.expires_at).getTime() <= Date.now()) {
        dbRef.prepare('DELETE FROM runtime_cache WHERE cache_key=?').run(key);
        return null;
      }
      try { return JSON.parse(row.value_json); } catch (_e) { return null; }
    },
    set: function(key, value, ttlMs) {
      var ttl = Math.max(1000, parseInt(ttlMs, 10) || 600000);
      var expiresAt = new Date(Date.now() + ttl).toISOString();
      dbRef.prepare(`
        INSERT INTO runtime_cache (cache_key, value_json, expires_at, updated_at)
        VALUES (?, ?, ?, datetime('now'))
        ON CONFLICT(cache_key) DO UPDATE SET
          value_json=excluded.value_json,
          expires_at=excluded.expires_at,
          updated_at=datetime('now')
      `).run(key, JSON.stringify(value || {}), expiresAt);
    },
    delByPrefix: function(prefix) {
      dbRef.prepare('DELETE FROM runtime_cache WHERE cache_key LIKE ?').run(prefix + '%');
    },
    cleanup: function() {
      dbRef.prepare("DELETE FROM runtime_cache WHERE datetime(expires_at) <= datetime('now')").run();
    },
  };
}

function installRequestAuditMiddleware(appRef, dbRef) {
  dbRef.exec(`
    CREATE TABLE IF NOT EXISTS request_audit_log (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      request_id    TEXT NOT NULL,
      user_id       INTEGER,
      method        TEXT NOT NULL,
      route_path    TEXT NOT NULL,
      status_code   INTEGER,
      duration_ms   INTEGER DEFAULT 0,
      ip            TEXT,
      error_message TEXT,
      created_at    TEXT DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_audit_created ON request_audit_log(created_at);
    CREATE INDEX IF NOT EXISTS idx_audit_user    ON request_audit_log(user_id);
  `);
  var insertAudit = dbRef.prepare(`
    INSERT INTO request_audit_log
      (request_id, user_id, method, route_path, status_code, duration_ms, ip, error_message, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  appRef.use(function(req, res, next) {
    var start = Date.now();
    var rid = 'rq-' + Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 8);
    req.requestId = rid;
    res.setHeader('X-Request-Id', rid);
    res.on('finish', function() {
      try {
        insertAudit.run(
          rid,
          req.user && req.user.id ? req.user.id : null,
          req.method,
          req.path,
          res.statusCode,
          Date.now() - start,
          req.ip || null,
          res.statusCode >= 500 ? 'internal_error' : null,
          new Date().toISOString()
        );
      } catch (_e) {}
    });
    next();
  });
}

function createAdEngine(dbRef, cacheRef) {
  return {
    recommendAds: function(userId, limit) {
      var lim = Math.min(10, Math.max(1, parseInt(limit, 10) || 3));

      // Lay interests tu ca 2 bang: user_interests (cu) va user_interests_signal (moi)
      var interests = [];
      try {
        var si = dbRef.prepare(
          "SELECT tag as category, decay_score as score FROM user_interests_signal WHERE user_id=? AND level IN ('MEDIUM','HIGH') ORDER BY decay_score DESC LIMIT 6"
        ).all(userId);
        var ui = dbRef.prepare(
          "SELECT category, score FROM user_interests WHERE user_id=? ORDER BY score DESC LIMIT 6"
        ).all(userId);
        // Merge, uu tien signal interests
        var seen = new Set();
        si.forEach(function(r) { interests.push(r.category); seen.add(r.category); });
        ui.forEach(function(r) { if (!seen.has(r.category)) interests.push(r.category); });
      } catch(_e) {}

      // Lay ads ACTIVE con budget
      var ads = dbRef.prepare(`
        SELECT id, name, platform, ctr, budget, spent, revenue, target_tags, starts_at, ends_at, daily_cap, frequency_cap
        FROM ad_campaigns
        WHERE status='active' AND (ends_at IS NULL OR ends_at >= date('now'))
        ORDER BY revenue DESC, ctr DESC
        LIMIT 50
      `).all();

      // Kiem tra frequency_cap cho user nay
      var now = new Date().toISOString().slice(0, 10);
      return ads.map(function(ad) {
        var tags = [];
        try { tags = JSON.parse(ad.target_tags || '[]'); } catch (_e) {}
        var score = Number(ad.ctr || 0) + Number(ad.revenue || 0) / 1000;
        tags.forEach(function(t) { if (interests.includes(String(t).toLowerCase())) score += 3; });

        // Kiem tra frequency_cap: so lan user da thay ad nay hom nay
        var dailyCap = ad.frequency_cap || 3;
        var seenToday = 0;
        try {
          seenToday = dbRef.prepare(
            "SELECT COUNT(*) as c FROM impression_log WHERE user_id=? AND article_id=? AND created_at >= date('now')"
          ).get(userId, ad.id).c;
        } catch(_e) {}
        if (seenToday >= dailyCap) score = -999; // Loai khoi de xuat

        // Kiem tra consecutive_cap: 3 lan lien tiep khong click -> tam dung 48h
        var consecutiveDismiss = 0;
        try {
          consecutiveDismiss = dbRef.prepare(
            "SELECT COUNT(*) as c FROM impression_log WHERE user_id=? AND article_id=? AND clicked=0 AND dismissed=1 AND created_at > datetime('now', '-48 hours')"
          ).get(userId, ad.id).c;
        } catch(_e) {}
        if (consecutiveDismiss >= 2) score = -999;

        return { ad: ad, score: score };
      }).filter(function(x) { return x.score > -999; })
        .sort(function(a, b) { return b.score - a.score; })
        .slice(0, lim)
        .map(function(x) {
          return {
            id: x.ad.id, name: x.ad.name, platform: x.ad.platform,
            ctr: x.ad.ctr || 0, budget: x.ad.budget || 0,
            spent: x.ad.spent || 0, revenue: x.ad.revenue || 0
          };
        });
    },
  };
}

function hashToken(token) {
  return crypto.createHash('sha256').update(String(token || '')).digest('hex');
}

function parseCookies(cookieHeader) {
  var out = {};
  String(cookieHeader || '').split(';').forEach(function(chunk) {
    var i = chunk.indexOf('=');
    if (i <= 0) return;
    var k = chunk.slice(0, i).trim();
    var v = chunk.slice(i + 1).trim();
    try { out[k] = decodeURIComponent(v); } catch (_e) { out[k] = v; }
  });
  return out;
}

function extractAuthToken(req) {
  var bearer = (req.headers.authorization || '').replace('Bearer ', '').trim();
  if (bearer) return bearer;
  var cookies = parseCookies(req.headers.cookie || '');
  return (cookies[AUTH_COOKIE_NAME] || '').trim();
}

function setAuthCookie(res, token) {
  res.cookie(AUTH_COOKIE_NAME, token, {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 7 * 24 * 60 * 60 * 1000,
    path: '/',
  });
}

function clearAuthCookie(res) {
  res.clearCookie(AUTH_COOKIE_NAME, {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    path: '/',
  });
}

function recordSession(userId, token, req) {
  try {
    var tokenHash = hashToken(token);
    var ua = safeText((req.headers['user-agent'] || ''), 300);
    var ip = req.ip || null;
    var expiresAt = new Date(Date.now() + 7 * 24 * 3600 * 1000).toISOString();
    stmt.addSession.run(userId, tokenHash, ip, ua, new Date().toISOString(), expiresAt);
  } catch (_e) {}
}

function recordUserActivity(userId, type, payload) {
  try {
    stmt.addUserActivity.run(userId, safeText(type, 50), JSON.stringify(payload || {}), new Date().toISOString());
  } catch (_e) {}
}

function formatArticle(row, full) {
  if (!row) return null;
  var art = {
    id:            row.id,
    slug:          row.slug,
    category:      row.category,
    categoryLabel: row.category_label,
    title:         row.title,
    excerpt:       row.excerpt,
    author:        row.author,
    authorAvatar:  row.author_avatar,
    date:          row.date,
    readTime:      row.read_time,
    views:         row.total_views || row.views || 0,
    shares:        row.shares || 0,
    bounceRate:    row.bounce_rate || 0,
    thumbnail:     row.thumbnail,
    tags:          JSON.parse(row.tags || '[]'),
    isFeatured:    row.is_featured === 1,
    isHot:         row.is_hot === 1,
    status:        row.status,
    commentCount:  stmt.countComments.get(row.id).c,
  };
  if (full) {
    art.content = row.content;
  } else {
    art.summary = stripHtml(row.content).slice(0, 120) + '...';
  }
  return art;
}

// Full fields cho admin (bao gom draft, deleted_at)
function formatArticleAdmin(row) {
  if (!row) return null;
  var art = formatArticle(row, true);
  art.deletedAt = row.deleted_at;
  return art;
}

// paginate dung LIMIT/OFFSET - chi can truyen total rieng
function paginateResult(items, total, page, limit) {
  return {
    items: items,
    total: total,
    page:  page,
    pages: Math.ceil(total / limit) || 1,
    limit: limit,
  };
}

function safeUser(row) {
  if (!row) return null;
  return {
    id:         row.id,
    name:       row.name,
    email:      row.email,
    avatar:     row.avatar,
    role:       row.role || 'user',
    status:     row.status || 'active',
    phone:      row.phone || null,
    createdAt:  row.created_at,
    updatedAt:  row.updated_at,
  };
}

function safeUserAdmin(row) {
  if (!row) return null;
  return Object.assign(safeUser(row), {
    lastIp:     row.last_ip || null,
    lastDevice: row.last_device || null,
  });
}

// Vietnamese slug: map dau -> khong dau
function vn2slug(str) {
  var map = {
    'à':'a','á':'a','ả':'a','ã':'a','ạ':'a',
    'ă':'a','ắ':'a','ặ':'a','ằ':'a','ẳ':'a','ẵ':'a',
    'â':'a','ấ':'a','ầ':'a','ẩ':'a','ẫ':'a','ậ':'a',
    'đ':'d',
    'è':'e','é':'e','ẻ':'e','ẽ':'e','ẹ':'e',
    'ê':'e','ế':'e','ề':'e','ể':'e','ễ':'e','ệ':'e',
    'ì':'i','í':'i','ỉ':'i','ĩ':'i','ị':'i',
    'ò':'o','ó':'o','ỏ':'o','õ':'o','ọ':'o',
    'ô':'o','ố':'o','ồ':'o','ổ':'o','ỗ':'o','ộ':'o',
    'ơ':'o','ớ':'o','ờ':'o','ở':'o','ỡ':'o','ợ':'o',
    'ù':'u','ú':'u','ủ':'u','ũ':'u','ụ':'u',
    'ư':'u','ứ':'u','ừ':'u','ử':'u','ữ':'u','ự':'u',
    'ỳ':'y','ý':'y','ỷ':'y','ỹ':'y','ỵ':'y',
  };
  return str
    .toLowerCase()
    .split('').map(function(c) { return map[c] || c; }).join('')
    .replace(/[^a-z0-9\s-]/g, '')
    .replace(/\s+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '')
    .slice(0, 80);
}

function generateSlug(title) {
  var base = vn2slug(title) || 'bai-viet';
  return base + '-' + Date.now();
}

// ============================================================
// AUTH MIDDLEWARE
// ============================================================

function requireAuth(req, res, next) {
  var token = extractAuthToken(req);
  if (!token) return res_err(res, 'Cần đăng nhập', 401);
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    return res_err(res, 'Token không hợp lệ hoặc đã hết hạn', 401);
  }
}

function requireAdmin(req, res, next) {
  requireAuth(req, res, function() {
    var user = stmt.userById.get(req.user.id);
    if (!user || user.role !== 'admin') return res_err(res, 'Không có quyền truy cập', 403);
    next();
  });
}

// Optional auth: nếu có token thì gán req.user, không có thì bỏ qua
function optionalAuth(req, _res, next) {
  var token = extractAuthToken(req);
  if (token) {
    try { req.user = jwt.verify(token, JWT_SECRET); } catch(e) { /* bo qua */ }
  }
  next();
}

// Rate limiter (in-memory, production: dung Redis)
var rateLimitMap = {};
function rateLimit(maxPerMin) {
  return function(req, res, next) {
    var key = (req.ip || 'unknown') + ':' + req.path;
    var now = Date.now();
    if (!rateLimitMap[key]) rateLimitMap[key] = [];
    rateLimitMap[key] = rateLimitMap[key].filter(function(t) { return now - t < 60000; });
    if (rateLimitMap[key].length >= maxPerMin) {
      return res_err(res, 'Quá nhiều yêu cầu. Vui lòng thử lại sau.', 429);
    }
    rateLimitMap[key].push(now);
    next();
  };
}
setInterval(function() { rateLimitMap = {}; }, 300000);

// Cache TTL 10 phut cho profile/ads de giam tai DB khi request lon
var runtimeCache = buildRuntimeCache(db);
setInterval(function() {
  try { runtimeCache.cleanup(); } catch (_e) {}
}, 60 * 1000);

// Housekeeping: xoa log cu de tranh phinh DB khi chay lau
setInterval(function() {
  try {
    db.prepare("DELETE FROM user_analytics_events WHERE created_at < datetime('now', ?)").run('-' + LOG_RETENTION_DAYS + ' days');
    db.prepare("DELETE FROM analytics_sync_requests WHERE created_at < datetime('now', ?)").run('-' + LOG_RETENTION_DAYS + ' days');
    db.prepare("DELETE FROM request_audit_log WHERE created_at < datetime('now', ?)").run('-' + LOG_RETENTION_DAYS + ' days');
    db.prepare("DELETE FROM user_activity_log WHERE created_at < datetime('now', ?)").run('-' + LOG_RETENTION_DAYS + ' days');
    db.prepare("DELETE FROM ad_events WHERE created_at < datetime('now', ?)").run('-' + LOG_RETENTION_DAYS + ' days');
  } catch (_e) {}
}, 6 * 60 * 60 * 1000); // 6h

// Interest decay: giảm nhẹ điểm sở thích cũ để ưu tiên hành vi gần đây
setInterval(function() {
  try {
    db.prepare(`
      UPDATE user_interests
      SET score = CAST(ROUND(score * ?, 0) AS INTEGER),
          updated_at = datetime('now')
      WHERE score > 1
    `).run(INTEREST_DECAY_RATE);
    db.prepare('DELETE FROM user_interests WHERE score <= 0').run();
    runtimeCache.delByPrefix('rec:content:user:');
    runtimeCache.delByPrefix('rec:ads:user:');
    runtimeCache.delByPrefix('rec:shop:user:');
  } catch (_e) {}
}, INTEREST_DECAY_INTERVAL_MS);

// Request audit log: theo doi request/response toan he thong
installRequestAuditMiddleware(app, db);
var adEngine = createAdEngine(db, runtimeCache);

var analyticsEventQueue = [];
var analyticsQueueBusy = false;
function enqueueAnalyticsEvents(job) {
  analyticsEventQueue.push(job);
  processAnalyticsQueue();
}
function processAnalyticsQueue() {
  if (analyticsQueueBusy || !analyticsEventQueue.length) return;
  analyticsQueueBusy = true;
  setImmediate(function() {
    var job = analyticsEventQueue.shift();
    try {
      var inserted = 0;
      db.transaction(function() {
        job.activities.forEach(function(ev) {
          stmt.insertAnalyticsEvent.run(
            job.userId,
            job.username,
            ev.type,
            ev.target,
            JSON.stringify(ev.metadata || {}),
            job.source,
            ev.timestamp
          );
          // Recency weighting: hành động mới tác động mạnh hơn
          var w = interestWeightForAction(ev.type);
          var targetToken = safeText(ev.target || '', 50).toLowerCase();
          if (targetToken) stmt.upsertInterestWeighted.run(job.userId, targetToken, Math.max(1, Math.floor(w / 2)));
          if (ev.metadata && ev.metadata.tag) {
            var tag = safeText(ev.metadata.tag, 50).toLowerCase();
            if (tag) stmt.upsertInterestWeighted.run(job.userId, tag, w);
          }
          inserted++;
        });
      })();
      var result = {
        accepted: true,
        usernameUpdated: job.usernameUpdated,
        interestsSynced: job.interestsCount,
        activitySynced: inserted,
      };
      stmt.updateAnalyticsSyncRequest.run(JSON.stringify(result), 'processed', null, new Date().toISOString(), job.requestId);
    } catch (e) {
      stmt.updateAnalyticsSyncRequest.run(JSON.stringify({ accepted: false }), 'failed', safeText(e.message || 'analytics queue error', 500), new Date().toISOString(), job.requestId);
    } finally {
      analyticsQueueBusy = false;
      if (analyticsEventQueue.length) processAnalyticsQueue();
    }
  });
}

// ============================================================
// ROUTES - HEALTH (admin only)
// ============================================================

app.get('/health', function(_req, res) {
  res.json({
    status:   'ok',
    articles: db.prepare('SELECT COUNT(*) as c FROM articles WHERE deleted_at IS NULL').get().c,
    users:    db.prepare('SELECT COUNT(*) as c FROM users').get().c,
    comments: db.prepare('SELECT COUNT(*) as c FROM comments WHERE deleted_at IS NULL').get().c,
    uptime:   Math.floor(process.uptime()) + 's',
    time:     new Date().toISOString(),
  });
});

// ============================================================
// ROUTES - UPLOAD
// ============================================================

app.post('/api/upload', requireAuth, upload.single('file'), function(req, res) {
  if (!req.file) return res_err(res, 'Không có file hoặc định dạng không hợp lệ');
  var url = (process.env.BASE_URL || 'http://localhost:' + PORT) + '/uploads/' + req.file.filename;
  res_ok(res, { url: url, filename: req.file.filename }, 201);
});

// ============================================================
// ROUTES - CATEGORIES
// ============================================================

app.get('/api/categories', function(_req, res) {
  var counts = db.prepare("SELECT category, COUNT(*) as c FROM articles WHERE status='published' AND deleted_at IS NULL GROUP BY category").all();
  var countMap = {};
  counts.forEach(function(r) { countMap[r.category] = r.c; });
  res_ok(res, CATEGORIES.map(function(cat) {
    return { id: cat.id, label: cat.label, count: countMap[cat.id] || 0 };
  }));
});

// ============================================================
// ROUTES - ARTICLES (PUBLIC)
// ============================================================

// GET /api/articles
app.get('/api/articles', function(req, res) {
  var page     = Math.max(1, parseInt(req.query.page)  || 1);
  var limit    = Math.min(50, Math.max(1, parseInt(req.query.limit) || 10));
  var category = req.query.category;
  var featured = req.query.featured;
  var hot      = req.query.hot;
  var sort     = req.query.sort;
  var offset   = (page - 1) * limit;

  var where = ["status='published'", "deleted_at IS NULL"];
  var args  = [];

  if (category && VALID_CATEGORY_IDS.has(category)) {
    where.push('category=?'); args.push(category);
  }
  if (featured === 'true') where.push('is_featured=1');
  if (hot === 'true')      where.push('is_hot=1');

  var orderBy = (sort === 'views') ? 'views DESC' : 'date DESC';
  var baseSQL = 'FROM articles WHERE ' + where.join(' AND ');

  var total = db.prepare('SELECT COUNT(*) as c ' + baseSQL).get(...args).c;
  var rows  = db.prepare('SELECT * ' + baseSQL + ' ORDER BY ' + orderBy + ' LIMIT ? OFFSET ?')
                .all(...args, limit, offset)
                .map(function(r) { return formatArticle(r, false); });

  res_ok(res, paginateResult(rows, total, page, limit));
});

// GET /api/articles/trending
app.get('/api/articles/trending', function(req, res) {
  var limit = Math.min(20, parseInt(req.query.limit) || 5);
  res_ok(res, stmt.trending.all(limit).map(function(r) { return formatArticle(r, false); }));
});

// GET /api/articles/search  -- phai truoc /:id
app.get('/api/articles/search', function(req, res) {
  var q        = (req.query.q || '').trim();
  var page     = Math.max(1, parseInt(req.query.page)  || 1);
  var limit    = Math.min(20, Math.max(1, parseInt(req.query.limit) || 10));
  var category = req.query.category;
  var sort     = req.query.sort;
  var offset   = (page - 1) * limit;

  if (!q) return res_ok(res, paginateResult([], 0, 1, limit));
  if (q.length > 200) return res_err(res, 'Từ khóa tìm kiếm quá dài');

  var like = '%' + q + '%';
  var rows = stmt.searchArticles.all(like, like, like, like);

  if (category && category !== 'all' && VALID_CATEGORY_IDS.has(category)) {
    rows = rows.filter(function(r) { return r.category === category; });
  }
  if (sort === 'views') {
    rows.sort(function(a, b) { return b.views - a.views; });
  }

  var total = rows.length;
  var items = rows.slice(offset, offset + limit).map(function(r) { return formatArticle(r, false); });
  res_ok(res, paginateResult(items, total, page, limit));
});

// POST /api/search  -- AI semantic search (fulltext fallback)
app.post('/api/search', rateLimit(20), function(req, res) {
  var q        = (req.body.q || '').trim();
  var page     = Math.max(1, parseInt(req.body.page)  || 1);
  var limit    = Math.min(20, Math.max(1, parseInt(req.body.limit) || 10));
  var category = req.body.category;
  var offset   = (page - 1) * limit;

  if (!q) return res_ok(res, paginateResult([], 0, 1, limit));
  if (q.length > 300) return res_err(res, 'Từ khóa tìm kiếm quá dài');

  // Fulltext search: tach query thanh tung tu, tim tat ca
  var terms = q.toLowerCase().split(/\s+/).filter(function(t) { return t.length > 1; }).slice(0, 5);
  var like  = '%' + q + '%';

  var rows = stmt.searchArticles.all(like, like, like, like);

  // Boost score: cong diem cho moi term match
  rows = rows.map(function(r) {
    var score = 0;
    var titleLow = (r.title || '').toLowerCase();
    var exLow    = (r.excerpt || '').toLowerCase();
    terms.forEach(function(t) {
      if (titleLow.includes(t))  score += 3;
      if (exLow.includes(t))     score += 1;
      if ((r.tags || '').toLowerCase().includes(t)) score += 2;
    });
    return { row: r, score: score };
  });
  rows.sort(function(a, b) { return b.score - a.score; });

  if (category && category !== 'all' && VALID_CATEGORY_IDS.has(category)) {
    rows = rows.filter(function(r) { return r.row.category === category; });
  }

  var total = rows.length;
  var items = rows.slice(offset, offset + limit).map(function(r) { return formatArticle(r.row, false); });
  res_ok(res, paginateResult(items, total, page, limit));
});

// GET /api/articles/:id  (slug hoac id)
app.get('/api/articles/:id', optionalAuth, function(req, res) {
  var id  = parseInt(req.params.id);
  var row = isNaN(id) ? stmt.articleBySlug.get(req.params.id) : stmt.articleById.get(id);
  if (!row) return res_err(res, 'Không tìm thấy bài viết', 404);

  // Dedup view: 1 IP chi tinh 1 view / gio
  var ip = req.ip || 'unknown';
  var ua = (req.headers['user-agent'] || '').slice(0, 300);
  var alreadyViewed = stmt.hasViewedRecently.get(row.id, ip);
  if (!alreadyViewed) {
    stmt.incrViews.run(row.id);
    stmt.logView.run(row.id, (req.user && req.user.id) || null, ip, ua);
    // Cập nhật interest nếu đăng nhập
    if (req.user) {
      stmt.upsertInterestWeighted.run(req.user.id, row.category, interestWeightForAction('read'));
      var tags = [];
      try { tags = JSON.parse(row.tags || '[]'); } catch (_e) {}
      safeJsonArrayText(tags, 8).forEach(function(tag) {
        stmt.upsertInterestWeighted.run(req.user.id, tag, 4);
      });
    }
  }

  res_ok(res, formatArticle(row, true));
});

// GET /api/articles/:id/related
app.get('/api/articles/:id/related', function(req, res) {
  var id  = parseInt(req.params.id);
  if (isNaN(id)) return res_err(res, 'ID không hợp lệ', 400);
  var row = stmt.articleById.get(id);
  if (!row) return res_err(res, 'Không tìm thấy bài viết', 404);
  res_ok(res, stmt.related.all(row.category, row.id).map(function(r) { return formatArticle(r, false); }));
});

// POST /api/articles/:id/ping — client gửi duration_sec khi rời bài
app.post('/api/articles/:id/ping', rateLimit(30), function(req, res) {
  var id  = parseInt(req.params.id);
  if (isNaN(id)) return res_ok(res, { ok: true }); // silent ignore
  var dur = parseInt(req.body.duration_sec);
  if (!dur || dur < 1 || dur > 86400) return res_ok(res, { ok: true });
  var ip  = req.ip || 'unknown';
  try { stmt.updateViewDuration.run(dur, id, ip); } catch(e) {}
  res_ok(res, { ok: true });
});

// GET /api/articles/:id/comments
app.get('/api/articles/:id/comments', function(req, res) {
  var id     = parseInt(req.params.id);
  if (isNaN(id)) return res_err(res, 'ID không hợp lệ', 400);
  var page   = Math.max(1, parseInt(req.query.page)  || 1);
  var limit  = Math.min(50, Math.max(1, parseInt(req.query.limit) || 20));
  var offset = (page - 1) * limit;

  var row = stmt.articleById.get(id);
  if (!row) return res_err(res, 'Không tìm thấy bài viết', 404);

  var total = stmt.countComments.get(id).c;
  var items = stmt.getComments.all(id, limit, offset);
  res_ok(res, paginateResult(items, total, page, limit));
});

// POST /api/articles/:id/comments
app.post('/api/articles/:id/comments', requireAuth, rateLimit(10), function(req, res) {
  var id      = parseInt(req.params.id);
  if (isNaN(id)) return res_err(res, 'ID không hợp lệ', 400);
  var content = (req.body.content || '').trim();
  if (!content)              return res_err(res, 'Nội dung bình luận không được để trống');
  if (content.length > 2000) return res_err(res, 'Bình luận quá dài (tối đa 2000 ký tự)');

  var row = stmt.articleById.get(id);
  if (!row) return res_err(res, 'Không tìm thấy bài viết', 404);

  var info = stmt.addComment.run(id, req.user.id, content);
  var user = stmt.userById.get(req.user.id);
  res_ok(res, {
    id:          info.lastInsertRowid,
    content:     content,
    created_at:  new Date().toISOString(),
    user_id:     user.id,
    user_name:   user.name,
    user_avatar: user.avatar,
  }, 201);
});

// DELETE /api/comments/:id  (owner hoac admin)
app.delete('/api/comments/:id', requireAuth, function(req, res) {
  var id      = parseInt(req.params.id);
  var comment = stmt.commentById.get(id);
  if (!comment) return res_err(res, 'Bình luận không tồn tại', 404);

  var user = stmt.userById.get(req.user.id);
  var isOwner = comment.user_id === req.user.id;
  var isAdmin = user && user.role === 'admin';

  if (!isOwner && !isAdmin) return res_err(res, 'Không có quyền xóa bình luận này', 403);

  stmt.softDelComment.run(id);
  res_ok(res, { message: 'Đã xóa bình luận', id: id });
});


// POST /api/articles/:id/share  (tang share count)
app.post('/api/articles/:id/share', function(req, res) {
  var id = parseInt(req.params.id);
  var row = stmt.articleById.get(id);
  if (!row) return res_err(res, 'Không tìm thấy bài viết', 404);
  stmt.incrShares.run(id);
  res_ok(res, { id: id, shares: row.shares + 1 });
});

// ============================================================
// ROUTES - AUTH
// ============================================================

app.post('/api/auth/register', rateLimit(5), function(req, res) {
  var name     = (req.body.name     || '').trim().slice(0, 100);
  var email    = (req.body.email    || '').trim().toLowerCase().slice(0, 200);
  var password = (req.body.password || '');

  if (!name || !email || !password) return res_err(res, 'Vui lòng điền đầy đủ thông tin');
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res_err(res, 'Email không hợp lệ');
  if (password.length < 8)  return res_err(res, 'Mật khẩu phải có ít nhất 8 ký tự');
  if (password.length > 128) return res_err(res, 'Mật khẩu quá dài');
  if (stmt.userByEmail.get(email)) return res_err(res, 'Email đã được sử dụng');

  var hashed = bcrypt.hashSync(password, 10);
  var avatar  = 'https://i.pravatar.cc/80?u=' + encodeURIComponent(email);
  var info    = stmt.insertUser.run(name, email, hashed, avatar);
  var user    = stmt.userById.get(info.lastInsertRowid);
  var token   = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: JWT_EXPIRES });
  setAuthCookie(res, token);
  recordSession(user.id, token, req);
  recordUserActivity(user.id, 'register', { email: user.email });
  res_ok(res, { token: token, user: safeUser(user) }, 201);
});

app.post('/api/auth/login', rateLimit(10), function(req, res) {
  var email    = (req.body.email    || '').trim().toLowerCase();
  var password = (req.body.password || '');
  if (!email || !password) return res_err(res, 'Vui lòng nhập email và mật khẩu');

  var user = stmt.userByEmail.get(email);
  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res_err(res, 'Email hoặc mật khẩu không đúng', 401);
  }
  if (user.status === 'banned') return res_err(res, 'Tài khoản đã bị khoá', 403);

  // Cap nhat last_ip, last_device
  var device = (req.headers['user-agent'] || '').slice(0, 200);
  stmt.updateLastSeen.run(req.ip || null, device, user.id);

  // Role co trong JWT de frontend biet quyen
  var token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: JWT_EXPIRES });
  setAuthCookie(res, token);
  recordSession(user.id, token, req);
  recordUserActivity(user.id, 'login', { ip: req.ip || null });
  res_ok(res, { token: token, user: safeUser(user) });
});

app.post('/api/auth/forgot-password', rateLimit(3), function(req, res) {
  var email = (req.body.email || '').trim().toLowerCase();
  if (!email) return res_err(res, 'Vui long nhap email');
  // TODO: gui email that qua SendGrid / Nodemailer
  // Tra ve success du user co ton tai hay khong (tranh enum user)
  res_ok(res, { message: 'Nếu email tồn tại, link đặt lại mật khẩu sẽ được gửi trong vài phút.' });
});

// ============================================================
// POST /api/auth/google  — Google Identity Services (popup flow)
// Frontend gui credential (ID token tu GIS), backend verify voi Google
// ============================================================
app.post('/api/auth/google', rateLimit(10), function(req, res) {
  var credential = (req.body.credential || '').trim();
  if (!credential) return res_err(res, 'Thiếu Google credential');

  var verifyUrl = 'https://oauth2.googleapis.com/tokeninfo?id_token=' + encodeURIComponent(credential);

  https.get(verifyUrl, function(r) {
    var raw = '';
    r.on('data', function(chunk) { raw += chunk; });
    r.on('end', function() {
      var payload;
      try { payload = JSON.parse(raw); } catch(e) { return res_err(res, 'Phản hồi Google không hợp lệ'); }

      if (payload.error || !payload.email) {
        return res_err(res, 'Token Google không hợp lệ: ' + (payload.error_description || payload.error || 'unknown'));
      }
      // Kiem tra audience neu da set GOOGLE_CLIENT_ID
      if (GOOGLE_CLIENT_ID && payload.aud !== GOOGLE_CLIENT_ID) {
        return res_err(res, 'Google client_id không khớp');
      }
      // email_verified phai la true
      if (payload.email_verified !== 'true' && payload.email_verified !== true) {
        return res_err(res, 'Email Google chưa được xác minh');
      }

      var email  = payload.email.trim().toLowerCase().slice(0, 200);
      var name   = (payload.name  || email.split('@')[0]).trim().slice(0, 100);
      var avatar = payload.picture || null;

      // Tim user cu hoac tao moi
      var user = stmt.userByEmail.get(email);
      if (!user) {
        // Password ngau nhien — user nay chi login duoc bang Google
        var dummyPw = bcrypt.hashSync(Math.random().toString(36) + Date.now().toString(), 8);
        var genAvatar = avatar || ('https://i.pravatar.cc/80?u=' + encodeURIComponent(email));
        var info = db.prepare(
          "INSERT INTO users (name, email, password, avatar, role, status) VALUES (?, ?, ?, ?, 'user', 'active')"
        ).run(name, email, dummyPw, genAvatar);
        user = stmt.userById.get(info.lastInsertRowid);
      } else {
        // Cap nhat avatar Google neu user chua co avatar
        if (avatar && !user.avatar) {
          db.prepare("UPDATE users SET avatar=?, updated_at=datetime('now') WHERE id=?").run(avatar, user.id);
          user = stmt.userById.get(user.id);
        }
      }

      if (user.status === 'banned') return res_err(res, 'Tài khoản đã bị khoá', 403);

      // Cap nhat last_ip, last_device
      var device = (req.headers['user-agent'] || '').slice(0, 200);
      stmt.updateLastSeen.run(req.ip || null, device, user.id);

      var token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: JWT_EXPIRES });
      setAuthCookie(res, token);
      recordSession(user.id, token, req);
      recordUserActivity(user.id, 'login_google', { ip: req.ip || null });
      res_ok(res, { token: token, user: safeUser(user) });
    });
  }).on('error', function(e) {
    res_err(res, 'Không kết nối được Google: ' + e.message);
  });
});

app.post('/api/auth/refresh', function(req, res) {
  var token = (req.body.token || '').trim();
  if (!token) return res_err(res, 'Thieu token', 401);
  try {
    var decoded  = jwt.verify(token, JWT_SECRET);
    var user     = stmt.userById.get(decoded.id);
    if (!user) return res_err(res, 'Tài khoản không tồn tại', 404);
    if (user.status === 'banned') return res_err(res, 'Tài khoản đã bị khoá', 403);
    var newToken = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: JWT_EXPIRES });
    setAuthCookie(res, newToken);
    recordSession(user.id, newToken, req);
    res_ok(res, { token: newToken, user: safeUser(user) });
  } catch (e) {
    return res_err(res, 'Token không hợp lệ', 401);
  }
});

app.post('/api/auth/logout', requireAuth, function(req, res) {
  var token = extractAuthToken(req);
  if (token) {
    try { stmt.revokeSessionByHash.run(hashToken(token)); } catch (_e) {}
  }
  clearAuthCookie(res);
  recordUserActivity(req.user.id, 'logout', { at: new Date().toISOString() });
  res_ok(res, { message: 'Đăng xuất thành công' });
});

app.get('/api/auth/me', requireAuth, function(req, res) {
  var user = stmt.userById.get(req.user.id);
  if (!user) return res_err(res, 'Tài khoản không tồn tại', 404);
  // Kem theo interests
  var interests = stmt.getUserInterests.all(user.id).map(function(r) { return r.category; });
  var data = safeUser(user);
  data.interests = interests;
  res_ok(res, data);
});

app.put('/api/auth/me', requireAuth, function(req, res) {
  var user = stmt.userById.get(req.user.id);
  if (!user) return res_err(res, 'Tài khoản không tồn tại', 404);
  var name   = ((req.body.name   || user.name  ) + '').trim().slice(0, 100);
  var avatar = ((req.body.avatar || user.avatar || '') + '').trim().slice(0, 500);
  stmt.updateProfile.run(name, avatar, req.user.id);
  res_ok(res, safeUser(stmt.userById.get(req.user.id)));
});

app.put('/api/auth/me/password', requireAuth, function(req, res) {
  var currentPassword = req.body.currentPassword || '';
  var newPassword     = req.body.newPassword     || '';
  if (!currentPassword || !newPassword) return res_err(res, 'Vui lòng nhập đầy đủ');
  var user = stmt.userById.get(req.user.id);
  if (!user) return res_err(res, 'Tài khoản không tồn tại', 404);
  if (!bcrypt.compareSync(currentPassword, user.password)) return res_err(res, 'Mật khẩu hiện tại không đúng');
  if (newPassword.length < 8)   return res_err(res, 'Mật khẩu mới phải có ít nhất 8 ký tự');
  if (newPassword.length > 128) return res_err(res, 'Mật khẩu quá dài');
  stmt.updatePw.run(bcrypt.hashSync(newPassword, 10), req.user.id);
  res_ok(res, { message: 'Đổi mật khẩu thành công' });
});

// ============================================================
// ROUTES - BOOKMARKS
// ============================================================

app.get('/api/user/bookmarks', requireAuth, function(req, res) {
  var ids = stmt.getBookmarks.all(req.user.id).map(function(r) { return r.article_id; });
  if (!ids.length) return res_ok(res, []);
  var ph   = ids.map(function() { return '?'; }).join(',');
  var rows = db.prepare('SELECT * FROM articles WHERE id IN (' + ph + ') AND deleted_at IS NULL')
               .all(...ids);
  res_ok(res, rows.map(function(r) { return formatArticle(r, false); }));
});

app.post('/api/user/bookmarks/:id', requireAuth, function(req, res) {
  var aid = parseInt(req.params.id);
  if (!stmt.articleById.get(aid)) return res_err(res, 'Bài viết không tồn tại', 404);
  if (stmt.hasBookmark.get(req.user.id, aid)) {
    stmt.delBookmark.run(req.user.id, aid);
    res_ok(res, { id: aid, saved: false });
  } else {
    stmt.addBookmark.run(req.user.id, aid);
    res_ok(res, { id: aid, saved: true });
  }
});

// ============================================================
// ROUTES - NOTIFICATIONS
// ============================================================

app.get('/api/user/notifications', requireAuth, function(req, res) {
  var row = stmt.getNotif.get(req.user.id);
  if (row) {
    res_ok(res, { email: row.email_on===1, breaking: row.breaking===1, weekly: row.weekly===1, marketing: row.marketing===1 });
  } else {
    res_ok(res, { email: true, breaking: true, weekly: false, marketing: false });
  }
});

app.put('/api/user/notifications', requireAuth, function(req, res) {
  var cur = stmt.getNotif.get(req.user.id) || { email_on:1, breaking:1, weekly:0, marketing:0 };
  function b(val, fallback) { return val === undefined ? fallback : (val ? 1 : 0); }
  var eo = b(req.body.email,     cur.email_on);
  var br = b(req.body.breaking,  cur.breaking);
  var wk = b(req.body.weekly,    cur.weekly);
  var mk = b(req.body.marketing, cur.marketing);
  stmt.upsertNotif.run(req.user.id, eo, br, wk, mk);
  res_ok(res, { email: eo===1, breaking: br===1, weekly: wk===1, marketing: mk===1 });
});

// ============================================================
// GET /api/user/stats  — thong ke profile overview
// ============================================================
app.get('/api/user/stats', requireAuth, function(req, res) {
  var uid = req.user.id;
  var bookmarks = db.prepare('SELECT COUNT(*) as c FROM bookmarks WHERE user_id=?').get(uid).c;
  var comments  = db.prepare('SELECT COUNT(*) as c FROM comments  WHERE user_id=? AND deleted_at IS NULL').get(uid).c;
  var views     = db.prepare('SELECT COUNT(*) as c FROM view_log  WHERE user_id=?').get(uid).c;
  // Bai doc gan day (5 bai cuoi trong view_log)
  var recent    = db.prepare(`
    SELECT DISTINCT vl.article_id, a.title, a.category_label, a.thumbnail, a.date
    FROM view_log vl
    JOIN articles a ON a.id = vl.article_id AND a.deleted_at IS NULL
    WHERE vl.user_id = ?
    ORDER BY vl.created_at DESC
    LIMIT 5
  `).all(uid);
  res_ok(res, {
    views:     views,
    bookmarks: bookmarks,
    comments:  comments,
    recent:    recent.map(function(r) {
      return { id: r.article_id, title: r.title, cat: r.category_label, thumbnail: r.thumbnail, date: r.date };
    }),
  });
});

// ============================================================
// ROUTES - USER ANALYTICS (UI -> backend)
// ============================================================

// POST /api/user/analytics/sync
// UI gui thong tin phan tich hanh vi nguoi dung, backend validate + luu event
app.post('/api/user/analytics/sync', requireAuth, enforcePayloadLimit(1024 * 1024), rateLimit(40), function(req, res) {
  var user = stmt.userById.get(req.user.id);
  if (!user) return res_err(res, 'Tài khoản không tồn tại', 404);
  if (user.status === 'banned') return res_err(res, 'Tài khoản đã bị khoá', 403);

  var requestId = buildRequestId('sync');
  var username = safeText(req.body.username || '', 100) || defaultDisplayName(user);
  var interests = normalizeInterests(req.body.interests);
  var activities = normalizeActivities(req.body.activities || req.body.activityHistory);
  var source = safeText(req.body.source || 'ui', 20) || 'ui';
  var nowIso = new Date().toISOString();
  var eventsToday = stmt.countAnalyticsEventsToday.get(user.id).c || 0;

  if (!interests.length && !activities.length && !username) {
    return res_err(res, 'Payload rỗng. Cần ít nhất interests hoặc activityHistory.', 400);
  }
  if (eventsToday + activities.length > MAX_ANALYTICS_EVENTS_PER_USER_PER_DAY) {
    return res_err(res, 'Vượt giới hạn đồng bộ hoạt động trong ngày. Vui lòng thử lại sau.', 429);
  }

  var inputForAudit = {
    username: username,
    interestsCount: interests.length,
    activitiesCount: activities.length,
    source: source,
  };
  var resultForAudit = {
    accepted: true,
    usernameUpdated: false,
    interestsSynced: 0,
    activitySynced: 0,
  };

  // Cap nhat ten hien thi neu UI gui ten hop le khac ten hien tai
  if (username && username !== user.name) {
    resultForAudit.usernameUpdated = true;
  }

  // Pipeline nhanh: update profile + interests trong luong chinh.
  // Activity log duoc dua vao queue de tranh block SQLite.
  try {
    db.transaction(function() {
      if (username && username !== user.name) {
        db.prepare("UPDATE users SET name=?, updated_at=datetime('now') WHERE id=?").run(username, user.id);
      }

      interests.forEach(function(interest) {
        stmt.upsertInterestWeighted.run(user.id, interest, 2);
      });
      resultForAudit.interestsSynced = interests.length;
      resultForAudit.activitySynced = 0;

      stmt.insertAnalyticsSyncRequest.run(
        requestId,
        user.id,
        source,
        JSON.stringify(inputForAudit),
        JSON.stringify(resultForAudit),
        activities.length ? 'queued' : 'processed',
        null,
        nowIso,
        new Date().toISOString()
      );
    })();
  } catch (e) {
    // Neu loi, van luu log request de truy vet
    try {
      stmt.insertAnalyticsSyncRequest.run(
        requestId,
        user.id,
        source,
        JSON.stringify(inputForAudit),
        JSON.stringify({ accepted: false }),
        'failed',
        safeText(e.message || 'Unknown analytics sync error', 500),
        nowIso,
        new Date().toISOString()
      );
    } catch (_e) {}
    return res_err(res, 'Xử lý analytics thất bại: ' + e.message, 500);
  }

  if (activities.length) {
    enqueueAnalyticsEvents({
      requestId: requestId,
      userId: user.id,
      username: username,
      usernameUpdated: resultForAudit.usernameUpdated,
      interestsCount: resultForAudit.interestsSynced,
      activities: activities,
      source: source,
    });
  }

  res_ok(res, {
    requestId: requestId,
    status: activities.length ? 'queued' : 'processed',
    accepted: true,
    userId: user.id,
    username: username,
    interestsSynced: resultForAudit.interestsSynced,
    activityQueued: activities.length,
    processedAt: new Date().toISOString(),
  });
});

// GET /api/user/analytics/summary
// Tra ve dung bo du lieu profile phan tich theo yeu cau UI
app.get('/api/user/analytics/summary', requireAuth, function(req, res) {
  var user = stmt.userById.get(req.user.id);
  if (!user) return res_err(res, 'Tài khoản không tồn tại', 404);

  var username = defaultDisplayName(user);
  var interests = stmt.getUserInterests.all(user.id).map(function(r) { return r.category; });
  var recentActivities = stmt.recentAnalyticsEvents.all(user.id, 100).map(function(r) {
    var metadata = {};
    try { metadata = JSON.parse(r.metadata_json || '{}'); } catch (e) {}
    return {
      id: r.id,
      type: r.event_type,
      target: r.event_target || null,
      metadata: metadata,
      source: r.source || 'ui',
      timestamp: r.created_at,
    };
  });

  res_ok(res, {
    username: username, // tu tao hoac lay ten Google da sync vao users.name
    userId: user.id,
    joinedAt: user.created_at || null,
    lastLoginAt: user.updated_at || user.created_at || null,
    interests: interests,
    activityHistory: recentActivities,
    syncHistory: stmt.analyticsSyncRecentByUser.all(user.id, 20),
  });
});

// GET /api/user/analytics/requests/:requestId
// UI co the lay ket qua xu ly cho mot request cu the
app.get('/api/user/analytics/requests/:requestId', requireAuth, function(req, res) {
  var requestId = safeText(req.params.requestId, 80);
  if (!requestId) return res_err(res, 'requestId không hợp lệ', 400);

  var item = stmt.analyticsSyncByRequestId.get(requestId);
  if (!item || item.user_id !== req.user.id) return res_err(res, 'Không tìm thấy request', 404);

  var inputJson = {};
  var resultJson = {};
  try { inputJson = JSON.parse(item.input_json || '{}'); } catch (e) {}
  try { resultJson = JSON.parse(item.result_json || '{}'); } catch (e) {}

  res_ok(res, {
    requestId: item.request_id,
    status: item.status,
    source: item.source,
    errorMessage: item.error_message || null,
    input: inputJson,
    result: resultJson,
    createdAt: item.created_at,
    processedAt: item.processed_at,
  });
});

// GET /api/user/recommendations
// Goi y noi dung + quang cao dua tren interests
// position: home_feed | end_of_article | sidebar | search_results
app.get('/api/user/recommendations', requireAuth, function(req, res) {
  var user = stmt.userById.get(req.user.id);
  if (!user) return res_err(res, 'Tài khoản không tồn tại', 404);

  var position = ['home_feed','end_of_article','sidebar','search_results'].includes(req.query.position)
    ? req.query.position : 'home_feed';
  var limit = Math.min(20, Math.max(1, parseInt(req.query.limit) || 6));
  // end_of_article: uu tien tag bai vua doc
  var articleTag = req.query.article_tag || null;

  var contentCacheKey = 'rec:content:user:' + user.id + ':' + position + ':' + (articleTag || '');
  var content = runtimeCache.get(contentCacheKey);
  if (!content) {
    // Lay interests tu ca 2 bang: signal (MEDIUM/HIGH) + user_interests
    var signalInterests = db.prepare(
      "SELECT tag as category, decay_score as score FROM user_interests_signal WHERE user_id=? AND level IN ('MEDIUM','HIGH') AND last_signal_at > datetime('now','-14 days') ORDER BY decay_score DESC LIMIT 5"
    ).all(String(user.id));
    var baseInterests = stmt.getUserInterests.all(user.id).map(function(r) { return r.category; });

    var tags = signalInterests.map(function(r) { return r.category; });
    // Them base interests neu chua du
    baseInterests.forEach(function(c) { if (!tags.includes(c)) tags.push(c); });

    // end_of_article: dat article_tag len dau
    if (articleTag && position === 'end_of_article') {
      tags = tags.filter(function(t) { return t !== articleTag; });
      tags.unshift(articleTag);
    }

    var articles;
    if (!tags.length) {
      // User moi: fallback noi dung hot hom nay
      articles = db.prepare(
        "SELECT id, title, category, category_label, thumbnail, total_views as views, date FROM articles WHERE status='published' AND deleted_at IS NULL ORDER BY date DESC LIMIT ?"
      ).all(limit);
    } else {
      var ph = tags.slice(0,5).map(function() { return '?'; }).join(',');
      articles = db.prepare(
        "SELECT id, title, category, category_label, thumbnail, total_views as views, date FROM articles WHERE status='published' AND deleted_at IS NULL AND category IN (" + ph + ") ORDER BY total_views DESC, date DESC LIMIT ?"
      ).all(...tags.slice(0,5), limit);
    }

    // Sap xep theo diem khop: decay_score × log(views+1) × do_moi
    var tagScoreMap = {};
    signalInterests.forEach(function(r) { tagScoreMap[r.category] = r.decay_score; });
    var now = Date.now();
    articles = articles.map(function(a) {
      var tagScore = tagScoreMap[a.category] || 0.1;
      var hot = Math.log1p(a.views || 0);
      var ageDays = (now - new Date(a.date).getTime()) / 86400000;
      var freshness = Math.exp(-0.05 * ageDays); // decay theo ngay
      a._matchScore = tagScore * hot * freshness;
      return a;
    }).sort(function(a, b) { return b._matchScore - a._matchScore; });

    // Loai trung tag lien tiep (spec ch.6 buoc 1)
    var seen = new Set();
    var deduped = [];
    articles.forEach(function(a) {
      if (!seen.has(a.category)) { deduped.push(a); seen.add(a.category); }
    });
    // Them lai bai cung tag neu chua du
    articles.forEach(function(a) { if (deduped.length < limit && !deduped.includes(a)) deduped.push(a); });

    content = deduped.slice(0, limit).map(function(a) {
      return { id: a.id, title: a.title, category: a.category, category_label: a.category_label, thumbnail: a.thumbnail, views: a.views, date: a.date, match_score: parseFloat((a._matchScore || 0).toFixed(4)) };
    });

    // sidebar: re-fetch sau 50% scroll — cache ngan hon
    var cacheTtl = position === 'sidebar' ? 5 * 60 * 1000 : 10 * 60 * 1000;
    runtimeCache.set(contentCacheKey, content, cacheTtl);
  }

  var adsCacheKey = 'rec:ads:user:' + user.id;
  var ads = runtimeCache.get(adsCacheKey);
  if (!ads) {
    ads = adEngine.recommendAds(String(user.id), 3);
    runtimeCache.set(adsCacheKey, ads, 10 * 60 * 1000);
  }

  res_ok(res, {
    userId: user.id,
    position: position,
    content: content,
    ads: ads,
    cachedForSec: position === 'sidebar' ? 300 : 600,
  });
});

// GET /api/shop/recommendations
app.get('/api/shop/recommendations', requireAuth, function(req, res) {
  var user = stmt.userById.get(req.user.id);
  if (!user) return res_err(res, 'Tài khoản không tồn tại', 404);
  var cacheKey = 'rec:shop:user:' + user.id + ':limit:' + (req.query.limit || '8');
  var items = runtimeCache.get(cacheKey);
  if (!items) {
    items = buildShopRecommendations(user.id, req.query.limit || 8);
    runtimeCache.set(cacheKey, items, 10 * 60 * 1000);
  }
  res_ok(res, {
    userId: user.id,
    monthContext: (new Date().getMonth() + 1),
    items: items,
    formula: 'score = interest*0.5 + trending*0.3 + seasonal*0.2 + collaborativeBonus',
    cachedForSec: 600,
  });
});

// ============================================================
// ROUTES - NEWSLETTER
// ============================================================

app.post('/api/newsletter/subscribe', rateLimit(5), function(req, res) {
  var email     = (req.body.email     || '').trim().toLowerCase().slice(0, 200);
  var frequency = req.body.frequency  || 'daily';
  var topics    = req.body.topics     || [];

  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res_err(res, 'Email không hợp lệ');
  if (!['daily','weekly','breaking'].includes(frequency)) frequency = 'daily';

  var topicsJson = JSON.stringify(Array.isArray(topics) ? topics.slice(0,10) : []);
  if (stmt.nlByEmail.get(email)) {
    stmt.nlUpdate.run(frequency, topicsJson, email);
    return res_ok(res, { message: 'Đã cập nhật cài đặt bản tin.', email: email });
  }
  stmt.nlInsert.run(email, frequency, topicsJson);
  res_ok(res, { message: 'Đăng ký thành công! Vui lòng kiểm tra email để xác nhận.', email: email }, 201);
});

// ============================================================
// ROUTES - ADMIN
// ============================================================

// GET /api/admin/stats
app.get('/api/admin/stats', requireAdmin, function(_req, res) {
  var totalViews = db.prepare('SELECT SUM(total_views) as v FROM articles WHERE deleted_at IS NULL').get().v || 0;
  // Weekly views: tong views 7 ngay qua tu view_log
  var weeklyRows = db.prepare(`
    SELECT date(created_at) as day, COUNT(*) as cnt
    FROM view_log
    WHERE created_at >= datetime('now', '-7 days')
    GROUP BY day ORDER BY day ASC
  `).all();

  // Tong views hom nay
  var todayViews = db.prepare(`
    SELECT COUNT(*) as c FROM view_log
    WHERE created_at >= datetime('now', 'start of day')
  `).get().c || 0;

  // Bounce rate trung binh (chi tinh bai co duration_sec)
  var avgBounce = db.prepare(`
    SELECT ROUND(100.0 * SUM(CASE WHEN duration_sec < 30 THEN 1 ELSE 0 END)
      / NULLIF(COUNT(*), 0), 1) as rate
    FROM view_log WHERE duration_sec IS NOT NULL
  `).get().rate || 0;

  // Thoi gian doc trung binh (giay)
  var avgDuration = db.prepare(`
    SELECT ROUND(AVG(duration_sec), 0) as avg
    FROM view_log WHERE duration_sec IS NOT NULL AND duration_sec > 0
  `).get().avg || 0;

  // Views theo category (cho content page)
  var categoryViews = db.prepare(`
    SELECT a.category, a.category_label, COUNT(vl.id) as views
    FROM view_log vl
    JOIN articles a ON a.id = vl.article_id
    WHERE vl.created_at >= datetime('now', '-30 days')
    GROUP BY a.category ORDER BY views DESC
  `).all();

  // Device breakdown tu user_agent
  var agents = db.prepare(`
    SELECT user_agent FROM view_log
    WHERE user_agent IS NOT NULL AND user_agent != ''
    AND created_at >= datetime('now', '-7 days')
  `).all();
  var mobile = 0, desktop = 0;
  agents.forEach(function(r) {
    var ua = (r.user_agent || '').toLowerCase();
    if (/mobi|android|iphone|ipad|tablet/.test(ua)) mobile++;
    else desktop++;
  });
  var total_ua = mobile + desktop || 1;

  res_ok(res, {
    articles:      db.prepare('SELECT COUNT(*) as c FROM articles WHERE deleted_at IS NULL').get().c,
    drafts:        db.prepare("SELECT COUNT(*) as c FROM articles WHERE status='draft' AND deleted_at IS NULL").get().c,
    users:         db.prepare('SELECT COUNT(*) as c FROM users').get().c,
    comments:      db.prepare('SELECT COUNT(*) as c FROM comments WHERE deleted_at IS NULL').get().c,
    newsletters:   db.prepare('SELECT COUNT(*) as c FROM newsletters').get().c,
    bookmarks:     db.prepare('SELECT COUNT(*) as c FROM bookmarks').get().c,
    totalViews:    totalViews,
    todayViews:    todayViews,
    weeklyViews:   weeklyRows,
    avgBounceRate: avgBounce,
    avgReadSec:    avgDuration,
    categoryViews: categoryViews,
    deviceSplit:   { mobile: Math.round(mobile/total_ua*100), desktop: Math.round(desktop/total_ua*100) },
    topArticles:   db.prepare('SELECT id,title,total_views as views,shares,bounce_rate,thumbnail,category_label FROM articles WHERE deleted_at IS NULL ORDER BY total_views DESC LIMIT 5').all(),
    recentUsers:   db.prepare('SELECT id,name,email,avatar,role,status,created_at FROM users ORDER BY id DESC LIMIT 5').all(),
    adsSummary:    db.prepare(`
      SELECT
        COUNT(*) as campaigns,
        COALESCE(SUM(impressions),0) as impressions,
        COALESCE(SUM(clicks),0) as clicks,
        COALESCE(SUM(spent),0) as spent,
        COALESCE(SUM(revenue),0) as revenue
      FROM ad_campaigns
    `).get(),
  });
});

// GET /api/admin/notifications — tổng hợp sự kiện gần đây
app.get('/api/admin/notifications', requireAdmin, function(_req, res) {
  var notifs = [];

  // Bình luận mới (7 ngày)
  var newComments = db.prepare(`
    SELECT c.id, c.created_at, u.name as user_name, a.title as article_title
    FROM comments c
    JOIN users u ON u.id = c.user_id
    JOIN articles a ON a.id = c.article_id
    WHERE c.deleted_at IS NULL AND c.created_at >= datetime('now', '-7 days')
    ORDER BY c.created_at DESC LIMIT 10
  `).all();
  newComments.forEach(function(r) {
    notifs.push({ type: 'comment', icon: 'comment', title: 'Bình luận mới',
      desc: (r.user_name || '—') + ' bình luận vào "' + (r.article_title || '').slice(0,40) + '"',
      time: r.created_at, read: false });
  });

  // User mới (7 ngày)
  var newUsers = db.prepare(`
    SELECT id, name, email, created_at FROM users
    WHERE created_at >= datetime('now', '-7 days')
    ORDER BY created_at DESC LIMIT 5
  `).all();
  newUsers.forEach(function(r) {
    notifs.push({ type: 'user', icon: 'user', title: 'Người dùng mới',
      desc: (r.name || r.email || '—') + ' vừa đăng ký tài khoản',
      time: r.created_at, read: false });
  });

  // Newsletter mới (7 ngày)
  var newNL = db.prepare(`
    SELECT email, created_at FROM newsletters
    WHERE created_at >= datetime('now', '-7 days')
    ORDER BY created_at DESC LIMIT 5
  `).all();
  newNL.forEach(function(r) {
    notifs.push({ type: 'newsletter', icon: 'mail', title: 'Đăng ký newsletter',
      desc: r.email + ' đã đăng ký nhận bản tin',
      time: r.created_at, read: false });
  });

  // Bài viết mới (3 ngày)
  var newArticles = db.prepare(`
    SELECT id, title, author, date FROM articles
    WHERE deleted_at IS NULL AND date >= datetime('now', '-3 days')
    ORDER BY date DESC LIMIT 5
  `).all();
  newArticles.forEach(function(r) {
    notifs.push({ type: 'article', icon: 'article', title: 'Bài viết mới xuất bản',
      desc: '"' + (r.title || '').slice(0, 50) + '" — ' + (r.author || 'Admin'),
      time: r.date, read: true });
  });

  // Sắp xếp mới nhất trước
  notifs.sort(function(a, b) { return new Date(b.time) - new Date(a.time); });

  res_ok(res, {
    items: notifs.slice(0, 30),
    unread: notifs.filter(function(n) { return !n.read; }).length,
  });
});

// GET /api/admin/activity-logs
app.get('/api/admin/activity-logs', requireAdmin, function(req, res) {
  var page = Math.max(1, parseInt(req.query.page) || 1);
  var limit = Math.min(100, Math.max(1, parseInt(req.query.limit) || 20));
  var offset = (page - 1) * limit;
  var userId = parseInt(req.query.userId);
  var route = safeText(req.query.route || '', 120);

  var where = ['1=1'];
  var args = [];
  if (!isNaN(userId)) { where.push('user_id=?'); args.push(userId); }
  if (route) { where.push('route_path LIKE ?'); args.push('%' + route + '%'); }
  var baseSql = 'FROM request_audit_log WHERE ' + where.join(' AND ');

  var total = db.prepare('SELECT COUNT(*) as c ' + baseSql).get(...args).c;
  var items = db.prepare(`
    SELECT id, request_id, user_id, method, route_path, status_code, duration_ms, ip, error_message, created_at
    ${baseSql}
    ORDER BY datetime(created_at) DESC
    LIMIT ? OFFSET ?
  `).all(...args, limit, offset);
  res_ok(res, paginateResult(items, total, page, limit));
});

// GET /api/admin/system/health
// Quan sat tinh trang server/queue/db de van hanh on dinh
app.get('/api/admin/system/health', requireAdmin, function(_req, res) {
  var dbStats = {
    users: db.prepare('SELECT COUNT(*) as c FROM users').get().c || 0,
    articles: db.prepare('SELECT COUNT(*) as c FROM articles WHERE deleted_at IS NULL').get().c || 0,
    viewLog: db.prepare('SELECT COUNT(*) as c FROM view_log').get().c || 0,
    analyticsEvents: db.prepare('SELECT COUNT(*) as c FROM user_analytics_events').get().c || 0,
    syncRequests: db.prepare('SELECT COUNT(*) as c FROM analytics_sync_requests').get().c || 0,
    auditLogs: db.prepare('SELECT COUNT(*) as c FROM request_audit_log').get().c || 0,
  };
  var queue = {
    pending: analyticsEventQueue.length,
    busy: analyticsQueueBusy,
  };
  var latestAudit = db.prepare(`
    SELECT request_id, method, route_path, status_code, duration_ms, created_at
    FROM request_audit_log
    ORDER BY datetime(created_at) DESC
    LIMIT 10
  `).all();
  res_ok(res, {
    uptimeSec: Math.floor(process.uptime()),
    time: new Date().toISOString(),
    retentionDays: LOG_RETENTION_DAYS,
    analyticsDailyLimit: MAX_ANALYTICS_EVENTS_PER_USER_PER_DAY,
    queue: queue,
    dbStats: dbStats,
    latestAudit: latestAudit,
  });
});
app.get('/api/admin/system-health', requireAdmin, function(req, res) {
  req.url = '/api/admin/system/health';
  var dbStats = {
    users: db.prepare('SELECT COUNT(*) as c FROM users').get().c || 0,
    articles: db.prepare('SELECT COUNT(*) as c FROM articles WHERE deleted_at IS NULL').get().c || 0,
    viewLog: db.prepare('SELECT COUNT(*) as c FROM view_log').get().c || 0,
    analyticsEvents: db.prepare('SELECT COUNT(*) as c FROM user_analytics_events').get().c || 0,
    syncRequests: db.prepare('SELECT COUNT(*) as c FROM analytics_sync_requests').get().c || 0,
    auditLogs: db.prepare('SELECT COUNT(*) as c FROM request_audit_log').get().c || 0,
  };
  res_ok(res, {
    uptimeSec: Math.floor(process.uptime()),
    time: new Date().toISOString(),
    retentionDays: LOG_RETENTION_DAYS,
    analyticsDailyLimit: MAX_ANALYTICS_EVENTS_PER_USER_PER_DAY,
    queue: { pending: analyticsEventQueue.length, busy: analyticsQueueBusy },
    dbStats: dbStats,
  });
});

// GET /api/admin/traffic?period=7d|30d&groupBy=hour
app.get('/api/admin/traffic', requireAdmin, function(req, res) {
  var groupBy = req.query.groupBy;

  if (groupBy === 'hour') {
    // Traffic theo giờ hôm nay (0–23)
    var rows = db.prepare(`
      SELECT strftime('%H', created_at) as hour, COUNT(*) as views
      FROM view_log
      WHERE created_at >= datetime('now', 'start of day')
      GROUP BY hour
      ORDER BY hour ASC
    `).all();
    // Điền đủ 24 giờ dù không có data
    var filled = [];
    for (var h = 0; h < 24; h++) {
      var hStr = String(h).padStart(2, '0');
      var found = rows.find(function(r) { return r.hour === hStr; });
      filled.push({ hour: hStr + ':00', views: found ? found.views : 0 });
    }
    return res_ok(res, filled);
  }

  var period = req.query.period === '30d' ? '30 days' : '7 days';
  var rows = db.prepare(`
    SELECT date(created_at) as day, COUNT(*) as views
    FROM view_log
    WHERE created_at >= datetime('now', '-${period}')
    GROUP BY day
    ORDER BY day ASC
  `).all();
  res_ok(res, rows);
});

// GET /api/admin/articles
app.get('/api/admin/articles', requireAdmin, function(req, res) {
  var page     = Math.max(1, parseInt(req.query.page)  || 1);
  var limit    = Math.min(50, Math.max(1, parseInt(req.query.limit) || 20));
  var status   = req.query.status;
  var category = req.query.category;
  var offset   = (page - 1) * limit;

  var where = ['1=1'];
  var args  = [];

  // Admin co the xem ca deleted
  if (req.query.includeDeleted !== 'true') where.push('deleted_at IS NULL');
  if (status && VALID_STATUSES.has(status))             { where.push('status=?'); args.push(status); }
  if (category && VALID_CATEGORY_IDS.has(category))     { where.push('category=?'); args.push(category); }

  var baseSQL = 'FROM articles WHERE ' + where.join(' AND ');
  var total   = db.prepare('SELECT COUNT(*) as c ' + baseSQL).get(...args).c;
  var rows    = db.prepare('SELECT * ' + baseSQL + ' ORDER BY date DESC LIMIT ? OFFSET ?')
                  .all(...args, limit, offset)
                  .map(formatArticleAdmin);

  res_ok(res, paginateResult(rows, total, page, limit));
});

// POST /api/admin/articles
app.post('/api/admin/articles', requireAdmin, function(req, res) {
  var b = req.body;
  if (!b.title || !b.category) return res_err(res, 'Thiếu tiêu đề hoặc chuyên mục');
  if (!VALID_CATEGORY_IDS.has(b.category)) return res_err(res, 'Chuyên mục không hợp lệ');

  var slug = generateSlug(b.title);
  var info = db.prepare(`
    INSERT INTO articles
      (slug,category,category_label,title,excerpt,content,author,author_avatar,
       date,read_time,thumbnail,tags,is_featured,is_hot,status)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
  `).run(
    slug,
    b.category,
    b.categoryLabel || (CATEGORIES.find(function(c) { return c.id === b.category; }) || {}).label || b.category,
    b.title.slice(0, 500),
    (b.excerpt || '').slice(0, 1000),
    b.content || '',
    (b.author || 'Admin').slice(0, 100),
    (b.authorAvatar || '').slice(0, 500),
    b.date || new Date().toISOString(),
    parseInt(b.readTime) || 4,
    (b.thumbnail || '').slice(0, 500),
    JSON.stringify(Array.isArray(b.tags) ? b.tags.slice(0, 10) : []),
    b.isFeatured ? 1 : 0,
    b.isHot ? 1 : 0,
    VALID_STATUSES.has(b.status) ? b.status : 'published'
  );

  res_ok(res, formatArticleAdmin(stmt.articleById.get(info.lastInsertRowid)), 201);
});

// PUT /api/admin/articles/:id
app.put('/api/admin/articles/:id', requireAdmin, function(req, res) {
  var id  = parseInt(req.params.id);
  var row = db.prepare('SELECT * FROM articles WHERE id=?').get(id); // cho phep edit ca archived
  if (!row) return res_err(res, 'Không tìm thấy bài viết', 404);

  var b = req.body;
  if (b.category && !VALID_CATEGORY_IDS.has(b.category)) return res_err(res, 'Chuyên mục không hợp lệ');
  if (b.status   && !VALID_STATUSES.has(b.status))       return res_err(res, 'Trạng thái không hợp lệ');

  var newTitle = (b.title || row.title).slice(0, 500);
  // Chi tai tao slug neu title thay doi
  var newSlug  = (b.title && b.title !== row.title) ? generateSlug(b.title) : row.slug;

  db.prepare(`
    UPDATE articles SET
      slug=?, category=?, category_label=?, title=?, excerpt=?, content=?,
      author=?, author_avatar=?, date=?, read_time=?, thumbnail=?,
      tags=?, is_featured=?, is_hot=?, status=?, bounce_rate=?
    WHERE id=?
  `).run(
    newSlug,
    b.category      || row.category,
    b.categoryLabel || row.category_label,
    newTitle,
    b.excerpt       !== undefined ? b.excerpt.slice(0, 1000) : row.excerpt,
    b.content       !== undefined ? b.content : row.content,
    (b.author       || row.author).slice(0, 100),
    b.authorAvatar  !== undefined ? b.authorAvatar.slice(0, 500) : row.author_avatar,
    b.date          || row.date,
    parseInt(b.readTime) || row.read_time,
    b.thumbnail     !== undefined ? b.thumbnail.slice(0, 500) : row.thumbnail,
    b.tags          ? JSON.stringify(b.tags.slice(0, 10)) : row.tags,
    b.isFeatured    !== undefined ? (b.isFeatured ? 1 : 0) : row.is_featured,
    b.isHot         !== undefined ? (b.isHot      ? 1 : 0) : row.is_hot,
    VALID_STATUSES.has(b.status) ? b.status : row.status,
    b.bounceRate    !== undefined ? parseFloat(b.bounceRate) || 0 : row.bounce_rate,
    id
  );

  res_ok(res, formatArticleAdmin(db.prepare('SELECT * FROM articles WHERE id=?').get(id)));
});

// DELETE /api/admin/articles/:id  (soft delete)
app.delete('/api/admin/articles/:id', requireAdmin, function(req, res) {
  var id  = parseInt(req.params.id);
  var row = stmt.articleById.get(id);
  if (!row) return res_err(res, 'Không tìm thấy bài viết', 404);

  if (req.query.hard === 'true') {
    // Hard delete chi khi truyen ?hard=true
    stmt.hardDelete.run(id);
    res_ok(res, { message: 'Đã xoá vĩnh viễn bài viết', id: id });
  } else {
    stmt.softDelete.run(id);
    res_ok(res, { message: 'Đã xoá bài viết (có thể khôi phục)', id: id });
  }
});

// GET /api/admin/users
app.get('/api/admin/users', requireAdmin, function(req, res) {
  var page   = Math.max(1, parseInt(req.query.page)  || 1);
  var limit  = Math.min(100, Math.max(1, parseInt(req.query.limit) || 20));
  var offset = (page - 1) * limit;

  var where = ['1=1'];
  var args  = [];

  if (req.query.role   && VALID_ROLES.has(req.query.role))               { where.push('role=?');   args.push(req.query.role); }
  if (req.query.status && VALID_USER_STATUSES.has(req.query.status))     { where.push('status=?'); args.push(req.query.status); }

  var baseSQL = 'FROM users WHERE ' + where.join(' AND ');
  var total   = db.prepare('SELECT COUNT(*) as c ' + baseSQL).get(...args).c;
  var rows    = db.prepare('SELECT * ' + baseSQL + ' ORDER BY id DESC LIMIT ? OFFSET ?')
                  .all(...args, limit, offset)
                  .map(safeUserAdmin);

  res_ok(res, paginateResult(rows, total, page, limit));
});

// GET /api/admin/users/:id/activity
app.get('/api/admin/users/:id/activity', requireAdmin, function(req, res) {
  var id = parseInt(req.params.id);
  var user = stmt.userById.get(id);
  if (!user) return res_err(res, 'Người dùng không tồn tại', 404);

  var recentActions = db.prepare(`
    SELECT id, activity_type, payload_json, created_at
    FROM user_activity_log
    WHERE user_id=?
    ORDER BY datetime(created_at) DESC
    LIMIT 50
  `).all(id).map(function(r) {
    var payload = {};
    try { payload = JSON.parse(r.payload_json || '{}'); } catch (_e) {}
    return { id: r.id, type: r.activity_type, payload: payload, createdAt: r.created_at };
  });

  var analytics = stmt.recentAnalyticsEvents.all(id, 50).map(function(r) {
    var metadata = {};
    try { metadata = JSON.parse(r.metadata_json || '{}'); } catch (_e) {}
    return {
      id: r.id,
      type: r.event_type,
      target: r.event_target || null,
      metadata: metadata,
      source: r.source || 'ui',
      createdAt: r.created_at,
    };
  });

  res_ok(res, { user: safeUserAdmin(user), activity: recentActions, analyticsEvents: analytics });
});

// GET /api/admin/ads
app.get('/api/admin/ads', requireAdmin, function(req, res) {
  var page = Math.max(1, parseInt(req.query.page) || 1);
  var limit = Math.min(100, Math.max(1, parseInt(req.query.limit) || 20));
  var offset = (page - 1) * limit;
  var items = stmt.adCampaigns.all(limit, offset).map(function(r) {
    var tags = [];
    try { tags = JSON.parse(r.target_tags || '[]'); } catch (_e) {}
    r.targetTags = tags;
    delete r.target_tags;
    return r;
  });
  var total = stmt.adCampaignCount.get().c;
  res_ok(res, paginateResult(items, total, page, limit));
});

// POST /api/admin/ads
app.post('/api/admin/ads', requireAdmin, enforcePayloadLimit(512 * 1024), rateLimit(20), function(req, res) {
  var b = req.body || {};
  var name = safeText(b.name, 150);
  var platform = safeText(b.platform, 80);
  if (!name || !platform) return res_err(res, 'Thiếu name hoặc platform');
  var status = ['active', 'paused', 'completed'].includes(b.status) ? b.status : 'active';
  var tags = Array.isArray(b.targetTags) ? b.targetTags.map(function(t) { return safeText(t, 40).toLowerCase(); }).slice(0, 20) : [];
  var info = stmt.addCampaign.run(
    name, platform, status,
    Number(b.budget || 0), Number(b.spent || 0), Number(b.revenue || 0),
    parseInt(b.impressions || 0), parseInt(b.clicks || 0), Number(b.ctr || 0),
    JSON.stringify(tags),
    b.startsAt || null,
    b.endsAt || null
  );
  res_ok(res, stmt.adCampaignById.get(info.lastInsertRowid), 201);
});

// PUT /api/admin/ads/:id
app.put('/api/admin/ads/:id', requireAdmin, enforcePayloadLimit(512 * 1024), rateLimit(30), function(req, res) {
  var id = parseInt(req.params.id);
  var old = stmt.adCampaignById.get(id);
  if (!old) return res_err(res, 'Campaign không tồn tại', 404);
  var b = req.body || {};
  var name = safeText(b.name !== undefined ? b.name : old.name, 150);
  var platform = safeText(b.platform !== undefined ? b.platform : old.platform, 80);
  var status = ['active', 'paused', 'completed'].includes(b.status) ? b.status : old.status;
  var tags = b.targetTags ? JSON.stringify((Array.isArray(b.targetTags) ? b.targetTags : []).slice(0, 20)) : old.target_tags;
  stmt.updateCampaign.run(
    name, platform, status,
    Number(b.budget !== undefined ? b.budget : old.budget),
    Number(b.spent !== undefined ? b.spent : old.spent),
    Number(b.revenue !== undefined ? b.revenue : old.revenue),
    parseInt(b.impressions !== undefined ? b.impressions : old.impressions),
    parseInt(b.clicks !== undefined ? b.clicks : old.clicks),
    Number(b.ctr !== undefined ? b.ctr : old.ctr),
    tags,
    b.startsAt !== undefined ? b.startsAt : old.starts_at,
    b.endsAt !== undefined ? b.endsAt : old.ends_at,
    id
  );
  runtimeCache.delByPrefix('rec:ads:user:');
  res_ok(res, stmt.adCampaignById.get(id));
});

// DELETE /api/admin/ads/:id
app.delete('/api/admin/ads/:id', requireAdmin, function(req, res) {
  var id = parseInt(req.params.id);
  var old = stmt.adCampaignById.get(id);
  if (!old) return res_err(res, 'Campaign không tồn tại', 404);
  stmt.delCampaign.run(id);
  runtimeCache.delByPrefix('rec:ads:user:');
  res_ok(res, { id: id, deleted: true });
});

// POST /api/admin/ads/:id/events  (impression/click/conversion)
app.post('/api/admin/ads/:id/events', requireAdmin, enforcePayloadLimit(128 * 1024), rateLimit(100), function(req, res) {
  var id = parseInt(req.params.id);
  var campaign = stmt.adCampaignById.get(id);
  if (!campaign) return res_err(res, 'Campaign không tồn tại', 404);
  var type = safeText(req.body.type || req.body.eventType || 'impression', 20).toLowerCase();
  if (!['impression', 'click', 'conversion'].includes(type)) return res_err(res, 'event type không hợp lệ');
  var value = Number(req.body.value || 0);
  stmt.addAdEvent.run(id, req.body.userId ? parseInt(req.body.userId) : null, type, value, new Date().toISOString());

  if (type === 'impression') {
    db.prepare('UPDATE ad_campaigns SET impressions=impressions+1, updated_at=datetime(\'now\') WHERE id=?').run(id);
  } else if (type === 'click') {
    db.prepare('UPDATE ad_campaigns SET clicks=clicks+1, spent=spent+?, updated_at=datetime(\'now\') WHERE id=?').run(value, id);
  } else if (type === 'conversion') {
    db.prepare('UPDATE ad_campaigns SET revenue=revenue+?, updated_at=datetime(\'now\') WHERE id=?').run(value, id);
  }
  db.prepare(`
    UPDATE ad_campaigns
    SET ctr = CASE WHEN impressions > 0 THEN ROUND(clicks * 100.0 / impressions, 2) ELSE 0 END
    WHERE id=?
  `).run(id);

  runtimeCache.delByPrefix('rec:ads:user:');
  res_ok(res, stmt.adCampaignById.get(id));
});

// GET /api/admin/products
app.get('/api/admin/products', requireAdmin, function(req, res) {
  var page = Math.max(1, parseInt(req.query.page) || 1);
  var limit = Math.min(100, Math.max(1, parseInt(req.query.limit) || 20));
  var offset = (page - 1) * limit;
  var items = stmt.adminProductList.all(limit, offset).map(function(p) {
    try { p.tags = JSON.parse(p.tags || '[]'); } catch (_e) { p.tags = []; }
    try { p.season_tags = JSON.parse(p.season_tags || '[]'); } catch (_e2) { p.season_tags = []; }
    return p;
  });
  var total = stmt.adminProductCount.get().c || 0;
  res_ok(res, paginateResult(items, total, page, limit));
});

// POST /api/admin/products
app.post('/api/admin/products', requireAdmin, rateLimit(40), function(req, res) {
  var b = req.body || {};
  var name = safeText(b.name, 160);
  var category = safeText(b.category, 50).toLowerCase();
  if (!name || !category) return res_err(res, 'Thiếu name/category');
  var tags = safeJsonArrayText(b.tags || [], 25);
  var seasonTags = safeJsonArrayText(b.seasonTags || b.season_tags || [], 12);
  var info = stmt.addProduct.run(
    name,
    category,
    JSON.stringify(tags),
    Number(b.price || 0),
    Math.max(0, parseInt(b.stock || 0)),
    Math.max(0, Number(b.trendScore || b.trend_score || 0)),
    JSON.stringify(seasonTags),
    ['active', 'inactive'].includes(b.status) ? b.status : 'active'
  );
  runtimeCache.delByPrefix('rec:shop:user:');
  res_ok(res, stmt.productById.get(info.lastInsertRowid), 201);
});

// PUT /api/admin/products/:id
app.put('/api/admin/products/:id', requireAdmin, rateLimit(60), function(req, res) {
  var id = parseInt(req.params.id);
  var old = stmt.productById.get(id);
  if (!old) return res_err(res, 'Product không tồn tại', 404);
  var b = req.body || {};
  var tags = b.tags !== undefined ? safeJsonArrayText(b.tags || [], 25) : parseJsonArraySafe(old.tags || '[]');
  var seasonTags = (b.seasonTags !== undefined || b.season_tags !== undefined)
    ? safeJsonArrayText(b.seasonTags || b.season_tags || [], 12)
    : parseJsonArraySafe(old.season_tags || '[]');
  stmt.updateProduct.run(
    safeText(b.name !== undefined ? b.name : old.name, 160),
    safeText((b.category !== undefined ? b.category : old.category), 50).toLowerCase(),
    JSON.stringify(tags),
    Number(b.price !== undefined ? b.price : old.price),
    Math.max(0, parseInt(b.stock !== undefined ? b.stock : old.stock)),
    Math.max(0, Number(b.trendScore !== undefined ? b.trendScore : (b.trend_score !== undefined ? b.trend_score : old.trend_score))),
    JSON.stringify(seasonTags),
    ['active', 'inactive'].includes(b.status) ? b.status : old.status,
    id
  );
  runtimeCache.delByPrefix('rec:shop:user:');
  res_ok(res, stmt.productById.get(id));
});

// DELETE /api/admin/products/:id
app.delete('/api/admin/products/:id', requireAdmin, function(req, res) {
  var id = parseInt(req.params.id);
  if (!stmt.productById.get(id)) return res_err(res, 'Product không tồn tại', 404);
  stmt.delProduct.run(id);
  runtimeCache.delByPrefix('rec:shop:user:');
  res_ok(res, { id: id, deleted: true });
});

// PATCH /api/admin/users/:id
app.patch('/api/admin/users/:id', requireAdmin, function(req, res) {
  var id   = parseInt(req.params.id);
  var user = stmt.userById.get(id);
  if (!user) return res_err(res, 'Người dùng không tồn tại', 404);

  var b = req.body;
  var name   = (b.name   !== undefined) ? (b.name + '').trim().slice(0, 100)   : user.name;
  var email  = (b.email  !== undefined) ? (b.email + '').trim().toLowerCase().slice(0, 200) : user.email;
  var role   = (b.role   !== undefined && VALID_ROLES.has(b.role))         ? b.role   : user.role;
  var status = (b.status !== undefined && VALID_USER_STATUSES.has(b.status)) ? b.status : user.status;
  var phone  = (b.phone  !== undefined) ? (b.phone + '').trim().slice(0, 20) : user.phone;

  // Kiem tra email trung neu thay doi
  if (email !== user.email && stmt.userByEmail.get(email)) {
    return res_err(res, 'Email đã được sử dụng boi tai khoan khac');
  }

  db.prepare(`
    UPDATE users SET name=?, email=?, role=?, status=?, phone=?, updated_at=datetime('now') WHERE id=?
  `).run(name, email, role, status, phone, id);

  res_ok(res, safeUserAdmin(stmt.userById.get(id)));
});

// DELETE /api/admin/users/:id
app.delete('/api/admin/users/:id', requireAdmin, function(req, res) {
  var id   = parseInt(req.params.id);
  var user = stmt.userById.get(id);
  if (!user) return res_err(res, 'Người dùng không tồn tại', 404);
  if (user.role === 'admin') return res_err(res, 'Không thể xoá tài khoản admin', 403);

  db.prepare('DELETE FROM users WHERE id=?').run(id);
  res_ok(res, { message: 'Đã xoá người dùng', id: id });
});

// PATCH /api/admin/profile — cap nhat thong tin admin dang nhap
app.patch('/api/admin/profile', requireAdmin, function(req, res) {
  try {
    var user = db.prepare('SELECT * FROM users WHERE id=?').get(req.user.id);
    if (!user) return res_err(res, 'Khong tim thay user', 404);
    var name  = safeText(req.body.name  || '', 100);
    var email = safeText(req.body.email || '', 200);
    var pass  = req.body.password || '';
    if (name)  db.prepare("UPDATE users SET name=?, updated_at=datetime('now') WHERE id=?").run(name, req.user.id);
    if (email) db.prepare("UPDATE users SET email=?, updated_at=datetime('now') WHERE id=?").run(email, req.user.id);
    if (pass && pass.length >= 8) {
      db.prepare("UPDATE users SET password=?, updated_at=datetime('now') WHERE id=?").run(bcrypt.hashSync(pass, 10), req.user.id);
    }
    res_ok(res, { ok: true });
  } catch(e) { res_err(res, e.message, 500); }
});

// GET /api/admin/settings
app.get('/api/admin/settings', requireAdmin, function(_req, res) {
  var rows = db.prepare('SELECT key, value FROM site_settings').all();
  var settings = {};
  rows.forEach(function(r) { settings[r.key] = r.value; });
  res_ok(res, settings);
});

// PUT /api/admin/settings
app.put('/api/admin/settings', requireAdmin, function(req, res) {
  var allowed = ['siteName', 'domain', 'email', 'description', 'logoUrl', 'timezone'];
  var upsert  = db.prepare("INSERT INTO site_settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value");
  var updated = {};

  db.transaction(function() {
    allowed.forEach(function(key) {
      if (req.body[key] !== undefined) {
        var val = (req.body[key] + '').trim().slice(0, 500);
        upsert.run(key, val);
        updated[key] = val;
      }
    });
  })();

  res_ok(res, updated);
});

// ============================================================
// ACTIVITY & SIGNAL — SCHEMA
// ============================================================

db.exec(`
  CREATE TABLE IF NOT EXISTS activity_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  TEXT NOT NULL,
    user_id     TEXT,
    article_id  TEXT,
    event_type  TEXT NOT NULL,
    event_data  TEXT,
    page        TEXT,
    device      TEXT,
    keywords    TEXT,
    ts          TEXT,
    ts_ms       INTEGER,
    created_at  TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS signal_sessions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      TEXT UNIQUE NOT NULL,
    user_id         TEXT,
    article_id      TEXT,
    article_tag     TEXT,
    flush_reason    TEXT,
    time_on_page    INTEGER DEFAULT 0,
    scroll_depth    INTEGER DEFAULT 0,
    committed_data  TEXT,
    candidate_data  TEXT,
    highlights      TEXT,
    searches        TEXT,
    started_at      TEXT,
    ended_at        TEXT,
    created_at      TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS reading_signals (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  TEXT NOT NULL,
    user_id     TEXT NOT NULL,
    article_id  TEXT,
    block_id    TEXT,
    tag         TEXT NOT NULL,
    signal_score REAL DEFAULT 0,
    level       TEXT DEFAULT 'CANDIDATE',
    signals_json TEXT DEFAULT '[]',
    occurred_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS user_interests_signal (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         TEXT NOT NULL,
    tag             TEXT NOT NULL,
    level           TEXT DEFAULT 'LOW',
    score           REAL DEFAULT 1,
    decay_score     REAL DEFAULT 1,
    signal_count    INTEGER DEFAULT 1,
    last_signal_at  TEXT DEFAULT (datetime('now')),
    created_at      TEXT DEFAULT (datetime('now')),
    UNIQUE(user_id, tag)
  );

  CREATE TABLE IF NOT EXISTS user_text_highlights (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     TEXT NOT NULL,
    session_id  TEXT,
    block_id    TEXT,
    tag         TEXT,
    text_content TEXT,
    signal_type TEXT DEFAULT 'highlight',
    occurred_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS tag_market_stats (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    tag          TEXT NOT NULL,
    period       TEXT NOT NULL,
    period_key   TEXT NOT NULL,
    unique_users INTEGER DEFAULT 0,
    total_signals INTEGER DEFAULT 0,
    high_count   INTEGER DEFAULT 0,
    avg_score    REAL DEFAULT 0,
    top_block_id TEXT,
    updated_at   TEXT DEFAULT (datetime('now')),
    UNIQUE(tag, period, period_key)
  );

  CREATE INDEX IF NOT EXISTS idx_activity_events_session ON activity_events(session_id);
  CREATE INDEX IF NOT EXISTS idx_activity_events_ts      ON activity_events(ts);
  CREATE INDEX IF NOT EXISTS idx_signal_sessions_user    ON signal_sessions(user_id);
  CREATE INDEX IF NOT EXISTS idx_reading_signals_user    ON reading_signals(user_id, tag);
  CREATE INDEX IF NOT EXISTS idx_uis_user_tag            ON user_interests_signal(user_id, tag);
  CREATE INDEX IF NOT EXISTS idx_uis_decay               ON user_interests_signal(decay_score DESC);
  CREATE INDEX IF NOT EXISTS idx_tag_market_period       ON tag_market_stats(tag, period_key);
`);

// ============================================================
// ACTIVITY & SIGNAL — HELPERS
// ============================================================

var SIGNAL_DECAY = { HIGH: 0.02, MEDIUM: 0.05, LOW: 0.15 };

function calcDecayScore(score, level, lastSignalAt) {
  var lambda = SIGNAL_DECAY[level] || 0.15;
  var days = (Date.now() - new Date(lastSignalAt).getTime()) / 86400000;
  return parseFloat((score * Math.exp(-lambda * days)).toFixed(4));
}

function refreshDecayForUser(userId) {
  try {
    var rows = db.prepare('SELECT id, score, level, last_signal_at FROM user_interests_signal WHERE user_id=?').all(userId);
    var upd  = db.prepare('UPDATE user_interests_signal SET decay_score=? WHERE id=?');
    db.transaction(function() {
      rows.forEach(function(r) { upd.run(calcDecayScore(r.score, r.level, r.last_signal_at), r.id); });
    })();
  } catch(_e) {}
}

function updateTagMarketStats(tag, level, score) {
  try {
    var now = new Date();
    var dayKey   = now.toISOString().slice(0, 10);
    var weekKey  = 'W' + Math.ceil(now.getDate() / 7) + '-' + now.toISOString().slice(0, 7);
    var monthKey = now.toISOString().slice(0, 7);
    [['day', dayKey], ['week', weekKey], ['month', monthKey]].forEach(function(p) {
      db.prepare(`
        INSERT INTO tag_market_stats (tag, period, period_key, unique_users, total_signals, high_count, avg_score, updated_at)
        VALUES (?, ?, ?, 1, 1, ?, ?, datetime('now'))
        ON CONFLICT(tag, period, period_key) DO UPDATE SET
          total_signals = total_signals + 1,
          high_count    = high_count + CASE WHEN ? = 'HIGH' THEN 1 ELSE 0 END,
          avg_score     = ROUND((avg_score * total_signals + ?) / (total_signals + 1), 4),
          updated_at    = datetime('now')
      `).run(tag, p[0], p[1], level === 'HIGH' ? 1 : 0, score, level, score);
    });
  } catch(_e) {}
}

// Decay job hàng ngày cho user_interests_signal (3 giờ sáng)
(function scheduleDailyDecay() {
  function runDecay() {
    try {
      var rows = db.prepare("SELECT id, score, level, last_signal_at FROM user_interests_signal WHERE last_signal_at < datetime('now', '-1 day')").all();
      var upd  = db.prepare('UPDATE user_interests_signal SET decay_score=? WHERE id=?');
      db.transaction(function() {
        rows.forEach(function(r) { upd.run(calcDecayScore(r.score, r.level, r.last_signal_at), r.id); });
        db.prepare('DELETE FROM user_interests_signal WHERE decay_score < 0.5').run();
    
    // Reset 1d scores for old interactions
    db.prepare(`
      UPDATE topic_interest_signals
      SET interest_score_1d = 0
      WHERE last_interaction_at < datetime('now', '-1 day')
    `).run();
  })();
      console.log('[signal-decay] Processed ' + rows.length + ' interests');
    } catch(e) { console.warn('[signal-decay]', e.message); }
  }
  function msUntil3am() {
    var now = new Date(), next = new Date(now);
    next.setHours(3, 0, 0, 0);
    if (next <= now) next.setDate(next.getDate() + 1);
    return next.getTime() - now.getTime();
  }
  setTimeout(function tick() { runDecay(); setTimeout(tick, 86400000); }, msUntil3am());
})();

// ============================================================
// ACTIVITY & SIGNAL — ENDPOINTS
// ============================================================

// POST /api/activity/batch — nhan batch events tu EventTracker (news-ui-v2)
app.post('/api/activity/batch', enforcePayloadLimit(2 * 1024 * 1024), function(req, res) {
  try {
    var payload = req.body;
    if (!payload || !payload.events || !Array.isArray(payload.events)) {
      return res_err(res, 'Invalid payload', 400);
    }
    var userInfo  = payload.userInfo || {};
    var sessionId = userInfo.sessionId || ('sess_' + Date.now());
    var userId    = userInfo.userId || null;

    var insertEvent = db.prepare(
      "INSERT OR IGNORE INTO activity_events (session_id, user_id, article_id, event_type, event_data, page, device, keywords, ts, ts_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    );
    var insertMany = db.transaction(function(events) {
      events.forEach(function(ev) {
        insertEvent.run(
          ev.sessionId || sessionId,
          ev.userId || userId,
          (ev.data && ev.data.articleId) || null,
          ev.type || 'unknown',
          JSON.stringify(ev.data || {}),
          ev.page || null,
          ev.device || userInfo.device || null,
          JSON.stringify(ev.keywords || []),
          ev.ts || new Date().toISOString(),
          ev.tsMs || Date.now()
        );
      });
    });
    insertMany(payload.events.slice(0, 200));
    res_ok(res, { received: payload.events.length });
  } catch(e) {
    res_err(res, e.message, 500);
  }
});

// GET /api/activity/recent — realtime feed cho admin dashboard
app.get('/api/activity/recent', requireAdmin, function(req, res) {
  try {
    var limit = Math.min(parseInt(req.query.limit) || 20, 100);
    var rows = db.prepare(
      "SELECT session_id, user_id, event_type, event_data, page, device, keywords, ts FROM activity_events ORDER BY id DESC LIMIT ?"
    ).all(limit);
    var events = rows.map(function(r) {
      var data = {}; var kws = [];
      try { data = JSON.parse(r.event_data || '{}'); } catch(e) {}
      try { kws  = JSON.parse(r.keywords   || '[]'); } catch(e) {}
      return { sessionId: r.session_id, userId: r.user_id, type: r.event_type, data: data, page: r.page, device: r.device, keywords: kws, ts: r.ts };
    });
    res_ok(res, { events: events, total: events.length });
  } catch(e) {
    res_err(res, e.message, 500);
  }
});

// GET /api/activity/keywords — top keywords tu activity data
app.get('/api/activity/keywords', requireAdmin, function(req, res) {
  try {
    var limit = Math.min(parseInt(req.query.limit) || 30, 100);
    var rows = db.prepare(
      "SELECT keywords FROM activity_events WHERE keywords IS NOT NULL AND keywords != '[]' ORDER BY id DESC LIMIT 2000"
    ).all();
    var freq = {};
    rows.forEach(function(r) {
      try {
        JSON.parse(r.keywords || '[]').forEach(function(kw) {
          if (!kw || kw.length < 2) return;
          kw = kw.toLowerCase().trim();
          freq[kw] = (freq[kw] || 0) + 1;
        });
      } catch(e) {}
    });
    var keywords = Object.entries(freq)
      .sort(function(a, b) { return b[1] - a[1]; })
      .slice(0, limit)
      .map(function(e) { return { keyword: e[0], count: e[1] }; });
    res_ok(res, { keywords: keywords });
  } catch(e) {
    res_err(res, e.message, 500);
  }
});

// POST /api/signals/flush — nhan signal data tu SignalEngine, xu ly day du theo spec
app.post('/api/signals/flush', function(req, res) {
  try {
    var payload    = req.body;
    if (!payload || !payload.session_id) return res_err(res, 'Invalid payload', 400);

    var userId     = payload.user_id || null;
    var articleId  = payload.article_id || null;
    var committed  = payload.committed_blocks  || [];
    var candidates = payload.candidate_blocks  || [];
    var highlights = payload.highlights        || [];
    var searches   = payload.searches          || [];
    var timeOnPage = payload.time_on_page      || 0;
    var flushReason = payload.flush_reason     || 'unknown';

    // B1: Chong gui trung — cho phep update neu la flush cuoi
    var existingSession = db.prepare('SELECT id FROM signal_sessions WHERE session_id=?').get(payload.session_id);
    if (existingSession && flushReason !== 'session_end' && flushReason !== 'beforeunload') {
      return res_ok(res, { ok: true, skipped: true, reason: 'duplicate_session' });
    }

    // B1: Luu session
    db.prepare(`
      INSERT OR REPLACE INTO signal_sessions
        (session_id, user_id, article_id, article_tag, flush_reason, time_on_page, scroll_depth,
         committed_data, candidate_data, highlights, searches, started_at, ended_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      payload.session_id, userId, articleId,
      payload.article_tag || null, flushReason,
      timeOnPage, payload.scroll_depth || 0,
      JSON.stringify(committed), JSON.stringify(candidates),
      JSON.stringify(highlights), JSON.stringify(searches),
      payload.started_at || new Date().toISOString(),
      payload.ended_at   || new Date().toISOString()
    );

    var allBlocks = committed.concat(candidates);
    if (!allBlocks.length || !userId) {
      return res_ok(res, { ok: true, committed: 0, interests_updated: 0 });
    }

    // Kiem tra ngoai le leo tat tang: copy + highlight + search cung tag -> MEDIUM ngay
    var fastTrackTags = new Set();
    if (highlights.length > 0 && searches.length > 0) {
      committed.forEach(function(b) {
        if (!b.tag) return;
        var hasCopy      = b.signals && b.signals.includes('copy');
        var hasHighlight = b.signals && b.signals.includes('highlight');
        var hasSearch    = searches.some(function(s) {
          return s.query && s.query.toLowerCase().includes(b.tag.toLowerCase());
        });
        if (hasCopy && hasHighlight && hasSearch) fastTrackTags.add(b.tag.toLowerCase());
      });
    }

    var interestsUpdated = 0;
    var insertSignal = db.prepare(`
      INSERT INTO reading_signals (session_id, user_id, article_id, block_id, tag, signal_score, level, signals_json, occurred_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
    `);

    // B2 + B3: Xu ly tung block
    db.transaction(function() {
      allBlocks.forEach(function(b) {
        if (!b.tag || !b.score) return;
        var tag   = b.tag.toLowerCase().trim();
        var level = b.level || 'CANDIDATE';

        // Ghi reading_signal
        insertSignal.run(
          payload.session_id, userId, articleId,
          b.block_id || null, tag, b.score, level,
          JSON.stringify(b.signals || [])
        );

        if (b.score < 8) return; // Chi xu ly CANDIDATE tro len

        var cur = db.prepare('SELECT * FROM user_interests_signal WHERE user_id=? AND tag=?').get(userId, tag);
        var newLevel = null;

        if (!cur) {
          // CHUA CO: can PENDING + co co che chu dong + time > 90s
          var hasActive = b.signals && b.signals.some(function(s) {
            return ['scroll_back','highlight','copy','oscillation'].includes(s);
          });
          var qualifies = (level === 'PENDING' || level === 'CONFIRMED') && hasActive && timeOnPage > 90;
          if (qualifies || fastTrackTags.has(tag)) {
            newLevel = fastTrackTags.has(tag) ? 'MEDIUM' : 'LOW';
            db.prepare(`
              INSERT INTO user_interests_signal (user_id, tag, level, score, decay_score, signal_count, last_signal_at)
              VALUES (?, ?, ?, ?, ?, 1, datetime('now'))
            `).run(userId, tag, newLevel, b.score, b.score);
            interestsUpdated++;
            updateTagMarketStats(tag, newLevel, b.score);
          }
        } else {
          // DA CO: kiem tra dieu kien nang tang
          var hoursSinceLast = (Date.now() - new Date(cur.last_signal_at).getTime()) / 3600000;
          if (cur.level === 'LOW' && hoursSinceLast >= 2 && b.score >= 8) {
            newLevel = 'MEDIUM';
          } else if (cur.level === 'MEDIUM') {
            var sessionCount = db.prepare(`
              SELECT COUNT(DISTINCT session_id) as c FROM reading_signals
              WHERE user_id=? AND tag=? AND occurred_at > datetime('now', '-14 days')
            `).get(userId, tag).c;
            var hasExplicitSearch = searches.some(function(s) {
              return s.query && s.query.toLowerCase().includes(tag);
            });
            if (sessionCount >= 3 || hasExplicitSearch) newLevel = 'HIGH';
          } else if (fastTrackTags.has(tag) && cur.level === 'LOW') {
            newLevel = 'MEDIUM';
          }

          if (newLevel) {
            db.prepare(`UPDATE user_interests_signal SET level=?, score=score+?, signal_count=signal_count+1, last_signal_at=datetime('now') WHERE user_id=? AND tag=?`).run(newLevel, b.score, userId, tag);
          } else {
            db.prepare(`UPDATE user_interests_signal SET score=score+?, signal_count=signal_count+1, last_signal_at=datetime('now') WHERE user_id=? AND tag=?`).run(b.score, userId, tag);
          }
          interestsUpdated++;
          updateTagMarketStats(tag, newLevel || cur.level, b.score);
        }
      });
    })();

    // B5: Luu text highlights
    if (highlights.length > 0) {
      var insertHL = db.prepare(`
        INSERT INTO user_text_highlights (user_id, session_id, block_id, tag, text_content, signal_type, occurred_at)
        VALUES (?, ?, ?, ?, ?, 'highlight', datetime('now'))
      `);
      db.transaction(function() {
        highlights.slice(0, 20).forEach(function(h) {
          if (!h.text) return;
          insertHL.run(userId, payload.session_id, h.block_id || null, h.tag || null, h.text.slice(0, 500));
        });
      })();
    }

    // B4: Tinh lai decay_score
    if (interestsUpdated > 0) {
      setImmediate(function() { refreshDecayForUser(userId); });
      runtimeCache.delByPrefix('rec:content:user:');
    }

    res_ok(res, { ok: true, committed: committed.length, interests_updated: interestsUpdated });
  } catch(e) {
    res_err(res, e.message, 500);
  }
});

// GET /api/admin/signals — xem signal sessions tren admin
app.get('/api/admin/signals', requireAdmin, function(req, res) {
  try {
    var page   = Math.max(1, parseInt(req.query.page)  || 1);
    var limit  = Math.min(parseInt(req.query.limit) || 20, 100);
    var offset = (page - 1) * limit;
    var rows   = db.prepare(
      "SELECT session_id, user_id, article_id, article_tag, flush_reason, time_on_page, scroll_depth, started_at, ended_at, created_at FROM signal_sessions ORDER BY id DESC LIMIT ? OFFSET ?"
    ).all(limit, offset);
    var total = db.prepare("SELECT COUNT(*) as c FROM signal_sessions").get().c;
    res_ok(res, { sessions: rows, total: total, page: page, limit: limit });
  } catch(e) {
    res_err(res, e.message, 500);
  }
});

// GET /api/admin/interests — xem user interests tu signal engine
app.get('/api/admin/interests', requireAdmin, function(req, res) {
  try {
    var limit = Math.min(parseInt(req.query.limit) || 50, 200);
    var tag   = req.query.tag || null;
    var rows  = tag
      ? db.prepare("SELECT * FROM user_interests_signal WHERE tag=? ORDER BY decay_score DESC LIMIT ?").all(tag, limit)
      : db.prepare("SELECT * FROM user_interests_signal ORDER BY decay_score DESC LIMIT ?").all(limit);
    res_ok(res, { interests: rows, total: rows.length });
  } catch(e) {
    res_err(res, e.message, 500);
  }
});

// GET /api/admin/tag-stats — thong ke tag market cho admin
app.get('/api/admin/tag-stats', requireAdmin, function(req, res) {
  try {
    var period = ['day','week','month'].includes(req.query.period) ? req.query.period : 'day';
    var limit  = Math.min(parseInt(req.query.limit) || 20, 100);
    var rows   = db.prepare(
      "SELECT tag, SUM(total_signals) as total_signals, SUM(high_count) as high_count, AVG(avg_score) as avg_score FROM tag_market_stats WHERE period=? GROUP BY tag ORDER BY total_signals DESC LIMIT ?"
    ).all(period, limit);
    res_ok(res, { stats: rows, period: period });
  } catch(e) {
    res_err(res, e.message, 500);
  }
});

// GET /api/user/signal-recommendations — de xuat noi dung dua tren signal interests (MEDIUM + HIGH)
app.get('/api/user/signal-recommendations', optionalAuth, function(req, res) {
  try {
    var userId = req.user ? String(req.user.id) : (req.query.uid || null);
    if (!userId) return res_ok(res, { content: [], reason: 'no_user' });

    var limit = Math.min(parseInt(req.query.limit) || 6, 20);

    var interests = db.prepare(
      "SELECT tag, level, decay_score FROM user_interests_signal WHERE user_id=? AND level IN ('MEDIUM','HIGH') AND last_signal_at > datetime('now', '-14 days') ORDER BY CASE level WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 1 ELSE 0 END DESC, decay_score DESC LIMIT 5"
    ).all(userId);

    if (!interests.length) return res_ok(res, { content: [], reason: 'no_signal_interests' });

    var tags   = interests.map(function(i) { return i.tag; });
    var tagMap = {};
    interests.forEach(function(i) { tagMap[i.tag] = i.decay_score; });

    var recentViewed = db.prepare(
      "SELECT DISTINCT article_id FROM reading_signals WHERE user_id=? AND occurred_at > datetime('now', '-7 days') AND article_id IS NOT NULL"
    ).all(userId).map(function(r) { return r.article_id; });

    var ph   = tags.map(function() { return '?'; }).join(',');
    var exPh = recentViewed.length
      ? ' AND CAST(a.id AS TEXT) NOT IN (' + recentViewed.map(function() { return '?'; }).join(',') + ')'
      : '';

    var articles = db.prepare(
      'SELECT a.id, a.title, a.category, a.category_label, a.thumbnail, a.total_views as views, a.date, a.tags FROM articles a WHERE a.status=\'published\' AND a.deleted_at IS NULL AND a.category IN (' + ph + ')' + exPh + ' ORDER BY a.total_views DESC, a.date DESC LIMIT ?'
    ).all(...tags, ...recentViewed, limit);

    var result = articles.map(function(a) {
      var matchedTag = tags.find(function(t) { return a.category === t || (a.tags || '').includes(t); }) || tags[0];
      return {
        id: a.id, title: a.title, category: a.category, category_label: a.category_label,
        thumbnail: a.thumbnail, views: a.views, date: a.date,
        tag_matched: matchedTag,
        match_score: parseFloat(((tagMap[matchedTag] || 0.1) * Math.log1p(a.views || 1)).toFixed(4)),
      };
    }).sort(function(a, b) { return b.match_score - a.match_score; });

    res_ok(res, { content: result, interests_used: tags });
  } catch(e) {
    res_err(res, e.message, 500);
  }
});

// ============================================================
// IMPRESSION LOG + SIGNAL ACTION — SCHEMA
// ============================================================

db.exec(`
  CREATE TABLE IF NOT EXISTS impression_log (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id      TEXT,
    article_id   INTEGER,
    position     TEXT DEFAULT 'recommendation',
    clicked      INTEGER DEFAULT 0,
    dismissed    INTEGER DEFAULT 0,
    created_at   TEXT DEFAULT (datetime('now'))
  );
  CREATE INDEX IF NOT EXISTS idx_imp_user_article ON impression_log(user_id, article_id);
  CREATE INDEX IF NOT EXISTS idx_imp_created      ON impression_log(created_at);

  CREATE TABLE IF NOT EXISTS signal_actions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    TEXT NOT NULL,
    action     TEXT NOT NULL,
    article_id TEXT,
    tag        TEXT,
    points     INTEGER DEFAULT 0,
    ts         TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  );
  CREATE INDEX IF NOT EXISTS idx_sa_user_tag ON signal_actions(user_id, tag);
`);

// ── POST /api/user/signal-action ─────────────────────────────
// Nhan hanh dong chu dong tu frontend: like, share, comment
// Ghi nhan ngay lap tuc, cap nhat user_interests_signal
app.post('/api/user/signal-action', function(req, res) {
  try {
    var payload = req.body;
    if (!payload || !payload.action || !payload.user_id) {
      return res_ok(res, { ok: false, reason: 'missing_fields' });
    }
    var userId    = safeText(payload.user_id, 100);
    var action    = safeText(payload.action, 20);
    var articleId = safeText(payload.article_id || '', 50);
    var tag       = safeText((payload.tag || '').toLowerCase().trim(), 50);
    var points    = Math.min(Math.max(parseInt(payload.points) || 0, 0), 50);

    // Luu signal action
    db.prepare(
      "INSERT INTO signal_actions (user_id, action, article_id, tag, points, ts) VALUES (?, ?, ?, ?, ?, ?)"
    ).run(userId, action, articleId || null, tag || null, points, payload.ts || new Date().toISOString());

    // Cap nhat user_interests_signal ngay lap tuc neu co tag
    if (tag && points > 0) {
      var existing = db.prepare('SELECT * FROM user_interests_signal WHERE user_id=? AND tag=?').get(userId, tag);
      if (!existing) {
        // Tao moi o muc LOW
        db.prepare(
          "INSERT INTO user_interests_signal (user_id, tag, level, score, decay_score, signal_count, last_signal_at) VALUES (?, ?, 'LOW', ?, ?, 1, datetime('now'))"
        ).run(userId, tag, points, points);
      } else {
        // Nang cap: like/share co the nang len MEDIUM/HIGH ngay
        var newLevel = existing.level;
        if (action === 'share' && existing.level === 'MEDIUM') newLevel = 'HIGH';
        else if ((action === 'like' || action === 'share') && existing.level === 'LOW') newLevel = 'MEDIUM';
        db.prepare(
          "UPDATE user_interests_signal SET score=score+?, signal_count=signal_count+1, level=?, last_signal_at=datetime('now') WHERE user_id=? AND tag=?"
        ).run(points, newLevel, userId, tag);
      }
      // Invalidate recommendation cache
      runtimeCache.delByPrefix('rec:content:user:');
    }

    res_ok(res, { ok: true, action: action, points: points });
  } catch(e) {
    res_err(res, e.message, 500);
  }
});

// ── POST /api/articles/:id/impression ────────────────────────
// Ghi nhan impression de xuat (bai vao viewport > 1s)
app.post('/api/articles/:id/impression', function(req, res) {
  try {
    var articleId = parseInt(req.params.id);
    if (!articleId) return res_err(res, 'Invalid id', 400);
    var userId  = req.body.user_id || null;
    var clicked = req.body.clicked ? 1 : 0;
    var pos     = safeText(req.body.position || 'recommendation', 50);

    db.prepare(
      "INSERT INTO impression_log (user_id, article_id, position, clicked) VALUES (?, ?, ?, ?)"
    ).run(userId, articleId, pos, clicked);

    // Kiem tra frequency: user thay bai nay >= 3 lan ma khong click -> ghi nhan
    if (!clicked && userId) {
      var count = db.prepare(
        "SELECT COUNT(*) as c FROM impression_log WHERE user_id=? AND article_id=? AND clicked=0 AND created_at > datetime('now', '-7 days')"
      ).get(userId, articleId).c;
      if (count >= 3) {
        // Danh dau "da thay nhieu lan khong click" — frontend xu ly loai khoi de xuat
        return res_ok(res, { ok: true, suppress: true, reason: 'seen_3x_no_click' });
      }
    }

    res_ok(res, { ok: true });
  } catch(e) {
    res_err(res, e.message, 500);
  }
});

// ── GET /api/admin/activity ───────────────────────────────────
// Bang chi tiet activity cho admin (khac voi /api/activity/recent)
app.get('/api/admin/activity', requireAdmin, function(req, res) {
  try {
    var page   = Math.max(1, parseInt(req.query.page) || 1);
    var limit  = Math.min(parseInt(req.query.limit) || 30, 100);
    var offset = (page - 1) * limit;
    var type   = req.query.type || null;

    var where = type ? "WHERE event_type=?" : "";
    var args  = type ? [type, limit, offset] : [limit, offset];

    var rows = db.prepare(
      "SELECT id, session_id, user_id, article_id, event_type, event_data, page, device, keywords, ts, created_at FROM activity_events " + where + " ORDER BY id DESC LIMIT ? OFFSET ?"
    ).all(...args);

    var total = db.prepare("SELECT COUNT(*) as c FROM activity_events" + (type ? " WHERE event_type=?" : "")).get(...(type ? [type] : [])).c;

    var events = rows.map(function(r) {
      var data = {}; var kws = [];
      try { data = JSON.parse(r.event_data || '{}'); } catch(_e) {}
      try { kws  = JSON.parse(r.keywords   || '[]'); } catch(_e) {}
      return {
        id: r.id, sessionId: r.session_id, userId: r.user_id,
        articleId: r.article_id, type: r.event_type,
        data: data, page: r.page, device: r.device,
        keywords: kws, ts: r.ts, createdAt: r.created_at
      };
    });

    // Thong ke theo loai event
    var typeCounts = db.prepare(
      "SELECT event_type, COUNT(*) as c FROM activity_events GROUP BY event_type ORDER BY c DESC LIMIT 20"
    ).all();

    res_ok(res, { events: events, total: total, page: page, limit: limit, type_counts: typeCounts });
  } catch(e) {
    res_err(res, e.message, 500);
  }
});

// ── GET /api/admin/alerts ─────────────────────────────────────
// Canh bao he thong cho admin (spec supplement ch.8)
app.get('/api/admin/alerts', requireAdmin, function(req, res) {
  try {
    var alerts = [];
    var now = new Date().toISOString();

    // 1. Kiem tra luong activity giam > 50% so voi cung gio hom qua
    var thisHour = db.prepare(
      "SELECT COUNT(*) as c FROM activity_events WHERE created_at > datetime('now', '-1 hour')"
    ).get().c;
    var lastHour = db.prepare(
      "SELECT COUNT(*) as c FROM activity_events WHERE created_at BETWEEN datetime('now', '-25 hours') AND datetime('now', '-24 hours')"
    ).get().c;
    if (lastHour > 10 && thisHour < lastHour * 0.5) {
      alerts.push({ type: 'tracking_drop', severity: 'warn',
        message: 'Luong activity giam > 50% so voi cung gio hom qua (' + thisHour + ' vs ' + lastHour + ')',
        ts: now });
    }

    // 2. Kiem tra tag tang nhanh nhung khong co quang cao
    var hotTags = db.prepare(
      "SELECT tag, SUM(total_signals) as total FROM tag_market_stats WHERE period='day' AND period_key >= date('now', '-7 days') GROUP BY tag ORDER BY total DESC LIMIT 5"
    ).all();
    hotTags.forEach(function(t) {
      var hasAd = db.prepare(
        "SELECT COUNT(*) as c FROM ad_campaigns WHERE status='active' AND target_tags LIKE ?"
      ).get('%' + t.tag + '%').c;
      if (!hasAd && t.total > 20) {
        alerts.push({ type: 'tag_no_ad', severity: 'info',
          message: 'Tag "' + t.tag + '" dang hot (' + t.total + ' signals) nhung khong co quang cao',
          ts: now });
      }
    });

    // 3. Kiem tra unmet needs (search nhieu lan khong click)
    var unmetCount = db.prepare(
      "SELECT COUNT(*) as c FROM signal_actions WHERE action='unmet_need' AND created_at > datetime('now', '-1 day')"
    ).get().c;
    if (unmetCount > 5) {
      alerts.push({ type: 'unmet_needs', severity: 'info',
        message: unmetCount + ' luot tim kiem khong tim duoc ket qua phu hop trong 24h qua',
        ts: now });
    }

    res_ok(res, { alerts: alerts, total: alerts.length });
  } catch(e) {
    res_err(res, e.message, 500);
  }
});

// ── GET /api/admin/ads/forecast ───────────────────────────────
// Du bao so user co tag nhat dinh (cho form nhap QC)
app.get('/api/admin/ads/forecast', requireAdmin, function(req, res) {
  try {
    var tags = (req.query.tags || '').split(',').map(function(t) { return t.trim().toLowerCase(); }).filter(Boolean);
    if (!tags.length) return res_ok(res, { forecast: [] });

    var forecast = tags.map(function(tag) {
      var active = db.prepare(
        "SELECT COUNT(DISTINCT user_id) as c FROM user_interests_signal WHERE tag=? AND level IN ('MEDIUM','HIGH') AND last_signal_at > datetime('now', '-14 days')"
      ).get(tag).c;
      var fading = db.prepare(
        "SELECT COUNT(DISTINCT user_id) as c FROM user_interests_signal WHERE tag=? AND level='LOW' AND last_signal_at > datetime('now', '-30 days')"
      ).get(tag).c;
      return { tag: tag, active_users: active, fading_users: fading };
    });

    res_ok(res, { forecast: forecast });
  } catch(e) {
    res_err(res, e.message, 500);
  }
});

// ── POST /api/ads/:id/event ───────────────────────────────────
// Nhan event tu frontend: impression, click, dismiss
app.post('/api/ads/:id/event', function(req, res) {
  try {
    var adId   = parseInt(req.params.id);
    var type   = safeText(req.body.type || 'impression', 20);
    var userId = safeText(req.body.user_id || '', 100) || null;
    var value  = parseFloat(req.body.value) || 0;

    if (!adId) return res_err(res, 'Invalid ad id', 400);

    // Ghi impression_log
    if (type === 'impression' || type === 'click' || type === 'dismiss') {
      db.prepare(
        "INSERT INTO impression_log (user_id, article_id, position, clicked, dismissed) VALUES (?, ?, 'ad', ?, ?)"
      ).run(userId, adId, type === 'click' ? 1 : 0, type === 'dismiss' ? 1 : 0);
    }

    // Cap nhat ad_campaigns stats
    if (type === 'impression') {
      db.prepare("UPDATE ad_campaigns SET impressions=impressions+1, updated_at=datetime('now') WHERE id=?").run(adId);
      // Tru budget (impression duoc tinh)
      db.prepare("UPDATE ad_campaigns SET spent=spent+0.001 WHERE id=?").run(adId);
    } else if (type === 'click') {
      db.prepare("UPDATE ad_campaigns SET clicks=clicks+1, spent=spent+?, updated_at=datetime('now') WHERE id=?").run(value || 0.01, adId);
    } else if (type === 'conversion') {
      db.prepare("UPDATE ad_campaigns SET revenue=revenue+?, updated_at=datetime('now') WHERE id=?").run(value, adId);
    }

    // Cap nhat CTR
    db.prepare("UPDATE ad_campaigns SET ctr=CASE WHEN impressions>0 THEN ROUND(clicks*100.0/impressions,2) ELSE 0 END WHERE id=?").run(adId);

    // Auto-update status: budget het -> EXHAUSTED
    var ad = db.prepare("SELECT budget, spent, ends_at FROM ad_campaigns WHERE id=?").get(adId);
    if (ad) {
      if (ad.spent >= ad.budget && ad.budget > 0) {
        db.prepare("UPDATE ad_campaigns SET status='exhausted', updated_at=datetime('now') WHERE id=?").run(adId);
      } else if (ad.ends_at && ad.ends_at < new Date().toISOString().slice(0,10)) {
        db.prepare("UPDATE ad_campaigns SET status='expired', updated_at=datetime('now') WHERE id=?").run(adId);
      }
    }

    res_ok(res, { ok: true, type: type });
  } catch(e) {
    res_err(res, e.message, 500);
  }
});

// ── Auto-update ad status job (moi 1 gio) ────────────────────
setInterval(function() {
  try {
    // EXHAUSTED: budget het
    db.prepare("UPDATE ad_campaigns SET status='exhausted', updated_at=datetime('now') WHERE status='active' AND budget > 0 AND spent >= budget").run();
    // EXPIRED: qua end_date
    db.prepare("UPDATE ad_campaigns SET status='expired', updated_at=datetime('now') WHERE status='active' AND ends_at IS NOT NULL AND ends_at < date('now')").run();
    console.log('[ad-status] Auto-updated ad statuses');
  } catch(e) { console.warn('[ad-status]', e.message); }
}, 60 * 60 * 1000);

// === TECHPULSE BEHAVIORAL PATCH ===
// Req 9-18: Signal tables, CRUD APIs, Recommendation Engine nâng cấp

// ── INIT BEHAVIORAL TABLES ──────────────────────────────────────────────────
(function initBehavioralTables() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS behavior_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT UNIQUE,
      event_name TEXT NOT NULL, ts_client INTEGER,
      ts_server INTEGER DEFAULT (strftime('%s','now') * 1000),
      visitor_id TEXT, session_id TEXT, user_id TEXT, content_id TEXT,
      section_id TEXT, scroll_percent INTEGER DEFAULT 0,
      active_ms INTEGER DEFAULT 0, idle_ms INTEGER DEFAULT 0,
      visible_ms INTEGER DEFAULT 0, dwell_ms INTEGER DEFAULT 0,
      reread_count INTEGER DEFAULT 0, search_query TEXT,
      ad_id TEXT, ad_slot_id TEXT, media_id TEXT,
      media_progress_percent INTEGER DEFAULT 0, transition_source TEXT,
      from_content_id TEXT, to_content_id TEXT,
      copied_text_length INTEGER DEFAULT 0, comment_length INTEGER DEFAULT 0,
      share_channel TEXT, payload_json TEXT DEFAULT '{}',
      page_url TEXT, viewport_type TEXT, referrer_type TEXT,
      created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS session_states (
      session_id TEXT PRIMARY KEY, visitor_id TEXT, user_id TEXT,
      current_content_id TEXT, current_section_id TEXT, previous_content_id TEXT,
      opened_contents_json TEXT DEFAULT '[]', recent_searches_json TEXT DEFAULT '[]',
      recent_transitions_json TEXT DEFAULT '[]',
      search_count INTEGER DEFAULT 0, transition_count INTEGER DEFAULT 0,
      deep_read_count INTEGER DEFAULT 0, high_intent_count INTEGER DEFAULT 0,
      bounce_flag INTEGER DEFAULT 0, compare_mode_flag INTEGER DEFAULT 0,
      started_at TEXT DEFAULT (datetime('now')), last_seen_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS content_signals (
      id INTEGER PRIMARY KEY AUTOINCREMENT, content_id TEXT NOT NULL,
      visitor_id TEXT, user_id TEXT, session_id TEXT,
      read_score REAL DEFAULT 0, focus_score REAL DEFAULT 0,
      high_intent_score REAL DEFAULT 0, unsatisfied_score REAL DEFAULT 0,
      completion_rate REAL DEFAULT 0, updated_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS topic_interest_signals (
      id INTEGER PRIMARY KEY AUTOINCREMENT, subject_id TEXT NOT NULL,
      subject_type TEXT NOT NULL DEFAULT 'visitor', topic_tag TEXT NOT NULL,
      interest_score_1d REAL DEFAULT 0,
      interest_score_7d REAL DEFAULT 0,
      interest_score_30d REAL DEFAULT 0, interest_score_7d REAL DEFAULT 0,
      interest_score_30d REAL DEFAULT 0, session_score REAL DEFAULT 0,
      escalation_score REAL DEFAULT 0, unsatisfied_score REAL DEFAULT 0,
      last_interaction_at TEXT DEFAULT (datetime('now')),
      UNIQUE(subject_id, subject_type, topic_tag)
    );
    CREATE TABLE IF NOT EXISTS ad_signals (
      id INTEGER PRIMARY KEY AUTOINCREMENT, visitor_id TEXT, user_id TEXT,
      ad_id TEXT NOT NULL, impression_count INTEGER DEFAULT 0,
      viewable_count REAL DEFAULT 0, click_count INTEGER DEFAULT 0,
      dismiss_count INTEGER DEFAULT 0, fatigue_score REAL DEFAULT 0,
      negative_score REAL DEFAULT 0, last_seen_at TEXT DEFAULT (datetime('now')),
      UNIQUE(visitor_id, ad_id)
    );
    CREATE TABLE IF NOT EXISTS admin_audit_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT, admin_user_id INTEGER DEFAULT 0,
      action_type TEXT NOT NULL, target_type TEXT, target_id TEXT,
      before_json TEXT DEFAULT '{}', after_json TEXT DEFAULT '{}',
      created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS websites (
      website_id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
      type TEXT DEFAULT 'main', domain TEXT, status TEXT DEFAULT 'active',
      default_topic_scope TEXT DEFAULT '[]',
      created_at TEXT DEFAULT (datetime('now')), updated_at TEXT
    );
    CREATE TABLE IF NOT EXISTS content_sections (
      section_id TEXT PRIMARY KEY, content_id TEXT NOT NULL,
      section_order INTEGER DEFAULT 0, section_type TEXT DEFAULT 'text',
      title TEXT, start_percent REAL DEFAULT 0, end_percent REAL DEFAULT 100,
      keywords_json TEXT DEFAULT '[]', topic_child_ids_json TEXT DEFAULT '[]',
      importance_weight REAL DEFAULT 1.0,
      is_problem_statement INTEGER DEFAULT 0, is_solution_statement INTEGER DEFAULT 0,
      is_question_block INTEGER DEFAULT 0, is_transition_trigger INTEGER DEFAULT 0,
      flags_json TEXT DEFAULT '{}'
    );
    CREATE TABLE IF NOT EXISTS content_relations (
      relation_id INTEGER PRIMARY KEY AUTOINCREMENT,
      from_content_id TEXT NOT NULL, to_content_id TEXT NOT NULL,
      relation_type TEXT DEFAULT 'related', weight REAL DEFAULT 1.0,
      source TEXT DEFAULT 'manual', created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS guest_profiles (
      visitor_id TEXT PRIMARY KEY, temp_profile_json TEXT DEFAULT '{}',
      temp_interest_json TEXT DEFAULT '{}',
      temp_recommendation_state_json TEXT DEFAULT '{}',
      merged_to_user_id TEXT DEFAULT NULL, archived INTEGER DEFAULT 0,
      created_at TEXT DEFAULT (datetime('now')), updated_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS sequence_records (
      sequence_id TEXT PRIMARY KEY, session_id TEXT NOT NULL,
      sequence_type TEXT NOT NULL, start_event TEXT, end_event TEXT,
      ordered_events_json TEXT DEFAULT '[]', content_ids_json TEXT DEFAULT '[]',
      section_ids_json TEXT DEFAULT '[]', topics_json TEXT DEFAULT '[]',
      transition_count INTEGER DEFAULT 0, search_count INTEGER DEFAULT 0,
      ad_count INTEGER DEFAULT 0, total_duration_ms INTEGER DEFAULT 0,
      outcome_type TEXT DEFAULT 'unknown', created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS section_features (
      id INTEGER PRIMARY KEY AUTOINCREMENT, content_id TEXT NOT NULL,
      section_id TEXT NOT NULL, view_count_1d INTEGER DEFAULT 0,
      view_count_7d INTEGER DEFAULT 0, view_count_30d INTEGER DEFAULT 0,
      avg_norm_dwell_7d REAL DEFAULT 0, focus_count_7d INTEGER DEFAULT 0,
      copy_count_30d INTEGER DEFAULT 0, search_trigger_count_30d INTEGER DEFAULT 0,
      section_heat_score REAL DEFAULT 0, updated_at TEXT DEFAULT (datetime('now')),
      UNIQUE(content_id, section_id)
    );
    CREATE TABLE IF NOT EXISTS content_features (
      content_id TEXT PRIMARY KEY, read_score_1d REAL DEFAULT 0,
      read_score_7d REAL DEFAULT 0, read_score_30d REAL DEFAULT 0,
      deep_read_rate REAL DEFAULT 0, avg_completion_rate REAL DEFAULT 0,
      high_intent_score_7d REAL DEFAULT 0, search_origin_score_7d REAL DEFAULT 0,
      unsatisfied_score_7d REAL DEFAULT 0, updated_at TEXT DEFAULT (datetime('now'))
  
  -- Add deep read tracking columns if not exists
  ALTER TABLE content_features ADD COLUMN IF NOT EXISTS total_read_sessions INTEGER DEFAULT 0;
  ALTER TABLE content_features ADD COLUMN IF NOT EXISTS deep_read_sessions INTEGER DEFAULT 0;
  ALTER TABLE content_features ADD COLUMN IF NOT EXISTS completion_sum REAL DEFAULT 0;
  );
    CREATE TABLE IF NOT EXISTS content_transition_features (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      from_content_id TEXT NOT NULL, to_content_id TEXT NOT NULL,
      transition_count_1d INTEGER DEFAULT 0, transition_count_7d INTEGER DEFAULT 0,
      avg_post_click_dwell REAL DEFAULT 0, transition_strength REAL DEFAULT 0,
      return_back_rate REAL DEFAULT 0, updated_at TEXT DEFAULT (datetime('now')),
      UNIQUE(from_content_id, to_content_id)
    );
        CREATE TABLE IF NOT EXISTS topics (
      topic_id TEXT PRIMARY KEY,
      topic_name TEXT NOT NULL,
      topic_level TEXT NOT NULL, -- grandparent|parent|child
      parent_topic_id TEXT DEFAULT NULL,
      grandparent_topic_id TEXT DEFAULT NULL,
      keywords_json TEXT DEFAULT '[]',
      description TEXT,
      created_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (parent_topic_id) REFERENCES topics(topic_id),
      FOREIGN KEY (grandparent_topic_id) REFERENCES topics(topic_id)
    );
    CREATE TABLE IF NOT EXISTS content_topics (
      content_id TEXT NOT NULL,
      topic_id TEXT NOT NULL,
      topic_level TEXT NOT NULL,
      relevance_score REAL DEFAULT 1.0,
      PRIMARY KEY (content_id, topic_id)
    );
    CREATE TABLE IF NOT EXISTS links (
      link_id TEXT PRIMARY KEY,
      link_type TEXT NOT NULL, -- inline|question|solution|related|recommendation|ad
      from_content_id TEXT NOT NULL,
      from_section_id TEXT,
      to_content_id TEXT,
      target_url TEXT,
      linked_topic_ids TEXT DEFAULT '[]',
      priority_weight REAL DEFAULT 1.0,
      created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS media_metadata (
      media_id TEXT PRIMARY KEY,
      media_type TEXT NOT NULL, -- image|video|widget|chart|table
      content_id TEXT NOT NULL,
      section_id TEXT,
      media_topic_ids TEXT DEFAULT '[]',
      importance_weight REAL DEFAULT 1.0,
      media_url TEXT,
      created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS ad_slots (
      ad_slot_id TEXT PRIMARY KEY,
      ad_slot_type TEXT NOT NULL, -- inline|sidebar|sticky|after_section|between_related
      content_id TEXT,
      section_id TEXT,
      allowed_ad_categories TEXT DEFAULT '[]',
      blocked_ad_categories TEXT DEFAULT '[]',
      contextual_topic_ids TEXT DEFAULT '[]',
      ad_position_weight REAL DEFAULT 1.0,
      created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_topics_level ON topics(topic_level);
    CREATE INDEX IF NOT EXISTS idx_topics_parent ON topics(parent_topic_id);
    CREATE INDEX IF NOT EXISTS idx_content_topics_content ON content_topics(content_id);
    CREATE INDEX IF NOT EXISTS idx_content_topics_topic ON content_topics(topic_id);
    CREATE INDEX IF NOT EXISTS idx_links_from ON links(from_content_id);
    CREATE INDEX IF NOT EXISTS idx_links_type ON links(link_type);
    CREATE INDEX IF NOT EXISTS idx_media_content ON media_metadata(content_id);
    CREATE INDEX IF NOT EXISTS idx_ad_slots_content ON ad_slots(content_id);
    CREATE TABLE IF NOT EXISTS intent_signals (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      session_id TEXT NOT NULL,
      user_id TEXT,
      visitor_id TEXT,
      intent_type TEXT NOT NULL, -- overview|deep_dive|solution_seeking|comparing|specific_key|browsing
      confidence_score REAL DEFAULT 0,
      evidence_events_json TEXT DEFAULT '[]',
      current_content_id TEXT,
      current_section_id TEXT,
      detected_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (session_id) REFERENCES session_states(session_id)
    );
    CREATE TABLE IF NOT EXISTS followup_signals (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      from_content_id TEXT NOT NULL,
      to_content_id TEXT NOT NULL,
      followup_reason TEXT NOT NULL, -- same_topic_parent|same_topic_child|search_followup|transition_affinity|problem_solution
      strength_score REAL DEFAULT 0,
      evidence_count INTEGER DEFAULT 0,
      last_seen_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS ad_context_signals (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      content_id TEXT NOT NULL,
      section_id TEXT,
      ad_category TEXT NOT NULL,
      context_fit_score REAL DEFAULT 0,
      problem_solution_fit REAL DEFAULT 0,
      timing_readiness REAL DEFAULT 0,
      updated_at TEXT DEFAULT (datetime('now')),
      UNIQUE(content_id, section_id, ad_category)
    );
    CREATE INDEX IF NOT EXISTS idx_intent_session ON intent_signals(session_id);
    CREATE INDEX IF NOT EXISTS idx_intent_type ON intent_signals(intent_type);
    CREATE INDEX IF NOT EXISTS idx_followup_from ON followup_signals(from_content_id);
    CREATE INDEX IF NOT EXISTS idx_followup_to ON followup_signals(to_content_id);
    CREATE INDEX IF NOT EXISTS idx_ad_context_content ON ad_context_signals(content_id);
    CREATE INDEX IF NOT EXISTS idx_ad_context_category ON ad_context_signals(ad_category);
    CREATE TABLE IF NOT EXISTS recommendation_config (
      key TEXT PRIMARY KEY, value TEXT NOT NULL, description TEXT,
      updated_by TEXT DEFAULT 'system', updated_at TEXT DEFAULT (datetime('now'))
  
  -- Insert default recency decay lambda
  INSERT OR IGNORE INTO recommendation_config (config_key, config_value, description, updated_by)
  VALUES ('recency_decay_lambda', '0.15', 'Exponential decay rate for interest scores (higher = faster decay)', 'system');
  );
    INSERT OR IGNORE INTO recommendation_config (key, value, description) VALUES
      ('recency_decay_lambda','0.15','He so decay theo ngay'),
      ('read_interest_weight','0.6','Trong so read score'),
      ('focus_interest_weight','1.0','Trong so focus score'),
      ('search_interest_weight','1.8','Trong so search score'),
      ('transition_interest_weight','1.2','Trong so transition score'),
      ('high_intent_weight','2.0','Trong so high intent'),
      ('dwell_min_ms','1500','Nguong dwell toi thieu'),
      ('recommendation_click_bounce_ms','5000','Nguong bounce sau click'),
      ('unsatisfied_rapid_exit_ms','10000','Nguong rapid exit ms');
    CREATE INDEX IF NOT EXISTS idx_be_session ON behavior_events(session_id);
    CREATE INDEX IF NOT EXISTS idx_be_visitor ON behavior_events(visitor_id);
    CREATE INDEX IF NOT EXISTS idx_be_content ON behavior_events(content_id);
    CREATE INDEX IF NOT EXISTS idx_be_event_name ON behavior_events(event_name);
    CREATE INDEX IF NOT EXISTS idx_tis_subject ON topic_interest_signals(subject_id, subject_type);
    CREATE INDEX IF NOT EXISTS idx_tis_tag ON topic_interest_signals(topic_tag);
    CREATE INDEX IF NOT EXISTS idx_cs_content ON content_sections(content_id);
    CREATE INDEX IF NOT EXISTS idx_cr_from ON content_relations(from_content_id);
    CREATE INDEX IF NOT EXISTS idx_sf_content ON section_features(content_id);
    CREATE INDEX IF NOT EXISTS idx_ctf_from ON content_transition_features(from_content_id);
    CREATE INDEX IF NOT EXISTS idx_aal_action ON admin_audit_logs(action_type);
    CREATE INDEX IF NOT EXISTS idx_aal_time ON admin_audit_logs(created_at);
  `);
})();

// ── SIGNAL ENGINE ────────────────────────────────────────────────────────────
function _getDecayLambda() {
  try { var c = db.prepare("SELECT value FROM recommendation_config WHERE key='recency_decay_lambda'").get(); return c ? parseFloat(c.value) : 0.15; } catch(e) { return 0.15; }
}
function _calculateContextMatch(ev, sessionState) {
  var contextScore = 1.0;
  if (!ev.content_id || !sessionState) return contextScore;
  try {
    var currentArt = db.prepare('SELECT tags,category FROM articles WHERE id=? OR slug=?').get(ev.content_id, ev.content_id);
    if (currentArt && currentArt.tags) {
      var currentTags = JSON.parse(currentArt.tags||'[]').map(function(t){return t.toLowerCase();});
      var sessionTopics = db.prepare("SELECT topic_tag FROM topic_interest_signals WHERE subject_id=? AND session_score>0 LIMIT 5").all(sessionState.visitor_id||sessionState.user_id||'');
      if (sessionTopics.length > 0) {
        var matchCount = 0;
        sessionTopics.forEach(function(st) { if (currentTags.includes(st.topic_tag)) matchCount++; });
        contextScore *= (0.8 + (matchCount / Math.max(sessionTopics.length, 1)) * 0.4);
    
    const row = db.prepare(`
      SELECT config_value FROM recommendation_config WHERE config_key = 'recency_decay_lambda'
    `).get();
    return parseFloat(row?.config_value || 0.15);
  }
    }
    if (ev.section_id) {
      var section = db.prepare('SELECT importance_weight FROM content_sections WHERE section_id=?').get(ev.section_id);
      if (section) contextScore *= (section.importance_weight || 1.0);
    }
  } catch(e) {}
  return Math.min(Math.max(contextScore, 0.5), 2.0);
}

function _calculateNoisePenalty(ev) {
  var penalty = 0;
  if ((ev.scroll_percent||0) > 60 && (ev.dwell_ms||0) < 2000) penalty += 0.8;
  if (ev.viewport_type === 'hidden' || (ev.visible_ms||0) === 0) penalty += 1.0;
  return Math.min(penalty, 2.0);
}

function _calculateConfidence(ev, sessionState) {
  var confidence = 1.0;
  if (ev.visible_ms > 0) {
    var activeRatio = (ev.active_ms||0) / Math.max(ev.visible_ms, 1);
    if (activeRatio < 0.3) confidence *= 0.5;
    else if (activeRatio < 0.6) confidence *= 0.8;
  }
  if (sessionState && (sessionState.bounce_flag||0) === 1) confidence *= 0.3;
  if (ev.dwell_ms && ev.dwell_ms < 1500) confidence *= 0.4;
  return Math.min(Math.max(confidence, 0.1), 2.0);
}

function _applyDecay(score, lastAt, lambda) {
  if (!lastAt) return score;
  return score * Math.exp(-(lambda||0.15) * (Date.now() - new Date(lastAt).getTime()) / 86400000);
}
function _upsertContentSignal(contentId, subjectId, sessionId, scores) {
  if (!contentId || !subjectId) return;
  try {
    db.prepare('INSERT OR IGNORE INTO content_signals (content_id, visitor_id, session_id) VALUES (?,?,?)').run(contentId, subjectId, sessionId||'');
    var sets = Object.keys(scores).map(function(k){ return k+'='+k+'+@'+k; });
    sets.push("updated_at=datetime('now')");
    var p = Object.assign({}, scores, {cid:contentId, sid:subjectId, ssid:sessionId||''});
    db.prepare('UPDATE content_signals SET '+sets.join(',')+' WHERE content_id=@cid AND visitor_id=@sid AND session_id=@ssid').run(p);
  } catch(e) {}
}
function _updateTopicInterest(contentId, subjectId, subjectType, score) {
  try {
    var art = db.prepare('SELECT tags FROM articles WHERE id=? OR slug=?').get(contentId, contentId);
    if (!art || !art.tags) return;
    JSON.parse(art.tags||'[]').forEach(function(tag) {
      db.prepare(`INSERT INTO topic_interest_signals (subject_id,subject_type,topic_tag,session_score,interest_score_1d,interest_score_7d,interest_score_30d,last_interaction_at)
        VALUES (@sid,@stype,@tag,@sc,@sc,@sc,@sc,datetime('now'))
        ON CONFLICT(subject_id,subject_type,topic_tag) DO UPDATE SET
          session_score=session_score+@sc, interest_score_1d=interest_score_1d+@sc,
          interest_score_7d=interest_score_7d+@sc, interest_score_30d=interest_score_30d+@sc,
          last_interaction_at=datetime('now')`).run({sid:subjectId,stype:subjectType,tag:tag.toLowerCase(),sc:score});
  
    // Calculate age in days for decay
    const now = Date.now();
    const ageDays = (now - (row.last_interaction_at || now)) / 86400000;
    const lambda = _getDecayLambda();
    
    // Apply recency decay for 7d and 30d scores
    const decayed7d = score * Math.exp(-lambda * Math.min(ageDays, 7));
    const decayed30d = score * Math.exp(-lambda * Math.min(ageDays, 30));
    
    // Update all three time windows
    db.prepare(`
      UPDATE topic_interest_signals
      SET interest_score_1d = interest_score_1d + ?,
          interest_score_7d = interest_score_7d + ?,
          interest_score_30d = interest_score_30d + ?,
          session_score = session_score + ?,
          last_interaction_at = ?
      WHERE subject_id = ? AND subject_type = ?
    `).run(score, decayed7d, decayed30d, score, now, subjectId, subjectType);
  });
  } catch(e) {}
}
function _updateAdSignal(ev) {
  var vid = ev.visitor_id || ev.user_id; if (!vid || !ev.ad_id) return;
  try {
    db.prepare('INSERT INTO ad_signals (visitor_id,ad_id) VALUES (?,?) ON CONFLICT(visitor_id,ad_id) DO NOTHING').run(vid, ev.ad_id);
    var upd = '';
    if (ev.event_name==='ad_impression')          upd='impression_count=impression_count+1';
    if (ev.event_name==='ad_viewable_impression') upd='viewable_count=viewable_count+1';
    if (ev.event_name==='ad_click')               upd='click_count=click_count+1';
    if (ev.event_name==='ad_dismiss')             upd='dismiss_count=dismiss_count+1,negative_score=negative_score+1.0';
    if (ev.event_name==='ad_post_click_bounce')   upd='negative_score=negative_score+1.3';
    if (ev.event_name==='ad_hover')               upd='viewable_count=viewable_count+0.5';
    if (upd) db.prepare('UPDATE ad_signals SET '+upd+",last_seen_at=datetime('now') WHERE visitor_id=? AND ad_id=?").run(vid, ev.ad_id);
    db.prepare("UPDATE ad_signals SET fatigue_score=CASE WHEN impression_count>5 AND click_count=0 THEN impression_count*0.2 ELSE fatigue_score END WHERE visitor_id=? AND ad_id=?").run(vid, ev.ad_id);
  } catch(e) {}
}
function _updateSectionHeat(contentId, sectionId, delta) {
  if (!contentId||!sectionId) return;
  try {
    db.prepare('INSERT OR IGNORE INTO section_features (content_id,section_id) VALUES (?,?)').run(contentId, sectionId);
    db.prepare("UPDATE section_features SET section_heat_score=section_heat_score+?,focus_count_7d=focus_count_7d+1,updated_at=datetime('now') WHERE content_id=? AND section_id=?").run(delta, contentId, sectionId);
  } catch(e) {}
}
function _updateDeepReadMetrics(contentId) {
    // This is called after a content_exit event with scroll_percent
    const exitEvent = db.prepare(`
      SELECT scroll_percent FROM events
      WHERE content_id = ? AND event_name = 'content_exit'
      ORDER BY ts_server DESC LIMIT 1
    `).get(contentId);
    
    if (!exitEvent) return;
    
    const scrollPercent = exitEvent.scroll_percent || 0;
    const isDeepRead = scrollPercent >= 70;
    
    // Update content_features atomically
    db.prepare(`
      UPDATE content_features
      SET total_read_sessions = total_read_sessions + 1,
          deep_read_sessions = deep_read_sessions + ?,
          completion_sum = completion_sum + ?,
          deep_read_rate = CAST(deep_read_sessions + ? AS REAL) / (total_read_sessions + 1),
          avg_completion_rate = (completion_sum + ?) / (total_read_sessions + 1),
          updated_at = ?
      WHERE content_id = ?
    `).run(
      isDeepRead ? 1 : 0,
      scrollPercent,
      isDeepRead ? 1 : 0,
      scrollPercent,
      Date.now(),
      contentId
    );
  }
  } catch(e) {}
}
function _updateSession(ev) {
  if (!ev.session_id) return;
  try {
    db.prepare('INSERT OR IGNORE INTO session_states (session_id,visitor_id,user_id) VALUES (?,?,?)').run(ev.session_id, ev.visitor_id||null, ev.user_id||null);
    var sess = db.prepare('SELECT * FROM session_states WHERE session_id=?').get(ev.session_id);
    var opened = JSON.parse(sess.opened_contents_json||'[]');
    var searches = JSON.parse(sess.recent_searches_json||'[]');
    var transitions = JSON.parse(sess.recent_transitions_json||'[]');
    var upd = {last_seen_at: new Date().toISOString()};
    if (ev.content_id && !opened.includes(ev.content_id)) { opened.push(ev.content_id); upd.opened_contents_json=JSON.stringify(opened.slice(-20)); }
    if (ev.event_name==='content_view') { upd.previous_content_id=sess.current_content_id; upd.current_content_id=ev.content_id; }
    if (ev.event_name==='section_enter') upd.current_section_id=ev.section_id;
    if (ev.event_name==='search_submit' && ev.search_query) { searches.unshift(ev.search_query); upd.recent_searches_json=JSON.stringify(searches.slice(0,10)); upd.search_count=(sess.search_count||0)+1; }
    if (['related_click','recommendation_click','inline_link_click'].includes(ev.event_name)) { transitions.unshift({from:ev.from_content_id,to:ev.to_content_id,ts:Date.now()}); upd.recent_transitions_json=JSON.stringify(transitions.slice(0,10)); upd.transition_count=(sess.transition_count||0)+1; }
    if (['text_copy','share_complete','comment_submit'].includes(ev.event_name)) upd.high_intent_count=(sess.high_intent_count||0)+1;
    var sets = Object.keys(upd).map(function(k){return k+'=@'+k;}).join(',');
    upd.session_id = ev.session_id;
    db.prepare('UPDATE session_states SET '+sets+' WHERE session_id=@session_id').run(upd);
  } catch(e) {}
}
function _processEvent(ev) {
  try {
    db.prepare(`INSERT OR IGNORE INTO behavior_events
      (event_id,event_name,ts_client,visitor_id,session_id,user_id,content_id,section_id,
       scroll_percent,active_ms,idle_ms,visible_ms,dwell_ms,reread_count,search_query,
       ad_id,ad_slot_id,media_id,transition_source,from_content_id,to_content_id,
       copied_text_length,comment_length,share_channel,page_url,viewport_type,referrer_type,payload_json)
      VALUES (@eid,@en,@tc,@vid,@sid,@uid,@cid,@secid,@sp,@am,@im,@vm,@dm,@rc,@sq,
              @adid,@asid,@mid,@ts,@fid,@tid,@ctl,@cl,@sc,@pu,@vt,@rt,@pj)`).run({
      eid:ev.event_id||null,en:ev.event_name,tc:ev.ts_client||null,vid:ev.visitor_id||null,
      sid:ev.session_id||null,uid:ev.user_id||null,cid:ev.content_id||null,secid:ev.section_id||null,
      sp:ev.scroll_percent||0,am:ev.active_ms||0,im:ev.idle_ms||0,vm:ev.visible_ms||0,
      dm:ev.dwell_ms||0,rc:ev.reread_count||0,sq:ev.search_query||null,
      adid:ev.ad_id||null,asid:ev.ad_slot_id||null,mid:ev.media_id||null,
      ts:ev.transition_source||null,fid:ev.from_content_id||null,tid:ev.to_content_id||null,
      ctl:ev.copied_text_length||0,cl:ev.comment_length||0,sc:ev.share_channel||null,
      pu:ev.page_url||null,vt:ev.viewport_type||null,rt:ev.referrer_type||null,pj:JSON.stringify(ev)
    });
  } catch(e) {}
  _updateSession(ev);
  var subjectId = ev.user_id||ev.visitor_id;
  var subjectType = ev.user_id?'user':'visitor';
  if (subjectId) {
    if (ev.event_name==='section_dwell' && ev.dwell_ms>=1500) {
      var normDwell=Math.min(ev.dwell_ms/8000,3.0);
      _upsertContentSignal(ev.content_id,subjectId,ev.session_id,{read_score:0.35*Math.min(normDwell/1.5,1.0)});
    }
    var hiScore=0;
    if (ev.event_name==='text_copy') hiScore=1.5;
    if (ev.event_name==='share_complete') hiScore=2.0;
    if (ev.event_name==='comment_submit') hiScore=2.2;
    if (ev.event_name==='search_submit') hiScore=1.8;
    if (hiScore>0 && ev.content_id) { _upsertContentSignal(ev.content_id,subjectId,ev.session_id,{high_intent_score:hiScore}); _updateTopicInterest(ev.content_id,subjectId,subjectType,hiScore); }
    if (ev.event_name==='content_exit') {
      _updateDeepReadMetrics(ev.content_id);
      if (ev.visible_ms>0) _upsertContentSignal(ev.content_id,subjectId,ev.session_id,{completion_rate:ev.active_ms/ev.visible_ms});
      if ((ev.scroll_percent||0)<20) _upsertContentSignal(ev.content_id,subjectId,ev.session_id,{unsatisfied_score:1.2});
    }
    if (ev.event_name==='read_speed_changed' && ev.speed_type==='slow_down' && (ev.scroll_percent||0)>=20 && (ev.scroll_percent||0)<=80 && ev.section_id) _updateSectionHeat(ev.content_id,ev.section_id,0.3);
    if (ev.event_name==='widget_interaction' && ev.section_id) _updateSectionHeat(ev.content_id,ev.section_id,1.5);
    if (ev.event_name==='content_return' && ev.content_id) { try { db.prepare('INSERT OR IGNORE INTO content_signals (content_id,visitor_id,session_id) VALUES (?,?,?)').run(ev.content_id,subjectId,ev.session_id||''); } catch(e) {} }
  // Advanced event handlers
  if (['pause_reading','resume_reading'].includes(ev.event_name) && ev.content_id) {
    try {
      db.prepare('INSERT OR IGNORE INTO content_signals (content_id,visitor_id,session_id) VALUES (?,?,?)').run(ev.content_id,subjectId,ev.session_id||'');
      if (ev.event_name==='pause_reading' && (ev.pause_duration_ms||0)>3000) {
        _upsertContentSignal(ev.content_id,subjectId,ev.session_id,{focus_score:0.2});
      }
    } catch(e) {}
  }
  }
  if (['text_copy','share_complete','comment_submit'].includes(ev.event_name) && ev.section_id) _updateSectionHeat(ev.content_id,ev.section_id,2.0);
  if (ev.ad_id) _updateAdSignal(ev);
  if (ev.from_content_id && ev.to_content_id) {
    try {
      var pcq=0.2;
      if ((ev.post_click_dwell_ms||0)>=12000 && (ev.post_click_scroll_percent||0)>=75) pcq=1.0;
      else if ((ev.post_click_dwell_ms||0)>=8000 && (ev.post_click_scroll_percent||0)>=50) pcq=0.8;
      else if ((ev.post_click_dwell_ms||0)>=3000 && (ev.post_click_scroll_percent||0)>=25) pcq=0.5;
      var ts=1.0+1.2*pcq-((ev.post_click_dwell_ms||0)<3000?0.8:0);
      db.prepare(`INSERT INTO content_transition_features (from_content_id,to_content_id,transition_count_7d,avg_post_click_dwell,transition_strength)
        VALUES (?,?,1,?,?) ON CONFLICT(from_content_id,to_content_id) DO UPDATE SET
        transition_count_7d=transition_count_7d+1,
        avg_post_click_dwell=(avg_post_click_dwell*transition_count_7d+?)/(transition_count_7d+1),
        transition_strength=MAX(transition_strength,?),updated_at=datetime('now')`).run(ev.from_content_id,ev.to_content_id,ev.post_click_dwell_ms||0,ts,ev.post_click_dwell_ms||0,ts);
    } catch(e) {}
  }
  if (ev.visitor_id && !ev.user_id) { try { db.prepare('INSERT OR IGNORE INTO guest_profiles (visitor_id) VALUES (?)').run(ev.visitor_id); } catch(e) {} }
}

// ── RECOMMENDATION ENGINE ────────────────────────────────────────────────────
function _getContentRecommendations(opts) {
  var contentId=opts.contentId, visitorId=opts.visitorId, userId=opts.userId;
  var sectionId=opts.sectionId||null, limit=opts.limit||6;
  var subjectId=userId||visitorId, lambda=_getDecayLambda();
  var art=db.prepare('
    // Get recency decay lambda from config
    const lambda = db.prepare(`
      SELECT config_value FROM recommendation_config WHERE config_key = 'recency_decay_lambda'
    `).get()?.config_value || 0.15;
    
    SELECT tags,category FROM articles WHERE (id=? OR slug=?) AND deleted_at IS NULL').get(contentId,contentId);
  var currentTags=art?JSON.parse(art.tags||'[]').map(function(t){return t.toLowerCase();}):[]; var currentCat=art?art.category:null;
  var sectionHeat=0, sectionKeywords=[];
  if (sectionId) { try { var sf=db.prepare('SELECT section_heat_score FROM section_features WHERE section_id=?').get(sectionId); if(sf) sectionHeat=sf.section_heat_score||0; var cs=db.prepare('SELECT keywords_json FROM content_sections WHERE section_id=?').get(sectionId); if(cs) sectionKeywords=JSON.parse(cs.keywords_json||'[]').map(function(k){return k.toLowerCase();}); } catch(e) {} }
  var transitionMap={};
  try { db.prepare('SELECT to_content_id,transition_strength,return_back_rate FROM content_transition_features WHERE from_content_id=? AND transition_count_7d>=3 AND transition_strength>0').all(contentId).forEach(function(r){transitionMap[r.to_content_id]=r;}); } catch(e) {}
  var relationMap={};
  try { db.prepare('SELECT to_content_id,relation_type,weight FROM content_relations WHERE from_content_id=?').all(contentId).forEach(function(r){relationMap[r.to_content_id]=r;}); } catch(e) {}
  var featuresMap={};
  try { db.prepare('SELECT content_id,deep_read_rate,avg_completion_rate FROM content_features').all().forEach(function(f){featuresMap[f.content_id]=f;}); } catch(e) {}
  var candidates=db.prepare("SELECT id,slug,title,excerpt,thumbnail,category_label,category,date,views,tags,read_time FROM articles WHERE deleted_at IS NULL AND status='published' AND id!=? ORDER BY views DESC,date DESC LIMIT 60").all(contentId);
  function scoreC(c) {
    var cid=String(c.id), cTags=JSON.parse(c.tags||'[]').map(function(t){return t.toLowerCase();}), score=0;
    if (c.category===currentCat) score+=1.0;
    score+=cTags.filter(function(t){return currentTags.includes(t);}).length*0.5;
    var rel=relationMap[cid]; if(rel) score+=rel.weight*0.8;
    if (sectionKeywords.length>0 && cTags.filter(function(t){return sectionKeywords.includes(t);}).length>0) score*=Math.min(1.0+sectionHeat*0.2,1.5);
    var tr=transitionMap[cid]; if(tr){score+=tr.transition_strength*0.3; if(tr.return_back_rate>=0.5) score-=tr.return_back_rate*0.2;}
    var feat=featuresMap[cid]; if(feat){if(feat.deep_read_rate>=0.4) score*=1.15; if(feat.avg_completion_rate<0.2) score*=0.85;}
    return score;
  }
  var scored=candidates.map(function(c){return{c:c,score:scoreC(c)};});
  var highW=Object.keys(relationMap).filter(function(id){return relationMap[id].weight>=1.5;});
  scored.sort(function(a,b){var ah=highW.includes(String(a.c.id))?1:0,bh=highW.includes(String(b.c.id))?1:0; return bh!==ah?bh-ah:b.score-a.score;});
  var related=scored.slice(0,limit).map(function(s){return s.c;});
  var personalized=[];
  if (subjectId) { try {
    var topSigs=db.prepare('SELECT topic_tag,interest_score_7d,interest_score_1d,session_score,last_interaction_at FROM topic_interest_signals WHERE subject_id=? ORDER BY interest_score_7d DESC,session_score DESC LIMIT 5').all(subjectId);
    var topTags=topSigs.map(function(s){return{tag:s.topic_tag,score:_applyDecay(s.interest_score_7d||s.interest_score_7d,s.last_interaction_at,lambda)};}).filter(function(s){return s.score>0;});
    if (topTags.length) {
      var seen=new Set(related.map(function(c){return c.id;}));
      var psc=candidates.filter(function(c){return !seen.has(c.id);}).map(function(c){
        var cTags=JSON.parse(c.tags||'[]').map(function(t){return t.toLowerCase();}), ps=0;
        topTags.forEach(function(ts){if(cTags.includes(ts.tag)) ps+=ts.score;});
        var rel=relationMap[String(c.id)]; if(rel&&rel.relation_type==='followup') ps+=rel.weight;
        return{c:c,score:ps};
      });
      psc.sort(function(a,b){return b.score-a.score;}); personalized=psc.slice(0,limit).map(function(s){return s.c;});
    }
  } catch(e) {} }
  var exploratory=[];
  try {
    var seenAll=new Set(related.map(function(c){return String(c.id);}).concat(personalized.map(function(c){return String(c.id);})));
    Object.keys(relationMap).forEach(function(eid){if(relationMap[eid].relation_type==='explore'&&!seenAll.has(eid)){var ec=candidates.find(function(c){return String(c.id)===eid;});if(ec){exploratory.push(ec);seenAll.add(eid);}}});
    if (exploratory.length<Math.ceil(limit/2)) candidates.filter(function(c){return c.category!==currentCat&&!seenAll.has(String(c.id));}).slice(0,Math.ceil(limit/2)-exploratory.length).forEach(function(c){exploratory.push(c);});
  } catch(e) {}
  
    // Separate exploratory content (explore relations)
    const exploratoryContent = candidates
      .filter(c => c.is_exploratory)
      .slice(0, 5);
    
    const personalizedContent = candidates
      .filter(c => !c.is_exploratory)
      .slice(0, 10);
    
    return {
      section_id: sectionId || null,
      section_context_applied: sectionId ? true : false,
      related_content:related,personalized_content:personalized,exploratory_content:exploratory,meta:{section_id:sectionId,section_heat:sectionHeat},
      exploratory_content: exploratoryContent
    }};
}
// ── SEQUENCE ANALYZER ────────────────────────────────────────────────────────
function _analyzeSequence(sessionId) {
  if (!sessionId) return null;
  try {
    var events = db.prepare("SELECT * FROM behavior_events WHERE session_id=? ORDER BY ts_client ASC LIMIT 200").all(sessionId);
    if (events.length < 2) return null;
    var seqId = 'seq_' + sessionId + '_' + Date.now();
    db.prepare("INSERT OR REPLACE INTO sequence_records (sequence_id,session_id,sequence_type,ordered_events_json,transition_count,search_count) VALUES (?,?,?,?,?,?)").run(seqId, sessionId, 'mixed', JSON.stringify(events.slice(0,50).map(function(e){return{n:e.event_name,t:e.ts_client};})), events.filter(function(e){return ['related_click','recommendation_click'].includes(e.event_name);}).length, events.filter(function(e){return e.event_name==='search_submit';}).length);
    return seqId;
  } catch(e) { return null; }
}

function _getAdRecommendations(opts) {
  var contentId=opts.contentId,visitorId=opts.visitorId,userId=opts.userId,slotId=opts.slotId,limit=opts.limit||3;
  var subjectId=userId||visitorId;
  var art=db.prepare('SELECT tags FROM articles WHERE (id=? OR slug=?) AND deleted_at IS NULL').get(contentId,contentId);
  var contentTags=art?JSON.parse(art.tags||'[]').map(function(t){return t.toLowerCase();}):[]; var interestTags=[];
  if (subjectId) { try { interestTags=db.prepare('SELECT topic_tag FROM topic_interest_signals WHERE subject_id=? ORDER BY session_score DESC,interest_score_1d DESC LIMIT 5').all(subjectId).map(function(r){return r.topic_tag;}); } catch(e) {} }
  var allTags=contentTags.concat(interestTags).slice(0,5);
  var ads=db.prepare("SELECT id,name,platform,target_tags,budget,spent,impressions,clicks,ctr FROM ad_campaigns WHERE status='active' AND (ends_at IS NULL OR ends_at>=date('now')) AND (budget=0 OR spent<budget) ORDER BY ctr DESC LIMIT 20").all();
    
    // Apply recency decay to interest scores
    const now = Date.now();
    interests = interests.map(row => {
      const ageDays = (now - (row.last_interaction_at || now)) / 86400000;
      return {
        ...row,
        interest_score_7d: row.interest_score_7d * Math.exp(-lambda * ageDays),
        interest_score_30d: row.interest_score_30d * Math.exp(-lambda * ageDays),
        // Do NOT decay session_score - it's inherently current
      };
    });
  var scored=ads.map(function(ad){
    var adTags=JSON.parse(ad.target_tags||'[]').map(function(t){return t.toLowerCase();}), match=0;
    allTags.forEach(function(t){if(adTags.includes(t)) match++;});
    var sig=subjectId?db.prepare('SELECT fatigue_score,negative_score FROM ad_signals WHERE visitor_id=? AND ad_id=?').get(subjectId,String(ad.id)):null;
    return{ad:ad,score:match/Math.max(allTags.length,1)-(sig?sig.fatigue_score*0.3+sig.negative_score*0.5:0)};
  });
  scored.sort(function(a,b){return b.score-a.score;});
  return{contextual_ads:scored.slice(0,limit).map(function(s){return s.ad;}),suppressed_ads:scored.filter(function(s){return s.score<0;}).map(function(s){return s.ad.id;}),slot_id:slotId};
}

// ── BEHAVIOR & RECOMMENDATION ROUTES ─────────────────────────────────────────
app.post('/api/events/ingest', enforcePayloadLimit(2*1024*1024), function(req,res) {
  try {
    var events=req.body.events||(req.body.event_name?[req.body]:[]);
    if (!Array.isArray(events)||!events.length) return res_err(res,'No events',400);
    events=events.slice(0,100); var processed=0;
    var tx=db.transaction(function(evts){evts.forEach(function(ev){if(!ev.event_name)return;_processEvent(ev);processed++;});});
    tx(events); res_ok(res,{ok:true,processed:processed});
  } catch(e) { res_err(res,e.message,500); }
});
app.get('/api/recommendations/content', optionalAuth, function(req,res) {
  try {
    var contentId=req.query.content_id||req.query.id; if(!contentId) return res_err(res,'content_id required',400);
    var result=_getContentRecommendations({contentId:contentId,visitorId:req.query.visitor_id||null,userId:req.user?String(req.user.id):null,sessionId:req.query.session_id||null,sectionId:req.query.section_id||null,limit:parseInt(req.query.limit)||6});
    res_ok(res,result);
  } catch(e) { res_err(res,e.message,500); }
});
app.get('/api/recommendations/ads', optionalAuth, function(req,res) {
  try {
    var result=_getAdRecommendations({contentId:req.query.content_id||null,visitorId:req.query.visitor_id||null,userId:req.user?String(req.user.id):null,slotId:req.query.slot_id||null,limit:parseInt(req.query.limit)||3});
    res_ok(res,result);
  } catch(e) { res_err(res,e.message,500); }
});
app.get('/api/page-context', optionalAuth, function(req,res) {
  try {
    var contentId=req.query.content_id||req.query.id; if(!contentId) return res_err(res,'content_id required',400);
    var art=db.prepare('SELECT * FROM articles WHERE (id=? OR slug=?) AND deleted_at IS NULL').get(contentId,contentId);
    if (!art) return res_err(res,'Content not found',404);
    var related=db.prepare("SELECT id,slug,title,excerpt,thumbnail,category_label,date,read_time FROM articles WHERE category=? AND id!=? AND deleted_at IS NULL AND status='published' ORDER BY views DESC LIMIT 5").all(art.category,art.id);
    var recs=_getContentRecommendations({contentId:String(art.id),visitorId:req.query.visitor_id,userId:req.user?String(req.user.id):null,sessionId:req.query.session_id,limit:4});
    var ads=_getAdRecommendations({contentId:String(art.id),visitorId:req.query.visitor_id,userId:req.user?String(req.user.id):null,limit:2});
    res_ok(res,{content:art,related_content:related,recommendations:recs,ads:ads,user_state:req.user?{id:req.user.id,name:req.user.name,role:req.user.role,avatar:req.user.avatar}:null,tracking_config:{visitor_id:req.query.visitor_id,session_id:req.query.session_id,ingest_url:'/api/events/ingest'}});
  } catch(e) { res_err(res,e.message,500); }
});
app.post('/api/guest/merge', requireAuth, function(req,res) {
  try {
    var visitorId=req.body.visitor_id; if(!visitorId) return res_err(res,'visitor_id required',400);
    var userId=String(req.user.id);
    var guestSignals=db.prepare("SELECT * FROM topic_interest_signals WHERE subject_id=? AND subject_type='visitor'").all(visitorId);
    var tx=db.transaction(function(){
      guestSignals.forEach(function(sig){
        db.prepare("INSERT INTO topic_interest_signals (subject_id,subject_type,topic_tag,interest_score_1d,session_score,last_interaction_at) VALUES (@uid,'user',@tag,@s1d,@ss,@lat) ON CONFLICT(subject_id,subject_type,topic_tag) DO UPDATE SET interest_score_1d=interest_score_1d+@s1d,session_score=session_score+@ss,last_interaction_at=@lat").run({uid:userId,tag:sig.topic_tag,s1d:sig.interest_score_1d,ss:sig.session_score,lat:sig.last_interaction_at});
      });
      db.prepare('UPDATE session_states SET user_id=? WHERE visitor_id=? AND user_id IS NULL').run(userId,visitorId);
      db.prepare("INSERT INTO admin_audit_logs (admin_user_id,action_type,target_type,target_id,before_json,after_json) VALUES (0,'guest_merge','visitor',?,?,?)").run(visitorId,JSON.stringify({visitor_id:visitorId}),JSON.stringify({user_id:userId}));
    });
    tx(); res_ok(res,{ok:true,merged_signals:guestSignals.length});
  } catch(e) { res_err(res,e.message,500); }
});
app.get('/api/admin/behavior/signals', requireAdmin, function(req,res) {
  try {
    var limit=parseInt(req.query.limit)||50, tag=req.query.tag||null;
    var signals=tag?db.prepare('SELECT * FROM topic_interest_signals WHERE topic_tag=? ORDER BY interest_score_1d DESC LIMIT ?').all(tag,limit):db.prepare('SELECT * FROM topic_interest_signals ORDER BY interest_score_1d DESC LIMIT ?').all(limit);
    res_ok(res,{signals:signals,total:signals.length});
  } catch(e) { res_err(res,e.message,500); }
});
app.get('/api/admin/behavior/sessions', requireAdmin, function(req,res) {
  try {
    var limit=parseInt(req.query.limit)||50;
    var sessions=db.prepare('SELECT session_id,visitor_id,user_id,current_content_id,search_count,transition_count,high_intent_count,bounce_flag,compare_mode_flag,started_at,last_seen_at FROM session_states ORDER BY last_seen_at DESC LIMIT ?').all(limit);
    res_ok(res,{sessions:sessions,total:sessions.length});
  } catch(e) { res_err(res,e.message,500); }
});
app.get('/api/admin/behavior/events', requireAdmin, function(req,res) {
  try {
    var limit=parseInt(req.query.limit)||100, evtName=req.query.event_name||null;
    var events=evtName?db.prepare('SELECT * FROM behavior_events WHERE event_name=? ORDER BY created_at DESC LIMIT ?').all(evtName,limit):db.prepare('SELECT * FROM behavior_events ORDER BY created_at DESC LIMIT ?').all(limit);
    res_ok(res,{events:events,total:events.length});
  } catch(e) { res_err(res,e.message,500); }
});
app.get('/api/admin/statistics/behavior', requireAdmin, function(req,res) {
  try {
    var limit=parseInt(req.query.limit)||50;
    var hotSections=db.prepare('SELECT sf.*,cs.title as section_title,a.title as content_title FROM section_features sf LEFT JOIN content_sections cs ON sf.section_id=cs.section_id LEFT JOIN articles a ON sf.content_id=CAST(a.id AS TEXT) ORDER BY sf.section_heat_score DESC LIMIT ?').all(limit);
    var contentFeatures=db.prepare('SELECT cf.content_id,cf.deep_read_rate,cf.avg_completion_rate,cf.read_score_7d,cf.high_intent_score_7d,a.title,a.slug FROM content_features cf LEFT JOIN articles a ON cf.content_id=CAST(a.id AS TEXT) ORDER BY cf.read_score_7d DESC LIMIT 50').all();
    var seqSummary=db.prepare("SELECT sequence_type,COUNT(*) as count FROM sequence_records WHERE created_at>datetime('now','-7 days') GROUP BY sequence_type ORDER BY count DESC").all();
    res_ok(res,{hot_sections:hotSections,content_features:contentFeatures,sequence_summary:seqSummary});
  } catch(e) { res_err(res,e.message,500); }
});
app.get('/api/admin/behavior/section-features', requireAdmin, function(req,res) {
  try {
    var limit=parseInt(req.query.limit)||50, contentId=req.query.content_id||null;
    var rows=contentId?db.prepare('SELECT * FROM section_features WHERE content_id=? ORDER BY section_heat_score DESC LIMIT ?').all(contentId,limit):db.prepare('SELECT * FROM section_features ORDER BY section_heat_score DESC LIMIT ?').all(limit);
    res_ok(res,{section_features:rows,total:rows.length});
  } catch(e) { res_err(res,e.message,500); }
});
app.get('/api/admin/recommendation/config', requireAdmin, function(_req,res) {
  try { res_ok(res,{configs:db.prepare('SELECT * FROM recommendation_config ORDER BY key').all()}); } catch(e) { res_err(res,e.message,500); }
});
app.put('/api/admin/recommendation/config', requireAdmin, function(req,res) {
  try {
    var updates=req.body.updates; if(!Array.isArray(updates)||!updates.length) return res_err(res,'updates array required',400);
    var tx=db.transaction(function(){
      updates.forEach(function(u){if(!u.key||u.value===undefined)return;db.prepare("INSERT INTO recommendation_config (key,value,updated_by,updated_at) VALUES (?,?,?,datetime('now')) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_by=excluded.updated_by,updated_at=excluded.updated_at").run(u.key,String(u.value),req.user?String(req.user.id):'admin');});
      db.prepare("INSERT INTO admin_audit_logs (admin_user_id,action_type,target_type,before_json,after_json) VALUES (?,'update_recommendation_config','config','{}',?)").run(req.user?req.user.id:0,JSON.stringify(updates));
    });
    tx(); res_ok(res,{ok:true,updated:updates.length});
  } catch(e) { res_err(res,e.message,500); }
});
app.get('/api/admin/audit-logs', requireAdmin, function(req,res) {
  try {
    var limit=parseInt(req.query.limit)||50, action=req.query.action||null;
    var logs=action?db.prepare('SELECT * FROM admin_audit_logs WHERE action_type=? ORDER BY created_at DESC LIMIT ?').all(action,limit):db.prepare('SELECT * FROM admin_audit_logs ORDER BY created_at DESC LIMIT ?').all(limit);
    res_ok(res,{logs:logs,total:logs.length});
  } catch(e) { res_err(res,e.message,500); }
});
app.get('/api/admin/audit-logs/search', requireAdmin, function(req,res) {
  try {
    var page=Math.max(1,parseInt(req.query.page)||1), limit=Math.min(200,parseInt(req.query.limit)||50), offset=(page-1)*limit;
    var action=req.query.action_type||'', dateFrom=req.query.date_from||'', dateTo=req.query.date_to||'';
    var conds=[], params=[];
    if(action){conds.push('action_type=?');params.push(action);}
    if(dateFrom){conds.push('created_at>=?');params.push(dateFrom);}
    if(dateTo){conds.push('created_at<=?');params.push(dateTo+' 23:59:59');}
    var where=conds.length?'WHERE '+conds.join(' AND '):'';
    var logs=db.prepare('SELECT * FROM admin_audit_logs '+where+' ORDER BY created_at DESC LIMIT ? OFFSET ?').all(...params,limit,offset);
    var total=db.prepare('SELECT COUNT(*) as c FROM admin_audit_logs '+where).get(...params).c;
    res_ok(res,{logs:logs,total:total,page:page,limit:limit});
  } catch(e) { res_err(res,e.message,500); }
});
app.get('/api/admin/analytics/hot-sections', requireAdmin, function(req,res) {
  try {
    var limit = parseInt(req.query.limit) || 20;
    var hotSections = db.prepare("SELECT sf.section_id, sf.content_id, sf.section_heat_score, sf.focus_count_7d, cs.title as section_title, a.title as content_title FROM section_features sf LEFT JOIN content_sections cs ON sf.section_id = cs.section_id LEFT JOIN articles a ON sf.content_id = CAST(a.id AS TEXT) ORDER BY sf.section_heat_score DESC LIMIT ?").all(limit);
    res_ok(res, { hot_sections: hotSections });
  } catch(e) { res_err(res, e.message, 500); }
});

app.get('/api/admin/analytics/content-quality', requireAdmin, function(req,res) {
  try {
    var limit = parseInt(req.query.limit) || 50;
    var contents = db.prepare("SELECT cf.*, a.title, a.slug, a.category FROM content_features cf LEFT JOIN articles a ON cf.content_id = CAST(a.id AS TEXT) WHERE a.deleted_at IS NULL ORDER BY cf.read_score_7d DESC LIMIT ?").all(limit);
    res_ok(res, { contents: contents });
  } catch(e) { res_err(res, e.message, 500); }
});

app.get('/api/admin/analytics/topic-trends', requireAdmin, function(req,res) {
  try {
    var limit = parseInt(req.query.limit) || 30;
    var trends = db.prepare("SELECT topic_tag, SUM(interest_score_7d) as total_interest, SUM(escalation_score) as total_escalation, COUNT(DISTINCT subject_id) as unique_users FROM topic_interest_signals WHERE interest_score_7d > 0 GROUP BY topic_tag ORDER BY total_interest DESC LIMIT ?").all(limit);
    res_ok(res, { trends: trends });
  } catch(e) { res_err(res, e.message, 500); }
});

app.get('/api/admin/analytics/transition-quality', requireAdmin, function(req,res) {
  try {
    var limit = parseInt(req.query.limit) || 30;
    var transitions = db.prepare("SELECT ctf.*, a1.title as from_title, a2.title as to_title FROM content_transition_features ctf LEFT JOIN articles a1 ON ctf.from_content_id = CAST(a1.id AS TEXT) LEFT JOIN articles a2 ON ctf.to_content_id = CAST(a2.id AS TEXT) WHERE ctf.transition_count_7d >= 3 ORDER BY ctf.transition_strength DESC LIMIT ?").all(limit);
    res_ok(res, { transitions: transitions });
  } catch(e) { res_err(res, e.message, 500); }
});

app.get('/api/admin/behavior/guest-profiles', requireAdmin, function(req,res) {
  try {
    var page=Math.max(1,parseInt(req.query.page)||1), limit=Math.min(100,parseInt(req.query.limit)||50), offset=(page-1)*limit;
    var search=req.query.visitor_id||'';
    var where=search?"WHERE visitor_id LIKE ?":"", params=search?[search+'%',limit,offset]:[limit,offset];
    var rows=db.prepare('SELECT * FROM guest_profiles '+where+' ORDER BY created_at DESC LIMIT ? OFFSET ?').all(...params);
    var total=db.prepare('SELECT COUNT(*) as c FROM guest_profiles '+where).get(...(search?[search+'%']:[])).c;
    var activeCount=db.prepare("SELECT COUNT(*) as c FROM guest_profiles WHERE merged_to_user_id IS NULL AND archived=0").get().c;
    var mergedCount=db.prepare("SELECT COUNT(*) as c FROM guest_profiles WHERE merged_to_user_id IS NOT NULL AND updated_at>datetime('now','-7 days')").get().c;
    var archivedCount=db.prepare("SELECT COUNT(*) as c FROM guest_profiles WHERE archived=1").get().c;
    res_ok(res,{profiles:rows,total:total,page:page,limit:limit,summary:{active:activeCount,merged_7d:mergedCount,archived:archivedCount}});
  } catch(e) { res_err(res,e.message,500); }
});
app.get('/api/admin/content/:id/sections', requireAdmin, function(req,res) {
  try { res_ok(res,{sections:db.prepare('SELECT * FROM content_sections WHERE content_id=? ORDER BY section_order ASC').all(req.params.id)}); } catch(e) { res_err(res,e.message,500); }
});
app.post('/api/admin/content/:id/sections', requireAdmin, function(req,res) {
  try {
    var b=req.body, contentId=req.params.id;
    if(!b.section_id) return res_err(res,'section_id required',400);
    if(b.start_percent<0||b.start_percent>100||b.end_percent<0||b.end_percent>100) return res_err(res,'start_percent/end_percent must be 0-100',400);
    if(b.start_percent>=b.end_percent) return res_err(res,'start_percent must be < end_percent',400);
    var existing=db.prepare('SELECT content_id FROM content_sections WHERE section_id=?').get(b.section_id);
    if(existing&&existing.content_id!==contentId) return res_err(res,'section_id already exists for another content',409);
    db.prepare("INSERT OR REPLACE INTO content_sections (section_id,content_id,section_order,section_type,title,start_percent,end_percent,keywords_json,importance_weight,is_problem_statement,is_solution_statement,is_question_block,is_transition_trigger) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)").run(b.section_id,contentId,b.section_order||0,b.section_type||'text',b.title||null,b.start_percent||0,b.end_percent||100,JSON.stringify(b.keywords_json||[]),b.importance_weight||1.0,b.is_problem_statement?1:0,b.is_solution_statement?1:0,b.is_question_block?1:0,b.is_transition_trigger?1:0);
    db.prepare("INSERT INTO admin_audit_logs (admin_user_id,action_type,target_type,target_id,after_json) VALUES (?,'content_section_create','content_section',?,?)").run(req.user.id,'content_section',b.section_id,JSON.stringify(b));
    res_ok(res,{ok:true,section_id:b.section_id});
  } catch(e) { res_err(res,e.message,500); }
});
app.put('/api/admin/content/:id/sections/:sectionId', requireAdmin, function(req,res) {
  try {
    var b=req.body;
    if(b.start_percent!==undefined&&b.end_percent!==undefined&&b.start_percent>=b.end_percent) return res_err(res,'start_percent must be < end_percent',400);
    var before=db.prepare('SELECT * FROM content_sections WHERE section_id=? AND content_id=?').get(req.params.sectionId,req.params.id);
    if(!before) return res_err(res,'Section not found',404);
    db.prepare("UPDATE content_sections SET section_order=?,section_type=?,title=?,start_percent=?,end_percent=?,keywords_json=?,importance_weight=?,is_problem_statement=?,is_solution_statement=?,is_question_block=?,is_transition_trigger=? WHERE section_id=? AND content_id=?").run(b.section_order??before.section_order,b.section_type??before.section_type,b.title??before.title,b.start_percent??before.start_percent,b.end_percent??before.end_percent,b.keywords_json?JSON.stringify(b.keywords_json):before.keywords_json,b.importance_weight??before.importance_weight,b.is_problem_statement!==undefined?(b.is_problem_statement?1:0):before.is_problem_statement,b.is_solution_statement!==undefined?(b.is_solution_statement?1:0):before.is_solution_statement,b.is_question_block!==undefined?(b.is_question_block?1:0):before.is_question_block,b.is_transition_trigger!==undefined?(b.is_transition_trigger?1:0):before.is_transition_trigger,req.params.sectionId,req.params.id);
    db.prepare("INSERT INTO admin_audit_logs (admin_user_id,action_type,target_type,target_id,before_json,after_json) VALUES (?,'content_section_update','content_section',?,?,?)").run(req.user.id,req.params.sectionId,JSON.stringify(before),JSON.stringify(b));
    res_ok(res,{ok:true});
  } catch(e) { res_err(res,e.message,500); }
});
app.delete('/api/admin/content/:id/sections/:sectionId', requireAdmin, function(req,res) {
  try {
    var before=db.prepare('SELECT * FROM content_sections WHERE section_id=? AND content_id=?').get(req.params.sectionId,req.params.id);
    if(!before) return res_err(res,'Section not found',404);
    db.prepare('DELETE FROM content_sections WHERE section_id=? AND content_id=?').run(req.params.sectionId,req.params.id);
    db.prepare("INSERT INTO admin_audit_logs (admin_user_id,action_type,target_type,target_id,before_json) VALUES (?,'content_section_delete','content_section',?,?)").run(req.user.id,req.params.sectionId,JSON.stringify(before));
    res_ok(res,{ok:true});
  } catch(e) { res_err(res,e.message,500); }
});
app.get('/api/content/:id/sections', function(req,res) {
  try {
    var art=db.prepare("SELECT id FROM articles WHERE (id=? OR slug=?) AND status='published' AND deleted_at IS NULL").get(req.params.id,req.params.id);
    if(!art) return res_err(res,'Content not found',404);
    res_ok(res,{sections:db.prepare('SELECT section_id,section_order,section_type,title,start_percent,end_percent,importance_weight FROM content_sections WHERE content_id=? ORDER BY section_order ASC').all(String(art.id))});
  } catch(e) { res_err(res,e.message,500); }
});
app.get('/api/admin/content/:id/relations', requireAdmin, function(req,res) {
  try { res_ok(res,{relations:db.prepare('SELECT cr.*,a.title as to_title FROM content_relations cr LEFT JOIN articles a ON cr.to_content_id=CAST(a.id AS TEXT) WHERE cr.from_content_id=? ORDER BY cr.weight DESC').all(req.params.id)}); } catch(e) { res_err(res,e.message,500); }
});
app.post('/api/admin/content/:id/relations', requireAdmin, function(req,res) {
  try {
    var b=req.body, fromId=req.params.id;
    if(!b.to_content_id) return res_err(res,'to_content_id required',400);
    if(b.to_content_id===fromId) return res_err(res,'Cannot relate content to itself',400);
    var target=db.prepare('SELECT id FROM articles WHERE id=? OR slug=?').get(b.to_content_id,b.to_content_id);
    if(!target) return res_err(res,'to_content_id not found',400);
    var dup=db.prepare('SELECT relation_id FROM content_relations WHERE from_content_id=? AND to_content_id=?').get(fromId,b.to_content_id);
    if(dup) return res_err(res,'Relation already exists',409);
    var validTypes=['related','followup','manual','explore'];
    var info=db.prepare("INSERT INTO content_relations (from_content_id,to_content_id,relation_type,weight,source) VALUES (?,?,?,?,?)").run(fromId,b.to_content_id,validTypes.includes(b.relation_type)?b.relation_type:'related',Math.min(Math.max(parseFloat(b.weight)||1.0,0),2.0),b.source||'manual');
    db.prepare("INSERT INTO admin_audit_logs (admin_user_id,action_type,target_type,target_id,after_json) VALUES (?,'content_relation_create','content_relation',?,?)").run(req.user.id,String(info.lastInsertRowid),JSON.stringify(b));
    res_ok(res,{ok:true,relation_id:info.lastInsertRowid});
  } catch(e) { res_err(res,e.message,500); }
});
app.put('/api/admin/content/:id/relations/:relationId', requireAdmin, function(req,res) {
  try {
    var b=req.body, before=db.prepare('SELECT * FROM content_relations WHERE relation_id=? AND from_content_id=?').get(req.params.relationId,req.params.id);
    if(!before) return res_err(res,'Relation not found',404);
    var validTypes=['related','followup','manual','explore'];
    db.prepare('UPDATE content_relations SET relation_type=?,weight=? WHERE relation_id=?').run(b.relation_type&&validTypes.includes(b.relation_type)?b.relation_type:before.relation_type,b.weight!==undefined?Math.min(Math.max(parseFloat(b.weight),0),2.0):before.weight,req.params.relationId);
    db.prepare("INSERT INTO admin_audit_logs (admin_user_id,action_type,target_type,target_id,before_json,after_json) VALUES (?,'content_relation_update','content_relation',?,?,?)").run(req.user.id,req.params.relationId,JSON.stringify(before),JSON.stringify(b));
    res_ok(res,{ok:true});
  } catch(e) { res_err(res,e.message,500); }
});
app.delete('/api/admin/content/:id/relations/:relationId', requireAdmin, function(req,res) {
  try {
    var before=db.prepare('SELECT * FROM content_relations WHERE relation_id=? AND from_content_id=?').get(req.params.relationId,req.params.id);
    if(!before) return res_err(res,'Relation not found',404);
    db.prepare('DELETE FROM content_relations WHERE relation_id=?').run(req.params.relationId);
    db.prepare("INSERT INTO admin_audit_logs (admin_user_id,action_type,target_type,target_id,before_json) VALUES (?,'content_relation_delete','content_relation',?,?)").run(req.user.id,req.params.relationId,JSON.stringify(before));
    res_ok(res,{ok:true});
  } catch(e) { res_err(res,e.message,500); }
});
app.get('/api/admin/websites', requireAdmin, function(_req,res) {
  try { res_ok(res,{websites:db.prepare('SELECT * FROM websites ORDER BY created_at DESC').all()}); } catch(e) { res_err(res,e.message,500); }
});
app.post('/api/admin/websites', requireAdmin, function(req,res) {
  try {
    var b=req.body;
    if(!b.name||!b.domain) return res_err(res,'name and domain required',400);
    if(!/^[a-zA-Z0-9][a-zA-Z0-9\-\.]+[a-zA-Z0-9]$/.test(b.domain)) return res_err(res,'Invalid domain format',400);
    var dup=db.prepare("SELECT website_id FROM websites WHERE domain=? AND status='active'").get(b.domain);
    if(dup) return res_err(res,'Domain already exists',409);
    var validTypes=['main','subsite'];
    var info=db.prepare("INSERT INTO websites (name,type,domain,status,default_topic_scope,updated_at) VALUES (?,?,?,?,?,datetime('now'))").run(b.name,validTypes.includes(b.type)?b.type:'main',b.domain,b.status==='inactive'?'inactive':'active',JSON.stringify(b.default_topic_scope||[]));
    db.prepare("INSERT INTO admin_audit_logs (admin_user_id,action_type,target_type,target_id,after_json) VALUES (?,'website_create','website',?,?)").run(req.user.id,String(info.lastInsertRowid),JSON.stringify(b));
    res_ok(res,{ok:true,website_id:info.lastInsertRowid});
  } catch(e) { res_err(res,e.message,500); }
});
app.put('/api/admin/websites/:id', requireAdmin, function(req,res) {
  try {
    var b=req.body, before=db.prepare('SELECT * FROM websites WHERE website_id=?').get(req.params.id);
    if(!before) return res_err(res,'Website not found',404);
    db.prepare("UPDATE websites SET name=?,type=?,domain=?,status=?,default_topic_scope=?,updated_at=datetime('now') WHERE website_id=?").run(b.name??before.name,b.type??before.type,b.domain??before.domain,b.status??before.status,b.default_topic_scope?JSON.stringify(b.default_topic_scope):before.default_topic_scope,req.params.id);
    db.prepare("INSERT INTO admin_audit_logs (admin_user_id,action_type,target_type,target_id,before_json,after_json) VALUES (?,'website_update','website',?,?,?)").run(req.user.id,req.params.id,JSON.stringify(before),JSON.stringify(b));
    res_ok(res,{ok:true});
  } catch(e) { res_err(res,e.message,500); }
});
app.delete('/api/admin/websites/:id', requireAdmin, function(req,res) {
  try {
    var before=db.prepare('SELECT * FROM websites WHERE website_id=?').get(req.params.id);
    if(!before) return res_err(res,'Website not found',404);
    db.prepare("UPDATE websites SET status='inactive',updated_at=datetime('now') WHERE website_id=?").run(req.params.id);
    db.prepare("INSERT INTO admin_audit_logs (admin_user_id,action_type,target_type,target_id,before_json) VALUES (?,'website_delete','website',?,?)").run(req.user.id,req.params.id,JSON.stringify(before));
    res_ok(res,{ok:true});
  } catch(e) { res_err(res,e.message,500); }
});
app.post('/api/guest/init', function(req,res) {
  try {
    var visitorId=req.body.visitor_id; if(!visitorId) return res_err(res,'visitor_id required',400);
    db.prepare('INSERT OR IGNORE INTO guest_profiles (visitor_id) VALUES (?)').run(visitorId);
    res_ok(res,{profile:db.prepare('SELECT * FROM guest_profiles WHERE visitor_id=?').get(visitorId)});
  } catch(e) { res_err(res,e.message,500); }
});
app.get('/api/guest/:visitor_id', function(req,res) {
  try {
    var profile=db.prepare('SELECT * FROM guest_profiles WHERE visitor_id=?').get(req.params.visitor_id);
    if(!profile) return res_err(res,'Guest not found',404);
    res_ok(res,{profile:profile});
  } catch(e) { res_err(res,e.message,500); }
});


// ============================================================
// 404 & GRACEFUL SHUTDOWN
// ============================================================

app.use(function(_req, res) { res_err(res, 'Route không tồn tại', 404); });

var server = app.listen(PORT, function() {
  var c = db.prepare('SELECT COUNT(*) as c FROM articles WHERE deleted_at IS NULL').get().c;
  console.log('TechPulse API  -> http://localhost:' + PORT);
  console.log('SQLite DB      -> ' + DB_PATH);
  console.log('Bai viet       -> ' + c);
  console.log('JWT expires    -> ' + JWT_EXPIRES);
  // Auto-ping de Render free tier khong bi sleep (ping moi 14 phut)
  var SELF_URL = (process.env.RENDER_EXTERNAL_URL || 'https://websitetechloky.onrender.com');
  setInterval(function() {
    https.get(SELF_URL + '/health', function(r) {
      console.log('[ping] ' + r.statusCode);
    }).on('error', function() {});
  }, 14 * 60 * 1000);
});

function shutdown() {
  console.log('[shutdown] Dong ket noi...');
  server.close(function() {
    db.close();
    console.log('[shutdown] Done.');
    process.exit(0);
  });
  // Force exit sau 10s neu hang
  setTimeout(function(
// ===== CONTENT SECTIONS CRUD API (Requirement 9) =====

// GET /api/admin/content/:id/sections - List all sections for a content
app.get('/api/admin/content/:id/sections', requireAdmin, (req, res) => {
  try {
    const contentId = req.params.id;
    
    const sections = db.prepare(`
      SELECT section_id, content_id, section_order, section_type, title,
             start_percent, end_percent, keywords_json, importance_weight,
             is_problem_statement, is_solution_statement, is_question_block,
             is_transition_trigger_block, created_at, updated_at
      FROM content_sections
      WHERE content_id = ?
      ORDER BY section_order ASC
    `).all(contentId);
    
    res_ok(res, { sections });
  } catch (err) {
    console.error('Error fetching content sections:', err);
    res_err(res, 'Failed to fetch sections', 500);
  }
});

// POST /api/admin/content/:id/sections - Create a new section
app.post('/api/admin/content/:id/sections', requireAdmin, (req, res) => {
  try {
    const contentId = req.params.id;
    const {
      section_id, section_order, section_type, title,
      start_percent, end_percent, keywords_json, importance_weight,
      is_problem_statement, is_solution_statement, is_question_block,
      is_transition_trigger_block
    } = req.body;
    
    // Validation
    if (!section_id || section_order === undefined) {
      return res_err(res, 'section_id and section_order are required', 400);
    }
    
    if (start_percent < 0 || start_percent > 100 || end_percent < 0 || end_percent > 100) {
      return res_err(res, 'start_percent and end_percent must be between 0 and 100', 400);
    }
    
    if (start_percent >= end_percent) {
      return res_err(res, 'start_percent must be less than end_percent', 400);
    }
    
    // Check if section_id already exists for a different content
    const existing = db.prepare(`
      SELECT content_id FROM content_sections WHERE section_id = ?
    `).get(section_id);
    
    if (existing && existing.content_id !== contentId) {
      return res_err(res, 'section_id already exists for a different content', 409);
    }
    
    // Insert section
    db.prepare(`
      INSERT INTO content_sections (
        section_id, content_id, section_order, section_type, title,
        start_percent, end_percent, keywords_json, importance_weight,
        is_problem_statement, is_solution_statement, is_question_block,
        is_transition_trigger_block, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      section_id, contentId, section_order, section_type || 'body', title || '',
      start_percent || 0, end_percent || 100, keywords_json || '[]',
      importance_weight || 1.0,
      b(is_problem_statement, 0), b(is_solution_statement, 0),
      b(is_question_block, 0), b(is_transition_trigger_block, 0),
      Date.now(), Date.now()
    );
    
    res_ok(res, { message: 'Section created', section_id });
  } catch (err) {
    console.error('Error creating section:', err);
    res_err(res, 'Failed to create section', 500);
  }
});

// PUT /api/admin/content/:id/sections/:sectionId - Update a section
app.put('/api/admin/content/:id/sections/:sectionId', requireAdmin, (req, res) => {
  try {
    const contentId = req.params.id;
    const sectionId = req.params.sectionId;
    const {
      section_order, section_type, title, start_percent, end_percent,
      keywords_json, importance_weight, is_problem_statement,
      is_solution_statement, is_question_block, is_transition_trigger_block
    } = req.body;
    
    // Validation
    if (start_percent !== undefined && end_percent !== undefined) {
      if (start_percent < 0 || start_percent > 100 || end_percent < 0 || end_percent > 100) {
        return res_err(res, 'start_percent and end_percent must be between 0 and 100', 400);
      }
      if (start_percent >= end_percent) {
        return res_err(res, 'start_percent must be less than end_percent', 400);
      }
    }
    
    // Update section
    db.prepare(`
      UPDATE content_sections
      SET section_order = COALESCE(?, section_order),
          section_type = COALESCE(?, section_type),
          title = COALESCE(?, title),
          start_percent = COALESCE(?, start_percent),
          end_percent = COALESCE(?, end_percent),
          keywords_json = COALESCE(?, keywords_json),
          importance_weight = COALESCE(?, importance_weight),
          is_problem_statement = COALESCE(?, is_problem_statement),
          is_solution_statement = COALESCE(?, is_solution_statement),
          is_question_block = COALESCE(?, is_question_block),
          is_transition_trigger_block = COALESCE(?, is_transition_trigger_block),
          updated_at = ?
      WHERE section_id = ? AND content_id = ?
    `).run(
      section_order, section_type, title, start_percent, end_percent,
      keywords_json, importance_weight,
      is_problem_statement !== undefined ? b(is_problem_statement, 0) : null,
      is_solution_statement !== undefined ? b(is_solution_statement, 0) : null,
      is_question_block !== undefined ? b(is_question_block, 0) : null,
      is_transition_trigger_block !== undefined ? b(is_transition_trigger_block, 0) : null,
      Date.now(), sectionId, contentId
    );
    
    res_ok(res, { message: 'Section updated' });
  } catch (err) {
    console.error('Error updating section:', err);
    res_err(res, 'Failed to update section', 500);
  }
});

// DELETE /api/admin/content/:id/sections/:sectionId - Delete a section
app.delete('/api/admin/content/:id/sections/:sectionId', requireAdmin, (req, res) => {
  try {
    const contentId = req.params.id;
    const sectionId = req.params.sectionId;
    
    db.prepare(`
      DELETE FROM content_sections
      WHERE section_id = ? AND content_id = ?
    `).run(sectionId, contentId);
    
    res_ok(res, { message: 'Section deleted' });
  } catch (err) {
    console.error('Error deleting section:', err);
    res_err(res, 'Failed to delete section', 500);
  }
});

// ===== CONTENT RELATIONS CRUD API (Requirement 10) =====

// GET /api/admin/content/:id/relations - List all relations for a content
app.get('/api/admin/content/:id/relations', requireAdmin, (req, res) => {
  try {
    const contentId = req.params.id;
    
    const relations = db.prepare(`
      SELECT cr.id, cr.from_content_id, cr.to_content_id, cr.relation_type,
             cr.weight, cr.source, cr.created_at, cr.updated_at,
             a.title as target_title
      FROM content_relations cr
      LEFT JOIN articles a ON a.id = cr.to_content_id
      WHERE cr.from_content_id = ?
      ORDER BY cr.weight DESC, cr.created_at DESC
    `).all(contentId);
    
    res_ok(res, { relations });
  } catch (err) {
    console.error('Error fetching content relations:', err);
    res_err(res, 'Failed to fetch relations', 500);
  }
});

// POST /api/admin/content/:id/relations - Create a new relation
app.post('/api/admin/content/:id/relations', requireAdmin, (req, res) => {
  try {
    const fromContentId = req.params.id;
    const { to_content_id, relation_type, weight, source } = req.body;
    
    // Validation
    if (!to_content_id || !relation_type) {
      return res_err(res, 'to_content_id and relation_type are required', 400);
    }
    
    if (to_content_id === fromContentId) {
      return res_err(res, 'Cannot create relation to the same content', 400);
    }
    
    // Check if to_content_id exists
    const targetExists = db.prepare(`
      SELECT id FROM articles WHERE id = ?
    `).get(to_content_id);
    
    if (!targetExists) {
      return res_err(res, 'Target content does not exist', 404);
    }
    
    // Check for duplicate relation
    const duplicate = db.prepare(`
      SELECT id FROM content_relations
      WHERE from_content_id = ? AND to_content_id = ?
    `).get(fromContentId, to_content_id);
    
    if (duplicate) {
      return res_err(res, 'Relation already exists', 409);
    }
    
    // Validate relation_type
    const validTypes = ['related', 'followup', 'manual', 'explore'];
    if (!validTypes.includes(relation_type)) {
      return res_err(res, `relation_type must be one of: ${validTypes.join(', ')}`, 400);
    }
    
    // Validate weight
    const weightValue = weight !== undefined ? parseFloat(weight) : 1.0;
    if (weightValue < 0 || weightValue > 2.0) {
      return res_err(res, 'weight must be between 0.0 and 2.0', 400);
    }
    
    // Insert relation
    const result = db.prepare(`
      INSERT INTO content_relations (
        from_content_id, to_content_id, relation_type, weight, source, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(
      fromContentId, to_content_id, relation_type, weightValue,
      source || 'manual', Date.now(), Date.now()
    );
    
    // Write to audit log
    db.prepare(`
      INSERT INTO admin_audit_logs (
        admin_user_id, action_type, target_type, target_id, after_json, created_at
      ) VALUES (?, ?, ?, ?, ?, ?)
    `).run(
      req.user.id, 'content_relation_create', 'content_relation', result.lastInsertRowid,
      JSON.stringify({ from_content_id: fromContentId, to_content_id, relation_type, weight: weightValue }),
      Date.now()
    );
    
    res_ok(res, { message: 'Relation created', id: result.lastInsertRowid });
  } catch (err) {
    console.error('Error creating relation:', err);
    res_err(res, 'Failed to create relation', 500);
  }
});

// PUT /api/admin/content/:id/relations/:relationId - Update a relation
app.put('/api/admin/content/:id/relations/:relationId', requireAdmin, (req, res) => {
  try {
    const relationId = req.params.relationId;
    const { relation_type, weight } = req.body;
    
    // Get current relation for audit log
    const before = db.prepare(`
      SELECT * FROM content_relations WHERE id = ?
    `).get(relationId);
    
    if (!before) {
      return res_err(res, 'Relation not found', 404);
    }
    
    // Validate relation_type if provided
    if (relation_type) {
      const validTypes = ['related', 'followup', 'manual', 'explore'];
      if (!validTypes.includes(relation_type)) {
        return res_err(res, `relation_type must be one of: ${validTypes.join(', ')}`, 400);
      }
    }
    
    // Validate weight if provided
    if (weight !== undefined) {
      const weightValue = parseFloat(weight);
      if (weightValue < 0 || weightValue > 2.0) {
        return res_err(res, 'weight must be between 0.0 and 2.0', 400);
      }
    }
    
    // Update relation
    db.prepare(`
      UPDATE content_relations
      SET relation_type = COALESCE(?, relation_type),
          weight = COALESCE(?, weight),
          updated_at = ?
      WHERE id = ?
    `).run(relation_type, weight, Date.now(), relationId);
    
    // Get updated relation for audit log
    const after = db.prepare(`
      SELECT * FROM content_relations WHERE id = ?
    `).get(relationId);
    
    // Write to audit log
    db.prepare(`
      INSERT INTO admin_audit_logs (
        admin_user_id, action_type, target_type, target_id, before_json, after_json, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(
      req.user.id, 'content_relation_update', 'content_relation', relationId,
      JSON.stringify(before), JSON.stringify(after), Date.now()
    );
    
    res_ok(res, { message: 'Relation updated' });
  } catch (err) {
    console.error('Error updating relation:', err);
    res_err(res, 'Failed to update relation', 500);
  }
});

// DELETE /api/admin/content/:id/relations/:relationId - Delete a relation
app.delete('/api/admin/content/:id/relations/:relationId', requireAdmin, (req, res) => {
  try {
    const relationId = req.params.relationId;
    
    // Get relation for audit log
    const relation = db.prepare(`
      SELECT * FROM content_relations WHERE id = ?
    `).get(relationId);
    
    if (!relation) {
      return res_err(res, 'Relation not found', 404);
    }
    
    // Delete relation
    db.prepare(`
      DELETE FROM content_relations WHERE id = ?
    `).run(relationId);
    
    // Write to audit log
    db.prepare(`
      INSERT INTO admin_audit_logs (
        admin_user_id, action_type, target_type, target_id, before_json, created_at
      ) VALUES (?, ?, ?, ?, ?, ?)
    `).run(
      req.user.id, 'content_relation_delete', 'content_relation', relationId,
      JSON.stringify(relation), Date.now()
    );
    
    res_ok(res, { message: 'Relation deleted' });
  } catch (err) {
    console.error('Error deleting relation:', err);
    res_err(res, 'Failed to delete relation', 500);
  }
});

// ===== PUBLIC CONTENT SECTIONS API (Requirement 12) =====

// Simple in-memory cache for section data (5 minute TTL)
const sectionCache = new Map();
const SECTION_CACHE_TTL = 5 * 60 * 1000; // 5 minutes

// GET /api/content/:id/sections - Public endpoint to fetch sections for an article
app.get('/api/content/:id/sections', (req, res) => {
  try {
    const contentId = req.params.id;
    
    // Check cache first
    const cacheKey = `sections:${contentId}`;
    const cached = sectionCache.get(cacheKey);
    if (cached && (Date.now() - cached.timestamp < SECTION_CACHE_TTL)) {
      return res_ok(res, { sections: cached.data, cached: true });
    }
    
    // Check if article exists and is published
    const article = db.prepare(`
      SELECT id, status FROM articles WHERE id = ?
    `).get(contentId);
    
    if (!article) {
      return res_err(res, 'Article not found', 404);
    }
    
    if (article.status !== 'published') {
      return res_err(res, 'Article not found', 404);
    }
    
    // Fetch sections
    const sections = db.prepare(`
      SELECT section_id, section_order, section_type, title,
             start_percent, end_percent, importance_weight
      FROM content_sections
      WHERE content_id = ?
      ORDER BY section_order ASC
    `).all(contentId);
    
    // Cache the result
    sectionCache.set(cacheKey, {
      data: sections,
      timestamp: Date.now()
    });
    
    res_ok(res, { sections, cached: false });
  } catch (err) {
    console.error('Error fetching public sections:', err);
    res_err(res, 'Failed to fetch sections', 500);
  }
});

// Clear section cache periodically (every 10 minutes)
setInterval(() => {
  const now = Date.now();
  for (const [key, value] of sectionCache.entries()) {
    if (now - value.timestamp > SECTION_CACHE_TTL) {
      sectionCache.delete(key);
    }
  }
}, 10 * 60 * 1000);

// ===== RECOMMENDATION CONFIG API (Requirement 6) =====

// GET /api/admin/recommendation/config - List all config keys
app.get('/api/admin/recommendation/config', requireAdmin, (req, res) => {
  try {
    const configs = db.prepare(`
      SELECT config_key, config_value, description, updated_by, updated_at
      FROM recommendation_config
      ORDER BY config_key ASC
    `).all();
    
    res_ok(res, { configs });
  } catch (err) {
    console.error('Error fetching recommendation config:', err);
    res_err(res, 'Failed to fetch config', 500);
  }
});

// PUT /api/admin/recommendation/config - Update config values
app.put('/api/admin/recommendation/config', requireAdmin, (req, res) => {
  try {
    const updates = req.body.updates; // Array of { config_key, config_value }
    
    if (!Array.isArray(updates) || updates.length === 0) {
      return res_err(res, 'updates array is required', 400);
    }
    
    const errors = [];
    const updated = [];
    
    // Validate and update each config
    for (const update of updates) {
      const { config_key, config_value } = update;
      
      if (!config_key || config_value === undefined) {
        errors.push({ config_key, error: 'config_key and config_value are required' });
        continue;
      }
      
      // Validate numeric value
      const numValue = parseFloat(config_value);
      if (isNaN(numValue)) {
        errors.push({ config_key, error: 'config_value must be a valid number' });
        continue;
      }
      
      // Get current value for audit log
      const before = db.prepare(`
        SELECT * FROM recommendation_config WHERE config_key = ?
      `).get(config_key);
      
      if (!before) {
        errors.push({ config_key, error: 'config_key not found' });
        continue;
      }
      
      // Update config
      db.prepare(`
        UPDATE recommendation_config
        SET config_value = ?, updated_by = ?, updated_at = ?
        WHERE config_key = ?
      `).run(config_value, req.user.username || req.user.email, Date.now(), config_key);
      
      // Get updated value for audit log
      const after = db.prepare(`
        SELECT * FROM recommendation_config WHERE config_key = ?
      `).get(config_key);
      
      // Write to audit log
      db.prepare(`
        INSERT INTO admin_audit_logs (
          admin_user_id, action_type, target_type, target_id, before_json, after_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
      `).run(
        req.user.id, 'recommendation_config_update', 'recommendation_config', config_key,
        JSON.stringify(before), JSON.stringify(after), Date.now()
      );
      
      updated.push(config_key);
    }
    
    if (errors.length > 0) {
      return res.status(400).json({
        success: false,
        message: 'Some config updates failed',
        updated,
        errors
      });
    }
    
    res_ok(res, { message: 'Config updated successfully', updated });
  } catch (err) {
    console.error('Error updating recommendation config:', err);
    res_err(res, 'Failed to update config', 500);
  }
});

// ===== ADMIN ANALYTICS APIs (Requirements 5, 7, 8) =====

// GET /api/admin/statistics/behavior - Statistics/Behavior page data (Req 5)
app.get('/api/admin/statistics/behavior', requireAdmin, (req, res) => {
  try {
    // Section heat scores ranked by heat score
    const sectionHeat = db.prepare(`
      SELECT sf.section_id, sf.content_id, sf.section_heat_score,
             cs.title as section_title, cs.section_order
      FROM section_features sf
      LEFT JOIN content_sections cs ON cs.section_id = sf.section_id
      ORDER BY sf.section_heat_score DESC
      LIMIT 50
    `).all();
    
    // Content features table - top 50 articles
    const contentFeatures = db.prepare(`
      SELECT content_id, deep_read_rate, avg_completion_rate,
             read_score_7d, high_intent_score_7d, updated_at
      FROM content_features
      ORDER BY read_score_7d DESC
      LIMIT 50
    `).all();
    
    // Sequences summary - last 7 days
    const sequencesSummary = db.prepare(`
      SELECT sequence_type, COUNT(*) as count
      FROM behavioral_sequences
      WHERE created_at >= datetime('now', '-7 days')
      GROUP BY sequence_type
      ORDER BY count DESC
    `).all();
    
    res_ok(res, {
      section_heat: sectionHeat,
      content_features: contentFeatures,
      sequences_summary: sequencesSummary
    });
  } catch (err) {
    console.error('Error fetching behavior statistics:', err);
    res_err(res, 'Failed to fetch statistics', 500);
  }
});

// GET /api/admin/audit-logs - Audit Logs page data (Req 7)
app.get('/api/admin/audit-logs', requireAdmin, (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 50;
    const offset = (page - 1) * limit;
    
    const actionType = req.query.action_type || null;
    const startDate = req.query.start_date || null;
    const endDate = req.query.end_date || null;
    
    // Build WHERE clause
    let whereClause = '1=1';
    const params = [];
    
    if (actionType) {
      whereClause += ' AND action_type = ?';
      params.push(actionType);
    }
    
    if (startDate) {
      whereClause += ' AND created_at >= ?';
      params.push(new Date(startDate).getTime());
    }
    
    if (endDate) {
      whereClause += ' AND created_at <= ?';
      params.push(new Date(endDate).getTime());
    }
    
    // Get total count
    const total = db.prepare(`
      SELECT COUNT(*) as count FROM admin_audit_logs WHERE ${whereClause}
    `).get(...params).count;
    
    // Get paginated logs
    const logs = db.prepare(`
      SELECT aal.id, aal.admin_user_id, aal.action_type, aal.target_type,
             aal.target_id, aal.before_json, aal.after_json, aal.created_at,
             u.username as admin_username, u.email as admin_email
      FROM admin_audit_logs aal
      LEFT JOIN users u ON u.id = aal.admin_user_id
      WHERE ${whereClause}
      ORDER BY aal.created_at DESC
      LIMIT ? OFFSET ?
    `).all(...params, limit, offset);
    
    res_ok(res, paginateResult(logs, total, page, limit));
  } catch (err) {
    console.error('Error fetching audit logs:', err);
    res_err(res, 'Failed to fetch audit logs', 500);
  }
});

// GET /api/admin/behavior/guest-profiles - Guest Profiles page data (Req 8)
app.get('/api/admin/behavior/guest-profiles', requireAdmin, (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 50;
    const offset = (page - 1) * limit;
    const search = req.query.search || null;
    
    // Build WHERE clause
    let whereClause = '1=1';
    const params = [];
    
    if (search) {
      whereClause += ' AND visitor_id LIKE ?';
      params.push(`${search}%`);
    }
    
    // Get total count
    const total = db.prepare(`
      SELECT COUNT(*) as count FROM guest_profiles WHERE ${whereClause}
    `).get(...params).count;
    
    // Get paginated profiles
    const profiles = db.prepare(`
      SELECT visitor_id, created_at, updated_at, merged_to_user_id,
             temp_interest_json, temp_recommendation_state_json
      FROM guest_profiles
      WHERE ${whereClause}
      ORDER BY updated_at DESC
      LIMIT ? OFFSET ?
    `).all(...params, limit, offset);
    
    // Get summary counts
    const summary = {
      total_active: db.prepare(`
        SELECT COUNT(*) as count FROM guest_profiles WHERE merged_to_user_id IS NULL
      `).get().count,
      merged_7d: db.prepare(`
        SELECT COUNT(*) as count FROM guest_profiles
        WHERE merged_to_user_id IS NOT NULL
        AND updated_at >= datetime('now', '-7 days')
      `).get().count,
      archived: db.prepare(`
        SELECT COUNT(*) as count FROM guest_profiles WHERE merged_to_user_id IS NOT NULL
      `).get().count
    };
    
    res_ok(res, {
      ...paginateResult(profiles, total, page, limit),
      summary
    });
  } catch (err) {
    console.error('Error fetching guest profiles:', err);
    res_err(res, 'Failed to fetch guest profiles', 500);
  }
});

// GET /api/admin/websites - Websites CRUD API (Req 11)
app.get('/api/admin/websites', requireAdmin, (req, res) => {
  try {
    const websites = db.prepare(`
      SELECT website_id, name, type, domain, status, default_topic_scope, created_at
      FROM websites
      ORDER BY created_at DESC
    `).all();
    
    res_ok(res, { websites });
  } catch (err) {
    console.error('Error fetching websites:', err);
    res_err(res, 'Failed to fetch websites', 500);
  }
});

// POST /api/admin/websites - Create website (Req 11)
app.post('/api/admin/websites', requireAdmin, (req, res) => {
  try {
    const { name, type, domain, status, default_topic_scope } = req.body;
    
    // Validation
    if (!name || !domain) {
      return res_err(res, 'name and domain are required', 400);
    }
    
    // Validate domain format (basic check)
    const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?\.[a-zA-Z]{2,}$/;
    if (!domainRegex.test(domain)) {
      return res_err(res, 'Invalid domain format', 400);
    }
    
    // Check for duplicate active domain
    const duplicate = db.prepare(`
      SELECT website_id FROM websites WHERE domain = ? AND status = 'active'
    `).get(domain);
    
    if (duplicate) {
      return res_err(res, 'Domain already exists for an active website', 409);
    }
    
    // Insert website
    const result = db.prepare(`
      INSERT INTO websites (name, type, domain, status, default_topic_scope, created_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(
      name, type || 'main', domain, status || 'active',
      default_topic_scope || '[]', Date.now()
    );
    
    // Write to audit log
    db.prepare(`
      INSERT INTO admin_audit_logs (
        admin_user_id, action_type, target_type, target_id, after_json, created_at
      ) VALUES (?, ?, ?, ?, ?, ?)
    `).run(
      req.user.id, 'website_create', 'website', result.lastInsertRowid,
      JSON.stringify({ name, type, domain, status }), Date.now()
    );
    
    res_ok(res, { message: 'Website created', id: result.lastInsertRowid });
  } catch (err) {
    console.error('Error creating website:', err);
    res_err(res, 'Failed to create website', 500);
  }
});

// PUT /api/admin/websites/:id - Update website (Req 11)
app.put('/api/admin/websites/:id', requireAdmin, (req, res) => {
  try {
    const websiteId = req.params.id;
    const { name, type, domain, status, default_topic_scope } = req.body;
    
    // Get current website for audit log
    const before = db.prepare(`
      SELECT * FROM websites WHERE website_id = ?
    `).get(websiteId);
    
    if (!before) {
      return res_err(res, 'Website not found', 404);
    }
    
    // Update website
    db.prepare(`
      UPDATE websites
      SET name = COALESCE(?, name),
          type = COALESCE(?, type),
          domain = COALESCE(?, domain),
          status = COALESCE(?, status),
          default_topic_scope = COALESCE(?, default_topic_scope)
      WHERE website_id = ?
    `).run(name, type, domain, status, default_topic_scope, websiteId);
    
    // Get updated website for audit log
    const after = db.prepare(`
      SELECT * FROM websites WHERE website_id = ?
    `).get(websiteId);
    
    // Write to audit log
    db.prepare(`
      INSERT INTO admin_audit_logs (
        admin_user_id, action_type, target_type, target_id, before_json, after_json, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(
      req.user.id, 'website_update', 'website', websiteId,
      JSON.stringify(before), JSON.stringify(after), Date.now()
    );
    
    res_ok(res, { message: 'Website updated' });
  } catch (err) {
    console.error('Error updating website:', err);
    res_err(res, 'Failed to update website', 500);
  }
});

// DELETE /api/admin/websites/:id - Soft delete website (Req 11)
app.delete('/api/admin/websites/:id', requireAdmin, (req, res) => {
  try {
    const websiteId = req.params.id;
    
    // Get website for audit log
    const website = db.prepare(`
      SELECT * FROM websites WHERE website_id = ?
    `).get(websiteId);
    
    if (!website) {
      return res_err(res, 'Website not found', 404);
    }
    
    // Soft delete (set status to inactive)
    db.prepare(`
      UPDATE websites SET status = 'inactive' WHERE website_id = ?
    `).run(websiteId);
    
    // Write to audit log
    db.prepare(`
      INSERT INTO admin_audit_logs (
        admin_user_id, action_type, target_type, target_id, before_json, created_at
      ) VALUES (?, ?, ?, ?, ?, ?)
    `).run(
      req.user.id, 'website_delete', 'website', websiteId,
      JSON.stringify(website), Date.now()
    );
    
    res_ok(res, { message: 'Website deactivated' });
  } catch (err) {
    console.error('Error deleting website:', err);
    res_err(res, 'Failed to delete website', 500);
  }
});
) { process.exit(1); }, 10000);
}
process.on('SIGTERM', shutdown);
process.on('SIGINT',  shutdown);
