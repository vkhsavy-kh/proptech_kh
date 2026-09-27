PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS roles (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS permissions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  code TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS role_permissions (
  role_id INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  permission_id INTEGER NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
  PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT UNIQUE,
  phone TEXT UNIQUE,
  password_hash TEXT,
  telegram_id TEXT UNIQUE,
  telegram_username TEXT,
  role_id INTEGER NOT NULL REFERENCES roles(id),
  status TEXT NOT NULL DEFAULT 'active',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS owners (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  phone TEXT,
  email TEXT,
  telegram TEXT,
  notes TEXT,
  created_by INTEGER REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS properties (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  description TEXT,
  listing_type TEXT NOT NULL CHECK(listing_type IN ('sale','rent','sale_rent')),
  property_type TEXT NOT NULL,
  sale_price REAL,
  rent_price REAL,
  currency TEXT NOT NULL DEFAULT 'USD',
  bedrooms INTEGER,
  bathrooms INTEGER,
  land_area REAL,
  building_area REAL,
  status TEXT NOT NULL DEFAULT 'draft',
  verification_status TEXT NOT NULL DEFAULT 'unverified',
  province TEXT,
  district TEXT,
  sangkat TEXT,
  village TEXT,
  street TEXT,
  landmark TEXT,
  latitude REAL,
  longitude REAL,
  owner_id INTEGER REFERENCES owners(id),
  agent_id INTEGER REFERENCES users(id),
  created_by INTEGER REFERENCES users(id),
  verified_by INTEGER REFERENCES users(id),
  published_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS property_images (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  property_id INTEGER NOT NULL REFERENCES properties(id) ON DELETE CASCADE,
  object_key TEXT NOT NULL,
  caption TEXT,
  sort_order INTEGER NOT NULL DEFAULT 0,
  is_cover INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS customers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER UNIQUE REFERENCES users(id) ON DELETE SET NULL,
  name TEXT NOT NULL,
  phone TEXT,
  email TEXT,
  telegram TEXT,
  budget_min REAL,
  budget_max REAL,
  preferred_location TEXT,
  preferred_property_type TEXT,
  bedrooms INTEGER,
  notes TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS leads (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  property_id INTEGER REFERENCES properties(id),
  customer_id INTEGER REFERENCES customers(id),
  agent_id INTEGER REFERENCES users(id),
  status TEXT NOT NULL DEFAULT 'new',
  source TEXT DEFAULT 'website',
  notes TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS favorites (
  customer_id INTEGER NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
  property_id INTEGER NOT NULL REFERENCES properties(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY(customer_id, property_id)
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  actor_id INTEGER REFERENCES users(id),
  action TEXT NOT NULL,
  entity_type TEXT NOT NULL,
  entity_id INTEGER,
  metadata TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT
);

INSERT OR IGNORE INTO roles(name) VALUES ('super_admin'),('admin'),('manager'),('agent'),('data_entry'),('customer');

INSERT OR IGNORE INTO permissions(code) VALUES
('property.create'),('property.view'),('property.edit'),('property.delete'),('property.publish'),('property.approve'),
('owner.create'),('owner.view'),('owner.private_view'),('owner.edit'),('owner.delete'),
('customer.create'),('customer.view'),('customer.edit'),
('lead.create'),('lead.view'),('lead.assign'),
('user.manage'),('role.manage'),('report.view'),('audit.view');

INSERT OR IGNORE INTO role_permissions(role_id,permission_id)
SELECT r.id,p.id FROM roles r CROSS JOIN permissions p WHERE r.name='super_admin';

INSERT OR IGNORE INTO role_permissions(role_id,permission_id)
SELECT r.id,p.id FROM roles r JOIN permissions p ON p.code IN ('property.create','property.view','property.edit','property.delete','property.publish','property.approve','owner.create','owner.view','owner.private_view','owner.edit','owner.delete','customer.create','customer.view','customer.edit','lead.create','lead.view','lead.assign','report.view') WHERE r.name='admin';

INSERT OR IGNORE INTO role_permissions(role_id,permission_id)
SELECT r.id,p.id FROM roles r JOIN permissions p ON p.code IN ('property.create','property.view','property.edit','property.approve','owner.create','owner.view','owner.private_view','owner.edit','customer.view','customer.edit','lead.create','lead.view','lead.assign','report.view') WHERE r.name='manager';

INSERT OR IGNORE INTO role_permissions(role_id,permission_id)
SELECT r.id,p.id FROM roles r JOIN permissions p ON p.code IN ('property.create','property.view','property.edit','owner.create','owner.view','owner.private_view','customer.view','lead.create','lead.view') WHERE r.name='agent';

INSERT OR IGNORE INTO role_permissions(role_id,permission_id)
SELECT r.id,p.id FROM roles r JOIN permissions p ON p.code IN ('property.create','property.view','property.edit') WHERE r.name='data_entry';
