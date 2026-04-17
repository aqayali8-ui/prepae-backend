{
  "name": "prepae-backend",
  "version": "1.0.0",
  "description": "PrePae Layaway Platform Backend API",
  "main": "server.js",
  "scripts": {
    "start": "node server.js",
    "dev": "nodemon server.js"
  },
  "dependencies": {
    "bcryptjs": "^2.4.3",
    "cors": "^2.8.5",
    "dotenv": "^16.0.3",
    "express": "^4.18.2",
    "jsonwebtoken": "^9.0.0",
    "multer": "^1.4.5-lts.1",
    "pg": "^8.11.0",
    "stripe": "^12.0.0"
  },
  "devDependencies": {
    "nodemon": "^2.0.22"
  },
  "engines": {
    "node": ">=18.0.0"
  }
}

// PREPAE - BACKEND API SERVER
// Node.js + Express + PostgreSQL + Stripe + JWT

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const { Pool } = require('pg');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Stripe
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

// File upload config
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
});
const upload = multer({ storage, limits: { fileSize: 5 * 1024 * 1024 } });

// Database
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// Middleware
app.use(cors({ origin: process.env.FRONTEND_URL || '*' }));
app.use(express.json());
app.use('/uploads', express.static('uploads'));

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'prepae-secret-change-in-production';

// ==================== AUTH MIDDLEWARE ====================

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access denied' });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
};

const isAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
  next();
};

const isMerchant = (req, res, next) => {
  if (req.user.role !== 'merchant' && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Merchant access required' });
  }
  next();
};

// ==================== HEALTH CHECK ====================

app.get('/', (req, res) => {
  res.json({ status: 'PrePae API running', version: '1.0.0' });
});

app.get('/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ status: 'healthy', database: 'connected' });
  } catch (err) {
    res.status(500).json({ status: 'unhealthy', database: 'disconnected' });
  }
});

// ==================== AUTH ROUTES ====================

// Register customer
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password, phone } = req.body;
    if (!name || !email || !password) {
      return res.status(400).json({ error: 'Name, email, and password are required' });
    }
    const existing = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (existing.rows.length > 0) {
      return res.status(400).json({ error: 'Email already registered' });
    }
    const hashedPassword = await bcrypt.hash(password, 12);
    const result = await pool.query(
      'INSERT INTO users (name, email, password, phone, role) VALUES ($1, $2, $3, $4, $5) RETURNING id, name, email, role',
      [name, email, hashedPassword, phone || null, 'customer']
    );
    const user = result.rows[0];
    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
    res.status(201).json({ token, user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) return res.status(401).json({ error: 'Invalid credentials' });
    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Get current user
app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, name, email, phone, role, balance, created_at FROM users WHERE id = $1',
      [req.user.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Failed to get user' });
  }
});

// ==================== GOALS (LAYAWAY) ROUTES ====================

// Get all goals for user
app.get('/api/goals', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT g.*, 
        COALESCE(SUM(p.amount), 0) as paid_amount,
        COUNT(p.id) as payment_count
       FROM goals g
       LEFT JOIN payments p ON p.goal_id = g.id AND p.status = 'completed'
       WHERE g.user_id = $1
       GROUP BY g.id
       ORDER BY g.created_at DESC`,
      [req.user.id]
    );
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to get goals' });
  }
});

// Create goal
app.post('/api/goals', authenticateToken, async (req, res) => {
  try {
    const { name, description, target_amount, product_id, merchant_id } = req.body;
    if (!name || !target_amount) return res.status(400).json({ error: 'Name and target amount required' });
    const result = await pool.query(
      `INSERT INTO goals (user_id, name, description, target_amount, product_id, merchant_id, status)
       VALUES ($1, $2, $3, $4, $5, $6, 'active') RETURNING *`,
      [req.user.id, name, description || null, target_amount, product_id || null, merchant_id || null]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to create goal' });
  }
});

// Get single goal
app.get('/api/goals/:id', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT g.*, COALESCE(SUM(p.amount), 0) as paid_amount
       FROM goals g
       LEFT JOIN payments p ON p.goal_id = g.id AND p.status = 'completed'
       WHERE g.id = $1 AND g.user_id = $2
       GROUP BY g.id`,
      [req.params.id, req.user.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Goal not found' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Failed to get goal' });
  }
});

// Delete goal
app.delete('/api/goals/:id', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'DELETE FROM goals WHERE id = $1 AND user_id = $2 RETURNING id',
      [req.params.id, req.user.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Goal not found' });
    res.json({ message: 'Goal deleted' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete goal' });
  }
});

// ==================== PAYMENTS ROUTES ====================

// Create Stripe payment intent
app.post('/api/payments/create-intent', authenticateToken, async (req, res) => {
  try {
    const { amount, goal_id } = req.body;
    if (!amount || amount < 1) return res.status(400).json({ error: 'Invalid amount' });
    const intent = await stripe.paymentIntents.create({
      amount: Math.round(amount * 100),
      currency: 'usd',
      metadata: { user_id: req.user.id.toString(), goal_id: goal_id ? goal_id.toString() : '' }
    });
    res.json({ client_secret: intent.client_secret });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to create payment intent' });
  }
});

// Record payment (after Stripe confirms)
app.post('/api/payments/record', authenticateToken, async (req, res) => {
  try {
    const { goal_id, amount, stripe_payment_id } = req.body;
    const result = await pool.query(
      `INSERT INTO payments (user_id, goal_id, amount, stripe_payment_id, status)
       VALUES ($1, $2, $3, $4, 'completed') RETURNING *`,
      [req.user.id, goal_id, amount, stripe_payment_id || null]
    );
    // Check if goal is complete
    const goalCheck = await pool.query(
      `SELECT g.target_amount, COALESCE(SUM(p.amount), 0) as paid
       FROM goals g
       LEFT JOIN payments p ON p.goal_id = g.id AND p.status = 'completed'
       WHERE g.id = $1 GROUP BY g.id`,
      [goal_id]
    );
    if (goalCheck.rows.length > 0) {
      const goal = goalCheck.rows[0];
      if (parseFloat(goal.paid) >= parseFloat(goal.target_amount)) {
        await pool.query("UPDATE goals SET status = 'completed' WHERE id = $1", [goal_id]);
      }
    }
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to record payment' });
  }
});

// Get payment history
app.get('/api/payments', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT p.*, g.name as goal_name
       FROM payments p
       LEFT JOIN goals g ON g.id = p.goal_id
       WHERE p.user_id = $1
       ORDER BY p.created_at DESC
       LIMIT 50`,
      [req.user.id]
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to get payments' });
  }
});

// ==================== PRODUCTS ROUTES ====================

// Get all products (public)
app.get('/api/products', async (req, res) => {
  try {
    const { merchant_id, category, search } = req.query;
    let query = `SELECT p.*, m.business_name as merchant_name
                 FROM products p
                 LEFT JOIN merchants m ON m.id = p.merchant_id
                 WHERE p.status = 'active'`;
    const params = [];
    if (merchant_id) { params.push(merchant_id); query += ` AND p.merchant_id = $${params.length}`; }
    if (category) { params.push(category); query += ` AND p.category = $${params.length}`; }
    if (search) { params.push(`%${search}%`); query += ` AND (p.name ILIKE $${params.length} OR p.description ILIKE $${params.length})`; }
    query += ' ORDER BY p.created_at DESC LIMIT 100';
    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to get products' });
  }
});

// Get single product
app.get('/api/products/:id', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT p.*, m.business_name as merchant_name
       FROM products p LEFT JOIN merchants m ON m.id = p.merchant_id
       WHERE p.id = $1`,
      [req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Product not found' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Failed to get product' });
  }
});

// ==================== MERCHANTS ROUTES ====================

// Apply to become merchant
app.post('/api/merchants/apply', authenticateToken, async (req, res) => {
  try {
    const { business_name, business_type, address, phone, description } = req.body;
    if (!business_name) return res.status(400).json({ error: 'Business name required' });
    const existing = await pool.query('SELECT id FROM merchants WHERE user_id = $1', [req.user.id]);
    if (existing.rows.length > 0) return res.status(400).json({ error: 'Already applied' });
    const result = await pool.query(
      `INSERT INTO merchants (user_id, business_name, business_type, address, phone, description, status)
       VALUES ($1, $2, $3, $4, $5, $6, 'pending') RETURNING *`,
      [req.user.id, business_name, business_type || null, address || null, phone || null, description || null]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Application failed' });
  }
});

// Add product (merchant)
app.post('/api/merchants/products', authenticateToken, isMerchant, upload.single('image'), async (req, res) => {
  try {
    const { name, description, price, category } = req.body;
    const merchant = await pool.query('SELECT id FROM merchants WHERE user_id = $1 AND status = $2', [req.user.id, 'approved']);
    if (merchant.rows.length === 0) return res.status(403).json({ error: 'Merchant not approved' });
    const image_url = req.file ? `/uploads/${req.file.filename}` : null;
    const result = await pool.query(
      `INSERT INTO products (merchant_id, name, description, price, category, image_url, status)
       VALUES ($1, $2, $3, $4, $5, $6, 'active') RETURNING *`,
      [merchant.rows[0].id, name, description || null, price, category || 'general', image_url]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Failed to add product' });
  }
});

// Get merchant dashboard stats
app.get('/api/merchants/stats', authenticateToken, isMerchant, async (req, res) => {
  try {
    const merchant = await pool.query('SELECT * FROM merchants WHERE user_id = $1', [req.user.id]);
    if (merchant.rows.length === 0) return res.status(404).json({ error: 'Merchant not found' });
    const m = merchant.rows[0];
    const products = await pool.query('SELECT COUNT(*) FROM products WHERE merchant_id = $1', [m.id]);
    const goals = await pool.query('SELECT COUNT(*) FROM goals WHERE merchant_id = $1', [m.id]);
    const revenue = await pool.query(
      `SELECT COALESCE(SUM(p.amount), 0) as total
       FROM payments p
       JOIN goals g ON g.id = p.goal_id
       WHERE g.merchant_id = $1 AND p.status = 'completed'`,
      [m.id]
    );
    res.json({
      merchant: m,
      stats: {
        products: parseInt(products.rows[0].count),
        active_goals: parseInt(goals.rows[0].count),
        total_revenue: parseFloat(revenue.rows[0].total)
      }
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to get stats' });
  }
});

// ==================== WISHLIST ROUTES ====================

app.get('/api/wishlist', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT w.*, p.name, p.price, p.image_url
       FROM wishlists w JOIN products p ON p.id = w.product_id
       WHERE w.user_id = $1`,
      [req.user.id]
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to get wishlist' });
  }
});

app.post('/api/wishlist', authenticateToken, async (req, res) => {
  try {
    const { product_id } = req.body;
    await pool.query(
      'INSERT INTO wishlists (user_id, product_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
      [req.user.id, product_id]
    );
    res.status(201).json({ message: 'Added to wishlist' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to add to wishlist' });
  }
});

app.delete('/api/wishlist/:product_id', authenticateToken, async (req, res) => {
  try {
    await pool.query('DELETE FROM wishlists WHERE user_id = $1 AND product_id = $2', [req.user.id, req.params.product_id]);
    res.json({ message: 'Removed from wishlist' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to remove from wishlist' });
  }
});

// ==================== ADMIN ROUTES ====================

// Get platform stats
app.get('/api/admin/stats', authenticateToken, isAdmin, async (req, res) => {
  try {
    const users = await pool.query("SELECT COUNT(*) FROM users WHERE role = 'customer'");
    const merchants = await pool.query("SELECT COUNT(*) FROM merchants WHERE status = 'approved'");
    const pending = await pool.query("SELECT COUNT(*) FROM merchants WHERE status = 'pending'");
    const revenue = await pool.query("SELECT COALESCE(SUM(amount), 0) as total FROM payments WHERE status = 'completed'");
    const goals = await pool.query("SELECT COUNT(*) FROM goals WHERE status = 'active'");
    res.json({
      total_users: parseInt(users.rows[0].count),
      approved_merchants: parseInt(merchants.rows[0].count),
      pending_applications: parseInt(pending.rows[0].count),
      total_revenue: parseFloat(revenue.rows[0].total),
      active_goals: parseInt(goals.rows[0].count)
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to get stats' });
  }
});

// Get pending merchant applications
app.get('/api/admin/merchants/pending', authenticateToken, isAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT m.*, u.name as owner_name, u.email as owner_email
       FROM merchants m JOIN users u ON u.id = m.user_id
       WHERE m.status = 'pending' ORDER BY m.created_at DESC`
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to get applications' });
  }
});

// Approve/reject merchant
app.patch('/api/admin/merchants/:id', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { status } = req.body;
    if (!['approved', 'rejected'].includes(status)) return res.status(400).json({ error: 'Invalid status' });
    const result = await pool.query(
      'UPDATE merchants SET status = $1 WHERE id = $2 RETURNING *',
      [status, req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Merchant not found' });
    if (status === 'approved') {
      await pool.query("UPDATE users SET role = 'merchant' WHERE id = $1", [result.rows[0].user_id]);
    }
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Failed to update merchant' });
  }
});

// Get all users
app.get('/api/admin/users', authenticateToken, isAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, name, email, role, balance, created_at FROM users ORDER BY created_at DESC LIMIT 100'
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to get users' });
  }
});

// ==================== SUPPORT ROUTES ====================

app.post('/api/support', authenticateToken, async (req, res) => {
  try {
    const { subject, message } = req.body;
    const result = await pool.query(
      'INSERT INTO support_tickets (user_id, subject, message, status) VALUES ($1, $2, $3, $4) RETURNING *',
      [req.user.id, subject, message, 'open']
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Failed to create ticket' });
  }
});

// ==================== STRIPE WEBHOOK ====================

app.post('/api/webhooks/stripe', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    return res.status(400).send(`Webhook error: ${err.message}`);
  }
  if (event.type === 'payment_intent.succeeded') {
    const intent = event.data.object;
    const { user_id, goal_id } = intent.metadata;
    if (user_id && goal_id) {
      await pool.query(
        `INSERT INTO payments (user_id, goal_id, amount, stripe_payment_id, status)
         VALUES ($1, $2, $3, $4, 'completed') ON CONFLICT DO NOTHING`,
        [user_id, goal_id, intent.amount / 100, intent.id]
      );
    }
  }
  res.json({ received: true });
});

// ==================== START SERVER ====================

app.listen(PORT, () => {
  console.log(`PrePae API running on port ${PORT}`);
});

module.exports = app;

# PREPAE BACKEND - ENVIRONMENT VARIABLES
# Copy this to .env and fill in your values

# Server
PORT=3000
NODE_ENV=production

# Database (get from Supabase)
DATABASE_URL=postgresql://postgres:[PASSWORD]@[HOST]:5432/postgres

# JWT Secret (make this long and random)
JWT_SECRET=change-this-to-a-long-random-string-in-production

# Stripe (get from stripe.com/dashboard)
STRIPE_SECRET_KEY=sk_live_your_key_here
STRIPE_PUBLISHABLE_KEY=pk_live_your_key_here
STRIPE_WEBHOOK_SECRET=whsec_your_webhook_secret_here

# Frontend URL (your Vercel/Netlify URL)
FRONTEND_URL=https://prepae.vercel.app

-- PREPAE DATABASE SCHEMA
-- Run this on Supabase SQL Editor

-- Users table
CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  email VARCHAR(255) UNIQUE NOT NULL,
  password VARCHAR(255) NOT NULL,
  phone VARCHAR(20),
  role VARCHAR(20) DEFAULT 'customer' CHECK (role IN ('customer', 'merchant', 'admin')),
  balance DECIMAL(10,2) DEFAULT 0.00,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

-- Merchants table
CREATE TABLE IF NOT EXISTS merchants (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  business_name VARCHAR(255) NOT NULL,
  business_type VARCHAR(100),
  address TEXT,
  phone VARCHAR(20),
  description TEXT,
  logo_url VARCHAR(500),
  status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected', 'suspended')),
  subscription_tier VARCHAR(20) DEFAULT 'basic' CHECK (subscription_tier IN ('basic', 'standard', 'premium', 'enterprise')),
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

-- Products table
CREATE TABLE IF NOT EXISTS products (
  id SERIAL PRIMARY KEY,
  merchant_id INTEGER REFERENCES merchants(id) ON DELETE CASCADE,
  name VARCHAR(255) NOT NULL,
  description TEXT,
  price DECIMAL(10,2) NOT NULL,
  category VARCHAR(100) DEFAULT 'general',
  image_url VARCHAR(500),
  status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'deleted')),
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

-- Goals (layaway plans) table
CREATE TABLE IF NOT EXISTS goals (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  product_id INTEGER REFERENCES products(id) ON DELETE SET NULL,
  merchant_id INTEGER REFERENCES merchants(id) ON DELETE SET NULL,
  name VARCHAR(255) NOT NULL,
  description TEXT,
  target_amount DECIMAL(10,2) NOT NULL,
  status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'completed', 'cancelled', 'paused')),
  target_date DATE,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

-- Joint goal participants
CREATE TABLE IF NOT EXISTS joint_goal_participants (
  id SERIAL PRIMARY KEY,
  goal_id INTEGER REFERENCES goals(id) ON DELETE CASCADE,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  role VARCHAR(20) DEFAULT 'participant',
  joined_at TIMESTAMP DEFAULT NOW(),
  UNIQUE(goal_id, user_id)
);

-- Payments table
CREATE TABLE IF NOT EXISTS payments (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  goal_id INTEGER REFERENCES goals(id) ON DELETE SET NULL,
  amount DECIMAL(10,2) NOT NULL,
  stripe_payment_id VARCHAR(255) UNIQUE,
  status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'completed', 'failed', 'refunded')),
  created_at TIMESTAMP DEFAULT NOW()
);

-- Withdrawals table
CREATE TABLE IF NOT EXISTS withdrawals (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  amount DECIMAL(10,2) NOT NULL,
  status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'processing', 'completed', 'failed')),
  bank_account VARCHAR(255),
  created_at TIMESTAMP DEFAULT NOW()
);

-- Orders table
CREATE TABLE IF NOT EXISTS orders (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  goal_id INTEGER REFERENCES goals(id) ON DELETE SET NULL,
  merchant_id INTEGER REFERENCES merchants(id) ON DELETE SET NULL,
  total_amount DECIMAL(10,2) NOT NULL,
  status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'confirmed', 'shipped', 'delivered', 'cancelled')),
  shipping_address TEXT,
  created_at TIMESTAMP DEFAULT NOW()
);

-- Wishlists table
CREATE TABLE IF NOT EXISTS wishlists (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  product_id INTEGER REFERENCES products(id) ON DELETE CASCADE,
  added_at TIMESTAMP DEFAULT NOW(),
  UNIQUE(user_id, product_id)
);

-- Support tickets table
CREATE TABLE IF NOT EXISTS support_tickets (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  subject VARCHAR(255) NOT NULL,
  message TEXT NOT NULL,
  status VARCHAR(20) DEFAULT 'open' CHECK (status IN ('open', 'in_progress', 'resolved', 'closed')),
  response TEXT,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

-- Advertising campaigns table
CREATE TABLE IF NOT EXISTS advertising_campaigns (
  id SERIAL PRIMARY KEY,
  merchant_id INTEGER REFERENCES merchants(id) ON DELETE CASCADE,
  title VARCHAR(255) NOT NULL,
  description TEXT,
  image_url VARCHAR(500),
  tier VARCHAR(20) DEFAULT 'tier1' CHECK (tier IN ('tier1', 'tier2', 'tier3', 'tier4')),
  status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'active', 'paused', 'completed')),
  start_date DATE,
  end_date DATE,
  budget DECIMAL(10,2),
  clicks INTEGER DEFAULT 0,
  impressions INTEGER DEFAULT 0,
  created_at TIMESTAMP DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_goals_user_id ON goals(user_id);
CREATE INDEX IF NOT EXISTS idx_payments_user_id ON payments(user_id);
CREATE INDEX IF NOT EXISTS idx_payments_goal_id ON payments(goal_id);
CREATE INDEX IF NOT EXISTS idx_products_merchant_id ON products(merchant_id);
CREATE INDEX IF NOT EXISTS idx_merchants_user_id ON merchants(user_id);

-- Default admin account (password: admin123 - CHANGE THIS)
INSERT INTO users (name, email, password, role)
VALUES ('Admin', 'admin@prepae.com', '$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/OwKyA1T8cXVGjX7Iq', 'admin')
ON CONFLICT (email) DO NOTHING;

-- Update timestamps trigger
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN NEW.updated_at = NOW(); RETURN NEW; END;
$$ language 'plpgsql';

CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users FOR EACH ROW EXECUTE PROCEDURE update_updated_at();
CREATE TRIGGER update_merchants_updated_at BEFORE UPDATE ON merchants FOR EACH ROW EXECUTE PROCEDURE update_updated_at();
CREATE TRIGGER update_products_updated_at BEFORE UPDATE ON products FOR EACH ROW EXECUTE PROCEDURE update_updated_at();
CREATE TRIGGER update_goals_updated_at BEFORE UPDATE ON goals FOR EACH ROW EXECUTE PROCEDURE update_updated_at();
