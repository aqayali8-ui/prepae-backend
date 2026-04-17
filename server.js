const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
require('dotenv').config();
const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'prepae-secret';
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
app.use(cors());
app.use(express.json());
app.get('/', (req, res) => res.json({ status: 'PrePae API running', version: '1.0.0' }));
app.get('/health', async (req, res) => {
    try { await pool.query('SELECT 1'); res.json({ status: 'healthy', database: 'connected' }); }
    catch (err) { res.status(500).json({ status: 'unhealthy', error: err.message }); }
});
const auth = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Access denied' });
    try { req.user = jwt.verify(token, JWT_SECRET); next(); }
    catch { res.status(403).json({ error: 'Invalid token' }); }
};
app.post('/api/auth/register', async (req, res) => {
    try {
          const { name, email, password } = req.body;
          const ex = await pool.query('SELECT id FROM users WHERE email=$1', [email]);
          if (ex.rows.length) return res.status(400).json({ error: 'Email already registered' });
          const hash = await bcrypt.hash(password, 12);
          const r = await pool.query('INSERT INTO users (name,email,password,role) VALUES ($1,$2,$3,$4) RETURNING id,name,email,role', [name, email, hash, 'customer']);
          const token = jwt.sign({ id: r.rows[0].id, email: r.rows[0].email, role: r.rows[0].role }, JWT_SECRET, { expiresIn: '7d' });
          res.status(201).json({ token, user: r.rows[0] });
    } catch (err) { res.status(500).json({ error: err.message }); }
});
app.post('/api/auth/login', async (req, res) => {
    try {
          const { email, password } = req.body;
          const r = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
          if (!r.rows.length) return res.status(401).json({ error: 'Invalid credentials' });
          const valid = await bcrypt.compare(password, r.rows[0].password);
          if (!valid) return res.status(401).json({ error: 'Invalid credentials' });
          const token = jwt.sign({ id: r.rows[0].id, email: r.rows[0].email, role: r.rows[0].role }, JWT_SECRET, { expiresIn: '7d' });
          res.json({ token, user: { id: r.rows[0].id, name: r.rows[0].name, email: r.rows[0].email, role: r.rows[0].role } });
    } catch (err) { res.status(500).json({ error: err.message }); }
});
app.get('/api/goals', auth, async (req, res) => {
    try {
          const r = await pool.query('SELECT g.*, COALESCE(SUM(p.amount),0) as paid_amount FROM goals g LEFT JOIN payments p ON p.goal_id=g.id AND p.status=$1 WHERE g.user_id=$2 GROUP BY g.id ORDER BY g.created_at DESC', ['completed', req.user.id]);
          res.json(r.rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});
app.post('/api/goals', auth, async (req, res) => {
    try {
          const { name, description, target_amount } = req.body;
          const r = await pool.query('INSERT INTO goals (user_id,name,description,target_amount,status) VALUES ($1,$2,$3,$4,$5) RETURNING *', [req.user.id, name, description||null, target_amount, 'active']);
          res.status(201).json(r.rows[0]);
    } catch (err) { res.status(500).json({ error: err.message }); }
});
app.get('/api/products', async (req, res) => {
    try {
          const r = await pool.query("SELECT p.*,m.business_name as merchant_name FROM products p LEFT JOIN merchants m ON m.id=p.merchant_id WHERE p.status='active' ORDER BY p.created_at DESC LIMIT 100");
          res.json(r.rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});
app.post('/api/merchants/apply', auth, async (req, res) => {
    try {
          const { business_name, business_type, address, phone, description } = req.body;
          const r = await pool.query('INSERT INTO merchants (user_id,business_name,business_type,address,phone,description,status) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *', [req.user.id, business_name, business_type||null, address||null, phone||null, description||null, 'pending']);
          res.status(201).json(r.rows[0]);
    } catch (err) { res.status(500).json({ error: err.message }); }
});
app.get('/api/admin/stats', auth, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
    try {
          const u = await pool.query("SELECT COUNT(*) FROM users WHERE role='customer'");
          const m = await pool.query("SELECT COUNT(*) FROM merchants WHERE status='approved'");
          const rv = await pool.query("SELECT COALESCE(SUM(amount),0) as total FROM payments WHERE status='completed'");
          res.json({ total_users: parseInt(u.rows[0].count), approved_merchants: parseInt(m.rows[0].count), total_revenue: parseFloat(rv.rows[0].total) });
    } catch (err) { res.status(500).json({ error: err.message }); }
});
app.listen(PORT, () => console.log('PrePae API running on port ' + PORT));
