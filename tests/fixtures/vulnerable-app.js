// Test fixture: Vulnerable JavaScript code for testing DeepScan
// This file contains INTENTIONAL vulnerabilities for testing purposes

const express = require('express');
const mysql = require('mysql');
const crypto = require('crypto');
const fs = require('fs');
const { exec } = require('child_process');

const app = express();
const db = mysql.createConnection({ host: 'localhost', user: 'root', password: 'admin123' });

// ── SQL Injection ──
app.get('/users', (req, res) => {
  const userId = req.query.id;
  // VULNERABLE: SQL injection via string concatenation
  const query = "SELECT * FROM users WHERE id = '" + userId + "'";
  db.query(query, (err, results) => {
    res.json(results);
  });
});

// ── Command Injection ──
app.get('/ping', (req, res) => {
  const host = req.query.host;
  // VULNERABLE: Command injection
  exec(`ping -c 4 ${host}`, (err, stdout) => {
    res.send(stdout);
  });
});

// ── XSS ──
app.get('/search', (req, res) => {
  const q = req.query.q;
  // VULNERABLE: Reflected XSS
  res.send(`<h1>Search results for: ${q}</h1>`);
});

// ── Hardcoded Secrets ──
const API_KEY = "sk-1234567890abcdef1234567890abcdef";
const AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE";
const GITHUB_TOKEN = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef12";
const DATABASE_URL = "postgresql://admin:password123@db.example.com:5432/mydb";
const jwt_secret = "my-super-secret-jwt-key";

// ── Weak Crypto ──
function hashPassword(password) {
  // VULNERABLE: MD5 is weak
  return crypto.createHash('md5').update(password).digest('hex');
}

function generateToken() {
  // VULNERABLE: Math.random is not cryptographically secure
  return Math.random().toString(36).substring(2);
}

// ── Weak Auth ──
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  // VULNERABLE: Direct password comparison
  if (password === "admin") {
    const token = require('jsonwebtoken').sign({ username }, 'secret', { algorithm: 'none' });
    res.cookie('session', token, { httpOnly: false, secure: false });
    res.json({ token });
  }
});

// ── Path Traversal ──
app.get('/file', (req, res) => {
  const fileName = req.query.name;
  // VULNERABLE: Path traversal
  const filePath = './uploads/' + fileName;
  fs.readFile(filePath, (err, data) => {
    res.send(data);
  });
});

// ── eval() ──
app.post('/calculate', (req, res) => {
  const expression = req.body.expression;
  // VULNERABLE: Code injection via eval
  const result = eval(expression);
  res.json({ result });
});

// ── Empty catch block ──
try {
  riskyOperation();
} catch (err) {
}

// ── Console.log in production ──
console.log("Server starting...");
console.log("Debug: user data =", userData);

// ── Magic numbers ──
function calculateDiscount(price) {
  if (price > 1000) {
    return price * 0.15;
  } else if (price > 500) {
    return price * 0.10;
  }
  return 0;
}

// ── innerHTML XSS ──
function displayMessage(msg) {
  document.getElementById('output').innerHTML = msg;
  document.write(msg);
}

// ── TODO comments ──
// TODO: fix this security issue
// FIXME: remove hardcoded credentials
// HACK: temporary workaround

// ── Long function (intentionally) ──
function processOrder(order) {
  const userId = order.userId;
  const items = order.items;
  const total = items.reduce((sum, item) => sum + item.price, 0);
  const tax = total * 0.1;
  const grandTotal = total + tax;
  const discount = calculateDiscount(grandTotal);
  const finalTotal = grandTotal - discount;
  const paymentMethod = order.payment;
  const billingAddress = order.address;
  const shippingAddress = order.shipping;
  const orderDate = new Date();
  const estimatedDelivery = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
  const orderNumber = generateToken();
  const status = 'pending';
  const notes = order.notes || '';
  const priority = order.priority || 'normal';
  const coupon = order.coupon;
  const referralCode = order.referral;
  const isGift = order.isGift || false;
  const giftMessage = order.giftMessage || '';
  const trackingNumber = null;
  const carrier = null;
  const warehouse = 'default';
  const weight = items.reduce((sum, item) => sum + (item.weight || 0), 0);
  const dimensions = { length: 0, width: 0, height: 0 };
  const insurance = grandTotal > 100;
  const signature = grandTotal > 500;
  // ... continue processing
  return {
    orderNumber, status, finalTotal, estimatedDelivery,
    trackingNumber, carrier, warehouse,
  };
}

// ── SSRF ──
app.get('/fetch-url', (req, res) => {
  // VULNERABLE: SSRF
  axios.get(req.query.url).then(response => {
    res.send(response.data);
  });
});

// ── Unsafe CORS ──
app.use((req, res, next) => {
  // VULNERABLE: CORS wildcard
  res.header('Access-Control-Allow-Origin', '*');
  next();
});

// ── Missing Rate Limiting ──
// VULNERABLE: No rate limiting on login endpoint
app.post('/api/auth/login', (req, res) => {
  res.json({ status: 'ok' });
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
});

