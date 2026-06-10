const db = require('../config/db-safe');
const { execFile } = require('child_process');

exports.getUser = (req, res) => {
  const id = req.query.id;
  // Parameterized query (safe SQL)
  db.query('SELECT * FROM users WHERE id = ?', [id], (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    // Safely outputting JSON (safe from XSS)
    res.json(results[0]);
  });
};

exports.ping = (req, res) => {
  const host = req.query.host;
  // Safe: validating input and using execFile with arguments array
  if (/^[a-zA-Z0-9.-]+$/.test(host)) {
    execFile('/bin/ping', ['-c', '1', host], (err, stdout) => {
      res.send(stdout);
    });
  } else {
    res.status(400).send('Invalid host');
  }
};
