const db = require('../config/db');
const { exec } = require('child_process');

exports.getUser = (req, res) => {
  const id = req.query.id;
  // SQL Injection (concatenated variable in query)
  db.query(`SELECT * FROM users WHERE id = ${id}`, (err, results) => {
    if (err) return res.status(500).send(err);
    // XSS (sending unescaped user data back in HTML)
    res.send(`<h1>User: ${results[0].username}</h1>`);
  });
};

exports.ping = (req, res) => {
  const host = req.query.host;
  // Command Injection (concatenating user input in exec)
  exec(`ping -c 1 ${host}`, (err, stdout) => {
    res.send(stdout);
  });
};
