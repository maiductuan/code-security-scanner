const jwt = require('jsonwebtoken');

exports.login = (req, res) => {
  const { username, password } = req.body;
  
  // direct password check (vulnerable to SEC-AUTH-001)
  if (username === 'admin' && password === 'admin123') {
    // weak JWT algorithm and secret (vulnerable to SEC-AUTH-004)
    const token = jwt.sign({ user: 'admin' }, 'secret', { algorithm: 'HS256' });
    
    // cookie httpOnly: false (vulnerable to security/weak-auth)
    res.cookie('auth_token', token, { httpOnly: false });
    return res.json({ status: 'ok', token });
  }
  
  res.status(401).json({ error: 'unauthorized' });
};
