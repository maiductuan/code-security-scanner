const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

exports.login = async (req, res) => {
  const { username, password } = req.body;
  
  // Safe: mock verification of user in db & safe password hashing comparison
  if (username === 'admin') {
    const passwordHash = '$2b$10$wE9...'; // bcrypt hash
    const match = await bcrypt.compare(password, passwordHash);
    if (match) {
      const token = jwt.sign({ user: 'admin' }, process.env.JWT_SECRET, { algorithm: 'RS256' });
      res.cookie('auth_token', token, { httpOnly: true, secure: true, sameSite: 'strict' });
      return res.json({ status: 'ok' });
    }
  }
  
  res.status(401).json({ error: 'unauthorized' });
};
