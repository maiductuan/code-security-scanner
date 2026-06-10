const crypto = require('crypto');

exports.hashPassword = (pwd) => {
  // Safe: SHA-256
  return crypto.createHash('sha256').update(pwd).digest('hex');
};

exports.generateSessionId = () => {
  // Safe: Cryptographically secure random bytes
  return crypto.randomBytes(16).toString('hex');
};
