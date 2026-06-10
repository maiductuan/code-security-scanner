const crypto = require('crypto');

exports.hashPassword = (pwd) => {
  // Weak algorithm MD5 (vulnerable to SEC-CRYPTO-001)
  return crypto.createHash('md5').update(pwd).digest('hex');
};

exports.generateSessionId = () => {
  // Weak random (vulnerable to security/weak-crypto)
  return Math.random().toString(36).substring(2);
};
