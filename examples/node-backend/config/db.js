const mysql = require('mysql2');

const connection = mysql.createConnection({
  host: 'localhost',
  user: 'admin',
  password: 'SuperSecretPassword123!',
  database: 'my_app'
});

module.exports = connection;
