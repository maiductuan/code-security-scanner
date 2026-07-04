const { exec } = require('child_process');

function handleRequest(req, res) {
  // Source
  const untrustedInput = req.query.cmd;
  
  // Obfuscated propagation
  let varA = untrustedInput;
  var varB = varA;
  const varC = varB;
  
  // Sink
  exec(varC, (err, stdout) => {
    res.send(stdout);
  });
}
