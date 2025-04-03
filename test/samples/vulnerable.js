// SQL Injection
function getUserData(userId) {
  const query = "SELECT * FROM users WHERE id = '" + userId + "'";
  return db.query(query);
}

// XSS
function displayUserComment(comment) {
  document.getElementById('comments').innerHTML = comment;
}

// Command Injection
function executeCommand(userInput) {
  const { exec } = require('child_process');
  exec('ls ' + userInput, (error, stdout, stderr) => {
    console.log(stdout);
  });
}

// Insecure JWT
function verifyToken(token) {
  const jwt = require('jsonwebtoken');
  return jwt.verify(token, secretKey);  // Missing algorithm specification
}

// Path Traversal
function readUserFile(fileName) {
  const fs = require('fs');
  return fs.readFileSync('./user_files/' + fileName);
}

// Weak Cryptography
function hashPassword(password) {
  const crypto = require('crypto');
  return crypto.createHash('md5').update(password).digest('hex');
}

// Prototype Pollution
function mergeUserData(userData) {
  const target = {};
  function merge(target, source) {
    for (let key in source) {
      target[key] = source[key];
    }
    return target;
  }
  return merge(target, userData);
}

// Insecure Random Values
function generateToken() {
  return 'token_' + Math.random().toString(36).substring(2);
}

// NoSQL Injection
function findUser(username) {
  return db.collection.find({ username: username });
}

// Insecure Deserialization
function processUserData(userData) {
  return eval('(' + userData + ')');
}

// CSRF vulnerability
function setupForm() {
  app.post('/update-profile', (req, res) => {
    // No CSRF token validation
    updateUserProfile(req.body);
    res.redirect('/profile');
  });
}

// SSRF vulnerability
function fetchExternalResource(url) {
  const axios = require('axios');
  return axios.get(url);
} 