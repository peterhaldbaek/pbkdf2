'use strict';

const crypto = require('crypto');

const pbkdf2 = function (password, salt, iterations, keylen) {
  return crypto.pbkdf2Sync(password, salt, iterations, keylen, 'sha1').toString('hex');
};

module.exports = pbkdf2;
