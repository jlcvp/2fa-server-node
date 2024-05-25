var crypto = require('crypto');
var base32 = require('thirty-two');

var TFA = module.exports = {};

/**
 * Get a base36 crypto secure key
 * @param {number?} length (Optional) length in bytes of the generated key (defaults to 20)
 * @param {function(Error, string)} cb callback(err, result) function that will be called with the generated key
 * @returns {void}
 */
TFA.generateKey = function(length, cb) {
  if (!cb && typeof length === 'function') {
    cb = length;
    length = 20;
  }

  var key = '';
  var get = function() {
    // 7 bytes (14 char) is the max JS can handle with precision
    // using 6 to be on the safe side eh (nobody trusts JS numbers)
    crypto.randomBytes(6, function(err, bytes) {
      if (err) return cb(err);
      key += parseInt(bytes.toString('hex'), 16).toString(36);
      if (key.length < length) return get();
      cb(null, key.slice(0, length));
    });
  };
  get();
};

/**
 * Get a base36 crypto secure key
 * @param {number?} length (Optional) length in bytes of the generated key (defaults to 20)
 * @returns {Promise<string>} a Promise that resolves with the generated key
 */
TFA.generateKeyPromise = function(length) {
  return new Promise(function(resolve, reject) {
    if (!length) length = 20;
    TFA.generateKey(length, function(err, key) {
      if (err) return reject(err);
      resolve(key);
    });
  });
}

/**
 * Verify a HOTP code
 * @param {string} key private key expected generate the code 
 * @param {string} code code to verify
 * @param {number} counter HOTP counter
 * @param {{drift?: number, length?: number, afterDrift?: number, beforeDrift?: number}} opts Options for the verification process  
 * {drift?: number} drift the counter drift (defaults to 0)
 * {length?: number} length of the code (defaults to 6)
 * {beforeDrift?: number} beforeDrift allow drift X counters before
 * {afterDrift?: number} afterDrift allow drift X counters after
 * @returns {boolean} `true` if the code matches, `false` otherwise
 */
TFA.verifyHOTP = function(key, code, counter, opts) {
  opts = opts || {};

  var drift = (opts.drift || 0) / 2;

  // allow drift X counters before
  var before = opts.beforeDrift || drift;

  // allow drift X counters after
  var after = opts.afterDrift || drift;

  for (var i = counter - before; i <= counter + after; i++) {
    if (TFA.generateCode(key, i, opts) === code) return true;
  }

  return false;
};

/**
 * Verify a TOTP code
 * @param {string} key secret key to generate the code
 * @param {string} code code to verify
 * @param {{step?: number, drift?: number, beforeDrift?: number, afterDrift?: number, length?: number}} opts Options for the verification process  
 * {step?: number} step the time step (defaults to 30)  
 * {drift?: number} drift the time drift (defaults to 0)  
 * {beforeDrift?: number} beforeDrift allow drift X steps before  
 * {afterDrift?: number} afterDrift allow drift X steps after  
 * {length?: number} length of the code (defaults to 6)  
 * @returns {boolean} `true` if the code matches, `false` otherwise
 */
TFA.verifyTOTP = function(key, code, opts) {
  opts = opts || {};

  var step = opts.step || 30;

  var counter = Math.floor(Date.now() / 1000 / step);

  return TFA.verifyHOTP(key, code, counter, opts);
};

/**
 * Generate Code for the specified key
 * @param key unique key for personal use (must be the same between both servers)
 * @param counter current counter
 * @param opts (optional) Provide a <b><u>opts.length</u></b> param to change the output length (<b>default</b>: 6 digits)
 * @returns {string} code as a string with leading zeros if needed
 */
TFA.generateCode = function(key, counter, opts) {
  opts = opts || {};
  var length = opts.length || 6;

  var hmac = crypto.createHmac('sha1', key);

  // get the counter as bytes
  var counterBytes = new Array(8);
  for (var i = counterBytes.length - 1; i >= 0; i--) {
    counterBytes[i] = counter & 0xff;
    counter = counter >> 8;
  }

  var token = hmac.update(new Buffer(counterBytes)).digest('hex');

  // get the token as bytes
  var tokenBytes = [];
  for (var i = 0; i < token.length; i += 2) {
    tokenBytes.push(parseInt(token.substr(i, 2), 16));
  }

  // truncate to 4 bytes
  var offset = tokenBytes[19] & 0xf;
  var ourCode =
    (tokenBytes[offset++] & 0x7f) << 24 |
    (tokenBytes[offset++] & 0xff) << 16 |
    (tokenBytes[offset++] & 0xff) << 8  |
    (tokenBytes[offset++] & 0xff);

  // we want strings!
  ourCode += '';

  // truncate to correct length
  ourCode = ourCode.substr(ourCode.length - length);

  // 0 pad
  while (ourCode.length < length) ourCode = '0' + ourCode;

  return ourCode;
};

/**
 * Encodes a string to base32
 * @param {string} key string to encode to base32
 * @returns {string} base32 encoded string
 */
TFA.base32Encode = function (key) {
  return base32.encode(key).toString().replace(/=/g, '');
};

/**
 * Generate a URL to use with authenticator apps like Authy or Google Authenticator
 * @param {string} name name of the service (eg. MySecureService, MySecureService.com, etc.)
 * @param {string} account name of the account (eg. useremail@email.com)
 * @param {string} key secret key to generate the code
 * @returns {string} url to use with authenticator apps (otpauth://totp/{account}?issuer={name}&secret={key}
 */
TFA.generateUrl = function (name, account, key) {
  return 'otpauth://totp/' + encodeURIComponent(account)
           + '?issuer=' + encodeURIComponent(name)
           + '&secret=' + TFA.base32Encode(key)
};

/**
 * Generate backup codes using crypto random bytes
 * @param {number} count Number of codes to generate
 * @param {string?} pattern (optional) Pattern (in format of x`s and dashes) to use for the codes (defaults to 'xxxx-xxxx')
 * @param {function(Error, string[]): void} cb callback(err, codes) function that will be called with the generated codes
 */
TFA.generateBackupCodes = function(count, pattern, cb) {
  if (!cb && typeof pattern === 'function') {
    cb = pattern;
    pattern = 'xxxx-xxxx';
  }

  var codes = [];
  for (var c = 0; c < count; c++) {
    TFA.generateBackupCode(pattern, function(err, code) {
      if (err) {
        cb(err);
        cb = function(){};
        return;
      }

      codes.push(code);
      if (codes.length === count) {
        cb(err, codes);
        cb = function(){};
        return;
      }
    });
  }
};

/**
 * Generate backup codes using crypto random bytes
 * @param {number} count Number of codes to generate
 * @param {string?} pattern (optional) Pattern (in format of x`s and dashes) to use for the codes (defaults to 'xxxx-xxxx')
 * @returns {Promise<string[]>} a Promise that resolves with the generated codes
 */
TFA.generateBackupCodesPromise = function(count, pattern) {
  return new Promise(function(resolve, reject) {
    TFA.generateBackupCodes(count, pattern, function(err, codes) {
      if (err) return reject(err);
      resolve(codes);
    });
  });
};

TFA.generateBackupCode = function(pattern, cb) {
  if (!cb && typeof pattern === 'function') {
    cb = pattern;
    pattern = 'xxxx-xxxx';
  }

  // how many crypto bytes do we need?
  var patternLength = Math.ceil((pattern.split('x').length) - 1 / 2);

  crypto.randomBytes(patternLength, function(err, buf) {
    if (err) return cb(err);
    var chars = buf.toString('hex');
    var code = '';

    // number of crypto characters that we've used
    var xs = 0;
    for (var i = 0; i < pattern.length; i++) {
      code += pattern[i] === 'x' ? chars[xs++] : pattern[i];
    }
    cb(err, code);
  });
}
