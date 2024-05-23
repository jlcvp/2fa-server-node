# 2factor-auth

[![NPM](https://nodei.co/npm/2factor-auth.png?compact=true)](https://nodei.co/npm/2factor-auth/)

Module for generating and verifying 2FA codes (specifically TOTP and HOTP).

Also contains utilities for handling common 2FA business logic, such as generating backup codes and otpauth urls.

## Install
```
npm install --save 2factor-auth
```

## Usage
### with async/await (or promises)
```javascript
const tfa = require('2factor-auth');

function registerUserTwoFactor() {
  // Name of your service (will appear on top of the authenticator app)
  const serviceName = 'Cool service that is 2FA protected';

  // Account name of the user (will also appear in the authenticator app)
  const account = 'myUsername@email.com';

  // generate crypto-secure hex key with 32 characters
  const key = await tfa.generateKeyPromise(32);

  // generate 8 crypto-secure backups codes with in a user-friendly pattern (xxxx-xxxx)
  // [ '7818-b7b8', '3526-d3f2', 'be3c-5d9f', ... ]
  const codes = await tfa.generateBackupCodesPromise(8);

  // generate a URL for the user to open in their 2FA app
  const url = tfa.generateURL(serviceName, account, key);
  // otpauth://totp/...
  
  // send this URL to the user, generate a QR code, etc.

  /** SAVE THE CODES AND KEY IN YOUR BACKEND/DB associated to the user **/
}

function verifyTwoFactorCode(secret_key, receivedCode) {

  // verify the received code without drift
  const valid = tfa.verifyTOTP(secret_key, receivedCode);
  
  // verify the received code with drift (allows for some time difference between the server and the client)
  const validWithDrift = tfa.verifyTOTP(secret_key, receivedCode, {
    beforeDrift: 2,
    afterDrift: 2
  });

  return valid;
}

```



### with Callbacks
```javascript
const tfa = require('2factor-auth');

function registerUserTwoFactor(callback) {
  // Name of your service (will appear on top of the authenticator app)
  const serviceName = 'Cool service that is 2FA protected';

  // Account name of the user (will also appear in the authenticator app)
  const account = 'myUsername@email.com';

  // generate crypto-secure hex key with 32 characters
  tfa.generateKey(32, (err, key) => {
    if (err) {
      callback(err);
      return;
    }

    // generate 8 crypto-secure backups codes with in a user-friendly pattern (xxxx-xxxx)
    // [ '7818-b7b8', '3526-d3f2', 'be3c-5d9f', ... ]
    tfa.generateBackupCodes(8, (err, codes) => {
      if (err) {
        callback(err);
        return;
      }

      // generate a URL for the user to open in their 2FA app
      const url = tfa.generateURL(serviceName, account, key);
      // otpauth://totp/...
      
      // send this URL to the user, generate a QR code, etc.

      /** SAVE THE CODES AND KEY IN YOUR BACKEND/DB associated to the user **/
      callback(null);
    });
  });
}

function verifyTwoFactorCode(secret_key, receivedCode) {
  // verify the received code without drift
  const valid = tfa.verifyTOTP(secret_key, receivedCode);
  
  // verify the received code with drift (allows for some time difference between the server and the client)
  const validWithDrift = tfa.verifyTOTP(secret_key, receivedCode, {
    beforeDrift: 2,
    afterDrift: 2
  });


  return valid;
}
```
