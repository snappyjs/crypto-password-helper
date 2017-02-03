# crypto-password-helper [![NPM version](https://badge.fury.io/js/crypto-password-helper.svg)](https://npmjs.org/package/crypto-password-helper)

> Helper for encrypting and generating password using crypto in node.js. The encryption is made using cryptos pbkdf2 method. Salt, iterations and digest is automatically added to the password hash so no need to save anything but the returned hash.

## Installation
Install via NPM using command:

```sh
$ npm install --save crypto-password-helper
```

## Usage
The hash is always returned via a promise as a string (URL-safe).
Two simple methods are available from the password helper, usage below:
```js
var password = require('crypto-password-helper');

// Using default configuration
password.encrypt(plainPassword).then(hash => {          // using default settings
    console.log(hash);                                  // save hash to user/database
}).catch(err => { throw err; });                        // handle internal server error. (crypto error)

// Using your own configuration
password.encrypt(plainPassword, config).then(hash => {  // using your own configuration
    console.log(hash);
}).catch(err => { throw err; });                        // handle internal server error. (crypto error)


// Check if password match
password.compare(plainPassword, hashedPassword).then(isMatch => {
    if(isMatch) {                                       // isMatch is true if the plainPassword matches the hashedPassword, otherwise false.
        login();
    } else {
        unauthorized();
    }
}).catch(err => { throw err; });                        // Handle internal server error. (crypto error)

```

## Configuration
There are four values that are configurable. See below for default configuration. All settings are adjustable.

```js
let defaults = {
    // Number of iterations (higher number -> more secure but takes longer time to complete.)
    iterations: 612484,

    // Number of bytes for the password hash.
    hashSize: 32,

    // Number of bytes for the password salt.
    saltSize: 16,

    // The digest used to hash the password. See list of digests for crypto.
    digest: 'sha512'
}

```

## Contributing
Pull requests and stars are always welcome. For bugs and feature requests, please create [an issue.](https://github.com/Steeljuice/crypto-password-helper/issues)

## License

MIT © [Tommy Dronkers](https://github.com/Steeljuice)
