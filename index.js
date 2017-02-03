"use strict";

let crypto = require('crypto');

/**
 * The default settings for encrypting the password.
 **/
let defaults = {
    // Number of iterations (higher number -> more secure but takes longer time to complete.)
    iterations: 612484,

    // Number of bytes for the password hash.
    hashSize: 32,

    // Number of bytes for the password salt.
    saltSize: 16,

    // The digest used to hash the password.
    digest: 'sha512'
}

/**
 * Encrypts a password using a promise. The hash will contain the salt
 * so there is no need to save it seperatly.
 * 
 * @param {String} plainPassword - The plain password to encrypt.
 * @param {JSON} options - (not required) options for encrypting the password.
 * @returns {Promise} - Promise parameter is the encrypted password as String.
 **/
function encrypt(plainPassword, config) {
    return new Promise((resolve, reject) => {
        try {
            config = _sanitizeConfiguration(config);

            // Salt buffer
            let salt = crypto.randomBytes(config.saltSize);
            // Hash buffer
            let hash = crypto.pbkdf2Sync(plainPassword, salt, config.iterations, config.hashSize, config.digest);
            // The digest used to hash the password
            let digest = new Buffer(config.digest);

            // The combined buffer size
            let combined = Buffer.alloc(4 + 4 + 4 + 4 + salt.length + hash.length + digest.length);

            // Salt size (0-4)
            combined.writeUInt32BE(salt.length, 0);

            // Iterations size (4-8)
            combined.writeUInt32BE(config.iterations, 4);

            // Hash size (8-12)
            combined.writeUInt32BE(config.hashSize, 8);

            // Digest size (12-16)
            combined.writeUInt32BE(digest.length, 12);

            // Salt (16)
            salt.copy(combined, 16);

            // Hash (16 + saltSize)
            hash.copy(combined, 16 + salt.length);

            // Digest (16 + saltSize + hashSize)
            digest.copy(combined, 16 + salt.length + hash.length);

            return resolve(combined.toString('hex'));
        }
        catch (err) {
            return reject(err); // Bubble any errors back to the promise.
        }
    });
}

/**
 * Compare a plain password with an encrypted password.
 * @param {String} plainPassowrd - The plain password to compare.
 * @param {String} encryptedPassword - The encrypted password to compare with plain password.
 * @returns {Promise} - Promise parameter is a boolen, true when plainPassword matches encryptedPassword. Otherwise false.
 **/
function compare(plainPassword, encryptedPassword) {
    return new Promise((resolve, reject) => {
        try {
            let hashBuffer = new Buffer(encryptedPassword, 'hex');

            let saltlength = hashBuffer.readUInt32BE(0);
            let iterations = hashBuffer.readUInt32BE(4);
            let hashlength = hashBuffer.readUInt32BE(8);
            let digestlength = hashBuffer.readUInt32BE(12);
            let salt = hashBuffer.slice(16, 16 + saltlength);

            let hash = hashBuffer.slice(16 + saltlength, 16 + saltlength + hashlength);
            let digest = hashBuffer.slice(16 + saltlength + hashlength, 16 + saltlength + hashlength + digestlength);

            let plainHash = crypto.pbkdf2Sync(plainPassword, salt, iterations, hashlength, digest.toString());

            return resolve((plainHash.toString('hex') === hash.toString('hex')));
        }
        catch (err) {
            return reject(err);
        }
    });
}

/**
 * Helper function to sanitzie the options. Makes sure that the settings
 * are OK.
 * @param {JSON} options - the JSON options to sanitize.
 * @returns {JSON} - With sanitized values.
 * @throws {Error} - If options are not correct.
 **/
function _sanitizeConfiguration(options) {
    let sanitized = Object.assign(defaults, options);
    if (sanitized.iterations <= 0) throw new Error('Field iterations have to be >= 1');
    if (sanitized.saltSize < 16) throw new Error('Minimum salt size is 16 bytes.');
    if (sanitized.hashSize < 32) throw new Error('Minimum hash size is 32 bytes.');


    return sanitized;
}


module.exports = {
    encrypt,
    compare
}