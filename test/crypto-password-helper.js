"use strict";

let password = require('../index.js');

let chai = require('chai');
let should = chai.should();
let assert = chai.assert;
let expect = chai.expect;

/**
 * Test for the password helper.
 **/
describe('Crypto Password Helper.', () => {

    let options = {
        iterations: 10,
        hashSize: 32,
        saltSize: 16
    };


    describe('Async', () => {
        /**
         * Make sure that a hash is returned with correct length and only alphanumerics (hex).
         **/
        it('Should generate a hash.', done => {
            password.encrypt("password", options).then(hash => {
                expect(hash).to.match(/^[0-9a-z]+$/i);
                done();
            }).catch(err => {
                done(err);
            });
        });

        /**
         * Compare a hashed password successfully.
         **/
        it('Should successfully compare password.', done => {
            password.encrypt("password", options).then(hash => {
                password.compare("password", hash).then(isMatch => {
                    assert.isTrue(isMatch);
                    done();
                });
            }).catch(err => {
                done(err);
            });
        }).timeout(5000);

        /**
         * Compare invalid password.
         **/
        it('Should not match password.', done => {
            password.encrypt("password", options).then(hash => {
                password.compare("invalid", hash).then(isMatch => {
                    assert.isFalse(isMatch);
                    done();
                });
            }).catch(err => {
                done(err);
            });

        }).timeout(5000);

        /**
         * Minimum iterations 1.
         **/
        it('Should not allow iterations below 1.', done => {
            password.encrypt('password', {
                    iterations: 0
                }).then(hash => {
                    done('Iterations below 1 allowed.');
                })
                .catch(err => {
                    assert.isNotNull(err);
                    done();
                });
        });

        /**
         * Minimum salt size 16 bytes.
         **/
        it('Should not allow salt size below 16 bytes.', done => {
            password.encrypt('password', {
                saltSize: 15
            }).then(hash => {
                done('Salt Size below 16 allowed.')
            }).catch(err => {
                assert.isNotNull(err);
                done();
            });
        });

        /**
         * Minimum hash size 32 bytes.
         **/
        it('Should not allow hash size below 32 bytes.', done => {
            password.encrypt('password', {
                hashSize: 31
            }).then(hash => {
                done('Hash size below 31 allowed.');
            }).catch(err => {
                assert.isNotNull(err);
                done();
            });
        });
    });

    describe('Sync', () => {


        it('Should generate hash.', done => {
            let hash = password.encryptSync('password', options);
            hash.should.be.a('string');
            hash.length.should.eql(140);
            done();
        });

        it('Should compare hash successfully.', done => {
            let hash = password.encryptSync('password', options);
            let comparison = password.compareSync('password', hash);
            assert.isTrue(comparison);
            done();
        }).timeout(5000);

        it('Should not match password.', done => {
            let hash = password.encryptSync('password', options);
            assert.isFalse(password.compareSync('invalid', hash));
            done();
        });

    });

});
