/* ***** BEGIN LICENSE BLOCK *****
 * Distributed under the BSD license:
 *
 * Copyright (c) 2015, xuewen.chu
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of xuewen.chu nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL xuewen.chu BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * ***** END LICENSE BLOCK ***** */

const utils = require('somes').default;
const uuid = require('somes/hash/uuid').default;
const scrypt = require('@web3-js/scrypt-shim'); // TODO
const assert = require('./assert');
const keccak = require('./keccak');
const {Buffer} = require('buffer');
const account = require('./account');
const utils_2 = require('./utils');

if (utils.haveNode) {
	var cryp = require('crypto');
} else {
	var cryp = require('crypto-browserify'); // TODO
}

function encryptPrivateKey(privateKey, password, options) {
	/* jshint maxcomplexity: 20 */

	privateKey = utils_2.toBuffer(privateKey);
	var publicKey = account.getPublic(privateKey);
	var details = account.publicKeyConvertDetails(publicKey);

	options = options || {};
	var salt = options.salt || account.getRandomValues(32);
	var iv = options.iv || account.getRandomValues(16);

	var derivedKey;
	var kdf = options.kdf || 'scrypt';
	var kdfparams = {
		dklen: options.dklen || 32,
		salt: salt.toString('hex')
	};

	if (kdf === 'pbkdf2') {
		kdfparams.c = options.c || 262144;
		kdfparams.prf = 'hmac-sha256';
		derivedKey = cryp.pbkdf2Sync(Buffer.from(password), Buffer.from(kdfparams.salt, 'hex'), kdfparams.c, kdfparams.dklen, 'sha256');
	} else if (kdf === 'scrypt') {
		// FIXME: support progress reporting callback
		kdfparams.n = options.n || 8192; // 2048 4096 8192 16384
		kdfparams.r = options.r || 8;
		kdfparams.p = options.p || 1;
		derivedKey = scrypt(Buffer.from(password), Buffer.from(kdfparams.salt, 'hex'), kdfparams.n, kdfparams.r, kdfparams.p, kdfparams.dklen);
	} else {
		throw new Error('Unsupported kdf');
	}

	var cipher = cryp.createCipheriv(options.cipher || 'aes-128-ctr', derivedKey.slice(0, 16), iv);
	if (!cipher) {
		throw new Error('Unsupported cipher');
	}

	var ciphertext = Buffer.concat([cipher.update(privateKey), cipher.final()]);

	var mac = keccak.keccak(Buffer.concat([derivedKey.slice(16, 32), Buffer.from(ciphertext, 'hex')])).hex.replace('0x', '');

	return {
		version: 3,
		id: uuid(options.uuid || cryp.randomBytes(16)),
		address: details.addressHex,
		crypto: {
			ciphertext: ciphertext.toString('hex'),
			cipherparams: {
				iv: iv.toString('hex')
			},
			cipher: options.cipher || 'aes-128-ctr',
			kdf: kdf,
			kdfparams: kdfparams,
			mac: mac.toString('hex')
		}
	};
}

function decryptPrivateKey(v3Keystore, password) {
	/* jshint maxcomplexity: 10 */

	assert.isString(password, 'No password given.');
	assert.isObject(v3Keystore, 'No v3Keystore given.');

	var json = v3Keystore;

	if (json.version !== 3) {
		throw new Error('Not a valid V3 wallet');
	}

	var derivedKey;
	var kdfparams;
	if (json.crypto.kdf === 'scrypt') {
		kdfparams = json.crypto.kdfparams;

		// FIXME: support progress reporting callback
		derivedKey = scrypt(Buffer.from(password), Buffer.from(kdfparams.salt, 'hex'), kdfparams.n, kdfparams.r, kdfparams.p, kdfparams.dklen);
	} else if (json.crypto.kdf === 'pbkdf2') {
		kdfparams = json.crypto.kdfparams;

		if (kdfparams.prf !== 'hmac-sha256') {
			throw new Error('Unsupported parameters to PBKDF2');
		}

		derivedKey = cryp.pbkdf2Sync(Buffer.from(password), Buffer.from(kdfparams.salt, 'hex'), kdfparams.c, kdfparams.dklen, 'sha256');
	} else {
		throw new Error('Unsupported key derivation scheme');
	}

	var ciphertext = Buffer.from(json.crypto.ciphertext, 'hex');

	var mac = keccak.keccak(Buffer.concat([derivedKey.slice(16, 32), ciphertext])).hex.slice(2);
	if (mac !== json.crypto.mac) {
		throw new Error('Key derivation failed - possibly wrong password');
	}

	var decipher = cryp.createDecipheriv(json.crypto.cipher, derivedKey.slice(0, 16), Buffer.from(json.crypto.cipherparams.iv, 'hex'));
	var privateKey = Buffer.concat([decipher.update(ciphertext), decipher.final()]);

	return privateKey;
}

module.exports = {
	encryptPrivateKey,
	decryptPrivateKey,
};