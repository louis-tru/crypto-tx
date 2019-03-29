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

var utils = require('qkit');
var { Buffer } = require('buffer');
var tx = require('./tx');
var { keccak256 } = require('./keccak');
var secp256k1 = require('./secp256k1');
var assert = require('./secp256k1/assert');
var errno = require('./secp256k1/errno');

if (utils.haveNode) {
	var crypto = require('crypto');
} else {
	var hash_js = require('hash.js');
	var browserCrypto = global.crypto || global.msCrypto || {};
	var subtle = browserCrypto.subtle || browserCrypto.webkitSubtle;
}

var EC_GROUP_ORDER = Buffer.from(
	'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141', 'hex');
var ZERO32 = Buffer.alloc(32, 0);

function isValidPrivateKey(privateKey) {
	if (privateKey.length === 32) {
		return privateKey.compare(ZERO32) > 0 && // > 0
		privateKey.compare(EC_GROUP_ORDER) < 0; // < G
	}
}

// Compare two buffers in constant time to prevent timing attacks.
function equalConstTime(b1, b2) {
	if (b1.length !== b2.length) {
		return false;
	}
	var res = 0;
	for (var i = 0; i < b1.length; i++) {
		res |= b1[i] ^ b2[i];  // jshint ignore:line
	}
	return res === 0;
}

function getRandomValues(len) {
	if (crypto) { // node
		return crypto.randomBytes(len);
	} else { // web
		return new Buffer(crypto.getRandomValues(new Uint8Array(len)));
	}
}

function genPrivateKey() {
	var privateKey = getRandomValues(32);
	while (!isValidPrivateKey(privateKey)) {
		privateKey = getRandomValues(32);
	}
	return privateKey;
}

function toEthAddress(publicKey) {
	assert.isBuffer(publicKey, errno.EC_PUBLIC_KEY_TYPE_INVALID);
	var hex = publicKey.toString('hex').slice(2);
	var publicHash = keccak256('0x' + hex).hex;
	var address = publicHash.slice(-40);
	var addressHash = keccak256(address).hex;
	var checksumAddress = '0x';
	for (var i = 0; i < 40; i++) {
		checksumAddress += parseInt(addressHash[i + 2], 16) > 7 ? 
			address[i].toUpperCase() : address[i];
	}
	return checksumAddress;
}

function getEthAddress(privateKey) {
	return toEthAddress(getPublic(privateKey));
}

function getPublic(privateKey) {
	return secp256k1.publicKeyCreate(privateKey, false);
}

/**
 * Get compressed version of public key.
 */
function getPublicCompressed(privateKey) { // jshint ignore:line
	return secp256k1.publicKeyCreate(privateKey, true);
}

function sign(privateKey, message, options) {
	return secp256k1.sign(message, privateKey, options);
}

function verify(publicKeyTo, message, signature) {
	return secp256k1.sign(message, signature, publicKeyTo);
}

function ecdh(publicKeyA, privateKeyB) {
	return secp256k1.ecdh(publicKeyA, privateKeyB);
}

function sha512(msg) {
	if (crypto) {
		return crypto.createHash("sha512").update(msg).digest();
	} else {
		return new Buffer(hash_js.sha512().update(msg).digest());
	}
}

function hmacSha256(key, msg) {
	if (crypto) {
		return crypto.createHmac('sha256', key).update(msg).digest();
	} else {
		return hash_js.hmac(hash_js.sha256, key).update(msg).digest();
	}
}

function getCryptoSubtleAes(op) {
	return async function(iv, key, data) {
		assert.isBuffer(iv, 'Bad AES iv');
		assert.isBuffer(key, 'Bad AES key');
		assert.isBuffer(data, 'Bad AES data');
		var algorithm = { name: 'AES-CBC' };
		var cryptoKey = await subtle.importKey('raw', key, algorithm, false, [op]);
		var encAlgorithm = { name: 'AES-CBC', iv: iv };
		var result = await subtle[op](encAlgorithm, cryptoKey, data);
		return Buffer.from(new Uint8Array(result));
	}
}

var aes256CbcEncrypt = crypto ? async function(iv, key, plaintext) {
	var cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
	var firstChunk = cipher.update(plaintext);
	var secondChunk = cipher.final();
	return Buffer.concat([firstChunk, secondChunk]);
}: getCryptoSubtleAes('encrypt');

var aes256CbcDecrypt = crypto ? async function(iv, key, ciphertext) {
	var cipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
	var firstChunk = cipher.update(ciphertext);
	var secondChunk = cipher.final();
	return Buffer.concat([firstChunk, secondChunk]);
}: getCryptoSubtleAes('decrypt');

/**
 * @func defaultEncryptIV
 */
function defaultEncryptIV() {
	return new Uint8Array([12,23,76,23,78,12,90,22,67,23,125,46,78,211,222,138]);
}

/**
 * Encrypt message for given recepient's public key.
 * @param {Buffer} publicKeyTo - Recipient's public key (65 bytes)
 * @param {Buffer} message - The message being encrypted
 * @param {?{?iv: Buffer, ?ephemPrivateKey: Buffer}} options - You may also
 * specify initialization vector (16 bytes) and ephemeral private key
 * (32 bytes) to get deterministic results.
 * @return {Promise.<Ecies>} - A promise that resolves with the ECIES
 * structure on successful encryption and rejects on failure.
 */
async function encryptECIES(publicKeyTo, message, options) {
	options = options || {};
	// Tmp variable to save context from flat promises;
	var ephemPrivateKey = options.ephemPrivateKey || genPrivateKey();
	assert(isValidPrivateKey(ephemPrivateKey), 'Bad private key invalid');

	var ephemPublicKey = getPublic(ephemPrivateKey);
	var px = ecdh(publicKeyTo, ephemPrivateKey);
	var hash = sha512(px);
	var iv = options.iv || defaultEncryptIV(); //getRandomValues(16);
	var encryptionKey = hash.slice(0, 32);
	var macKey = hash.slice(32);
	var ciphertext = await aes256CbcEncrypt(iv, encryptionKey, message);
	var dataToMac = Buffer.concat([iv, ephemPublicKey, ciphertext]);
	var mac = Buffer.from(hmacSha256(macKey, dataToMac));
	return {
		iv: iv,
		ephemPublicKey: ephemPublicKey,
		ciphertext: ciphertext,
		mac: mac,
	};
}

/**
 * Decrypt message using given private key.
 * @param {Buffer} privateKey - A 32-byte private key of recepient of
 * the mesage
 * @param {Ecies} options - ECIES structure (result of ECIES encryption)
 * @return {Promise.<Buffer>} - A promise that resolves with the
 * plaintext on successful decryption and rejects on failure.
 */
async function decryptECIES(privateKey, options) {
	assert.isBuffer(privateKey, 'Bad private key');
	assert.isBufferLength(privateKey, 32, 'Bad private key length');
	assert(isValidPrivateKey(privateKey), 'Bad private key invalid');

	var px = ecdh(options.ephemPublicKey, privateKey);
	var hash = sha512(px);
	var encryptionKey = hash.slice(0, 32);
	var macKey = hash.slice(32);
	var iv = options.iv || defaultEncryptIV();

	if (options.mac) {
		var dataToMac = Buffer.concat([
			iv,
			options.ephemPublicKey,
			options.ciphertext
		]);
		var realMac = hmacSha256(macKey, dataToMac);
		assert(equalConstTime(options.mac, realMac), 'Bad MAC');
	}

	var result = await aes256CbcDecrypt(iv, encryptionKey, options.ciphertext);

	return result;
}

module.exports = {
	genPrivateKey,
	getPublic,
	getPublicCompressed,
	getEthAddress,
	secp256k1,
	sign,
	verify,
	ecdh,
	aes256CbcEncrypt,
	aes256CbcDecrypt,
	getRandomValues,
	defaultEncryptIV,
	encryptECIES,
	decryptECIES,
	...tx,
};