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

import somes from 'somes';
import utils from 'somes';
import buffer, {Buffer} from 'somes/buffer';
import secp256k1 from './ec';
import * as assert from './assert';
import utils_2 from './utils';
import * as account from './account';

if (utils.haveNode) {
	var crypto = require('crypto');
} else {
	var hash_js = require('hash.js');
	var _subtle: SubtleCrypto;
	var getSubtle = function() {
		if (!_subtle) {
			var browserCrypto = global.crypto || (global as any).msCrypto || {};
			_subtle = browserCrypto.subtle || (browserCrypto as any).webkitSubtle;
			utils.assert(_subtle, `not find web crypto.subtle`);
		}
		return _subtle;
	};
}

export {};

// Compare two buffers in constant time to prevent timing attacks.
function equalConstTime(b1: Buffer, b2: Buffer) {
	if (b1.length !== b2.length) {
		return false;
	}
	var res = 0;
	for (var i = 0; i < b1.length; i++) {
		res |= b1[i] ^ b2[i];  // jshint ignore:line
	}
	return res === 0;
}

export function ecdh(publicKeyA: Buffer, privateKeyB: Buffer) {
	return secp256k1.ecdh(publicKeyA, privateKeyB);
}

function sha512(msg: Uint8Array | string) {
	if (crypto) {
		return crypto.createHash("sha512").update(msg).digest();
	} else {
		return buffer.from(hash_js.sha512().update(msg).digest());
	}
}

// import * as crypt from 'crypto';

function hmacSha256(key: Uint8Array | string, msg: Uint8Array | string) {
	if (crypto) {
		return crypto.createHmac('sha256', key).update(msg).digest();
	} else {
		return hash_js.hmac(hash_js.sha256, key).update(msg).digest();
	}
}

function getCryptoSubtleAes(op: KeyUsage) {
	return async function(iv: Uint8Array, key: Uint8Array, data: Uint8Array) {
		assert.isBuffer(iv, 'Bad AES iv');
		assert.isBuffer(key, 'Bad AES key');
		assert.isBuffer(data, 'Bad AES data');
		var algorithm = { name: 'AES-CBC' };
		var cryptoKey = await getSubtle().importKey('raw', key, algorithm, false, [op]);
		var encAlgorithm = { name: 'AES-CBC', iv: iv };
		var fn = getSubtle()[op] as any;
		var result = await fn(encAlgorithm, cryptoKey, data);
		return buffer.from(new Uint8Array(result));
	}
}

export const aes256CbcEncrypt = crypto ? async function(iv: Uint8Array, key: Uint8Array, plaintext: string | Uint8Array) {
	var cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
	var firstChunk = cipher.update(plaintext);
	var secondChunk = cipher.final();
	return buffer.concat([firstChunk, secondChunk]);
}: getCryptoSubtleAes('encrypt');

export const aes256CbcDecrypt = crypto ? async function(iv: Uint8Array, key: Uint8Array, ciphertext: Uint8Array) {
	var cipher = crypto.createDecipheriv("aes-256-cbc", key, iv);
	var firstChunk = cipher.update(ciphertext);
	var secondChunk = cipher.final();
	return buffer.concat([firstChunk, secondChunk]);
}: getCryptoSubtleAes('decrypt');

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
export async function encryptECIES(publicKeyTo: Buffer, message: Buffer, options?: {iv?: Buffer, ephemPrivateKey?: Buffer}) {
	options = options || {};
	// Tmp variable to save context from flat promises;
	var ephemPrivateKey = options.ephemPrivateKey || account.genPrivateKey();
	somes.assert(account.isValidPrivateKey(ephemPrivateKey), 'Bad private key invalid');

	var ephemPublicKey = account.getPublic(ephemPrivateKey);
	var px = ecdh(publicKeyTo, ephemPrivateKey);
	var hash = sha512(px);
	var iv = options.iv ? utils_2.toBuffer(options.iv): account.getRandomValues(16);

	assert.isBufferLength(iv, 16, 'Bad iv length Must 128 bit');

	var encryptionKey = hash.slice(0, 32);
	var macKey = hash.slice(32);
	var ciphertext = await aes256CbcEncrypt(iv, encryptionKey, message);
	var dataToMac = buffer.concat([iv, ephemPublicKey, ciphertext]);
	var mac = buffer.from(hmacSha256(macKey, dataToMac));
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
export async function decryptECIES(privateKey: Buffer, options: { ephemPublicKey: Buffer, iv: Buffer, mac: Buffer, ciphertext: Buffer}) {
	assert.isBuffer(privateKey, 'Bad private key');
	assert.isBufferLength(privateKey, 32, 'Bad private key length');
	somes.assert(account.isValidPrivateKey(privateKey), 'Bad private key invalid');

	var px = ecdh(options.ephemPublicKey, privateKey);
	var hash = sha512(px);
	var encryptionKey = hash.slice(0, 32);
	var macKey = hash.slice(32);
	var iv = utils_2.toBuffer(options.iv);

	assert.isBufferLength(iv, 16, 'Bad iv length Must 128 bit');

	if (options.mac) {
		var dataToMac = buffer.concat([
			iv,
			options.ephemPublicKey,
			options.ciphertext
		]);
		var realMac = hmacSha256(macKey, dataToMac);
		somes.assert(equalConstTime(options.mac, realMac), 'Bad MAC');
	}

	var result = await aes256CbcDecrypt(iv, encryptionKey, options.ciphertext);

	return result;
}