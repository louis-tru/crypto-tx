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

const { Buffer } = require('buffer');
const { keccak } = require('./keccak');
const secp256k1 = require('./secp256k1');
const utils_2 = require('./utils');

const EC_GROUP_ORDER = Buffer.from(
	'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141', 'hex');
const ZERO32 = Buffer.alloc(32, 0);

const getRandomValues = utils_2.getRandomValues;

function isValidPrivateKey(privateKey) {
	if (privateKey.length === 32) {
		return privateKey.compare(ZERO32) > 0 && // > 0
		privateKey.compare(EC_GROUP_ORDER) < 0; // < G
	}
}

function genPrivateKey() {
	do {
		var privateKey = getRandomValues(32);
	} while (!isValidPrivateKey(privateKey));
	return privateKey;
}

function toChecksumAddress(address) {
	address = address.toString('hex');
	var addressHash = keccak(address).hex.slice(2);
	// console.log(addressHash);
	var checksumAddress = '';
	for (var i = 0; i < 40; i++) {
		checksumAddress += parseInt(addressHash[i], 16) > 7 ? 
			address[i].toUpperCase() : address[i];
	}
	return checksumAddress;
}

function publicToAddress(publicKey, fmt = 'address') {
	var address = utils_2.publicToAddress(publicKey, true);
	if (fmt == 'binary') {
		return address; // binary
	}	else {
		address = toChecksumAddress(address);
		return fmt == 'address' ? '0x' + address: address;
	}
}

function getAddress(privateKey, fmt = 'address') {
	return publicToAddress(getPublic(privateKey), fmt);
}

function getPublic(privateKey, compressed = false) {
	return secp256k1.publicKeyCreate(privateKey, compressed);
}

const publicKeyConvert = secp256k1.publicKeyConvert;

function publicKeyConvertDetails(public_key) {
	public_key = utils_2.toBuffer(public_key);
	var publicKeyLong = publicKeyConvert(public_key, false);
	var publicKey = publicKeyConvert(publicKeyLong);
	var address = publicToAddress(publicKeyLong, 'binary');
	var publicKeyHex = publicKey.toString('hex');
	var publicKeyLongHex = publicKeyLong.toString('hex');
	var addressHex = toChecksumAddress(address);
	return {
		publicKeyBytes: publicKey,
		publicKeyLongBytes: publicKeyLong,
		addressBytes: address,
		publicKey: '0x' + publicKeyHex,
		publicKeyLong: '0x' + publicKeyLongHex,
		address: '0x' + addressHex,
		publicKeyHex: publicKeyHex,
		publicKeyLongHex: publicKeyLongHex,
		addressHex: addressHex,
	};
}

function checkAddressHex(addressHex) {
	if (typeof addressHex == 'string') {
		if (addressHex.length == 42 && addressHex[0] == '0' && addressHex[1] == 'x') {
			var _0 = '0'.charCodeAt(0), _9 = '9'.charCodeAt(0);
			var _a = 'a'.charCodeAt(0), _f = 'f'.charCodeAt(0);
			var _A = 'A'.charCodeAt(0), _F = 'F'.charCodeAt(0);

			for (var i = 2; i < 42; i++) {
				var code = addressHex.charCodeAt(i);
				if (!(
					(_0 <= code && code <= _9) || 
					(_a <= code && code <= _f) || 
					(_A <= code && code <= _F)
				)) {
					return false
				}
			}
			return true;
		}
	}
	return false;
}

function sign(message, privateKey, options) {
	return secp256k1.sign(message, privateKey, options);
}

function verify(message, signature, publicKeyTo, canonical) {
	return secp256k1.verify(message, signature, publicKeyTo, canonical);
}

function recover(message, signature, recovery, compressed = true) {
	return secp256k1.recover(message, signature, recovery, compressed);
}

module.exports = {
	getRandomValues,
	isValidPrivateKey,
	genPrivateKey,
	getPublic,
	publicToAddress,
	checkAddressHex,
	getAddress,
	toChecksumAddress,
	publicKeyConvert,
	publicKeyConvertDetails,
	sign,
	verify,
	recover,
};