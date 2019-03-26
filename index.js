/* ***** BEGIN LICENSE BLOCK *****
 * Distributed under the BSD license:
 *
 * Copyright (c) 2019, hardchain
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of hardchain nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL hardchain BE LIABLE FOR ANY
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
var { Transaction } = require('./tx');
var { keccak256 } = require('./keccak');
var secp256k1 = require('./secp256k1');

if (utils.haveNode) {
	var crypto = require('crypto');
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

function getRandomValues(len) {
	if (utils.haveNode) { // node
		return crypto.randomBytes(len);
	} else { // web
		return new Buffer(crypto.getRandomValues(new Uint8Array(len)));
	}
}

function generatePrivateKey() {
	var privateKey = getRandomValues(32);
	while (!isValidPrivateKey(privateKey)) {
		privateKey = getRandomValues(32);
	}
	return privateKey;
};

function toChecksum(address) {
	var addressHash = keccak256(address).hex;
	var checksumAddress = '0x';
	for (var i = 0; i < 40; i++) {
		checksumAddress += parseInt(addressHash[i + 2], 16) > 7 ? 
			address[i].toUpperCase() : address[i];
	}
	return checksumAddress;
}

function getPublicKeyFromPrivate(privateKey) {
	var publicKey = secp256k1.publicKeyCreate(privateKey, false).toString('hex').slice(2);
	var publicHash = keccak256('0x' + publicKey).hex;
	var address = toChecksum(publicHash.slice(-40));
	// console.log(address);
	return address;
}

function sign(txData) {
	// var txData = {
	// 	nonce: '0x00',
	// 	gasPrice: '0x09184e72a000', 
	// 	gasLimit: '0x2710',
	// 	to: '0x0000000000000000000000000000000000000000',
	// 	value: '0x00', 
	// 	data: '0x7f7465737432000000000000000000000000000000000000000000000000000000600057',
	// 	// EIP 155 chainId - mainnet: 1, ropsten: 3
	// 	chainId: 3
	// }
	var tx = new Transaction(txData);
	tx.sign(getAccountPrivkeyKey());
	var serializedTx = tx.serialize();
	return {
		rsv: { r: tx.r, s: tx.s, v: tx.v },
		rsvHex: {
			r: '0x' + tx.r.toString('hex'),
			s: '0x' + tx.s.toString('hex'),
			v: '0x' + tx.v.toString('hex'),
		},
		rawTx: txData,
		signTx: serializedTx,
		hex: '0x' + serializedTx.toString('hex'),
	};
}

module.exports = {
	generatePrivateKey,
	getPublicKeyFromPrivate,
	Transaction,
	secp256k1,
	sign,
};