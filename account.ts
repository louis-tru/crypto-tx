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

import buffer, {Buffer} from 'somes/buffer';
import { keccak } from './keccak';
import k1 from './ec';
import * as utils from './utils';
import {rng} from 'somes/rng';

const EC_GROUP_ORDER = buffer.from(
	'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141', 'hex');
const ZERO32 = buffer.alloc(32, 0);

export const getRandomValues = utils.getRandomValues;

export function isValidPrivateKey(privateKey: Buffer) {
	if (privateKey.length === 32) {
		return privateKey.compare(ZERO32) > 0 && // > 0
		privateKey.compare(EC_GROUP_ORDER) < 0; // < G
	}
}

export function genPrivateKey() {
	do {
		var privateKey = getRandomValues(32);
	} while (!isValidPrivateKey(privateKey));
	return privateKey;
}

export function toChecksumAddress(address: string | Buffer) {
	if (typeof address == 'string') {
		address = address.slice(2).toLowerCase();
	} else {
		address = address.toString('hex');
	}
	if (!checkAddressHex('0x' + address)) {
		throw new Error('ERR_INVALID_ETH_ADDRESS');
	}
	
	var addressHash = keccak(address).hex.slice(2);
	// console.log(addressHash);
	var checksumAddress = '';
	for (var i = 0; i < 40; i++) {
		checksumAddress += parseInt(addressHash[i], 16) > 7 ? 
			address[i].toUpperCase() : address[i];
	}
	return checksumAddress;
}

export function checksumAddress(address: string | Buffer) {
	return '0x' + toChecksumAddress(address);
}

export function publicToAddress(publicKey: Buffer, fmt = 'address') {
	var address = utils.publicToAddress(publicKey, true);
	if (fmt == 'binary') {
		return address; // binary
	}	else {
		var addr = toChecksumAddress(address);
		return fmt == 'address' ? '0x' + addr: addr;
	}
}

export function getAddress(privateKey: Buffer, fmt = 'address') {
	return publicToAddress(getPublic(privateKey), fmt);
}

export function getPublic(privateKey: Buffer, compressed = false) {
	return k1.publicKeyCreate(privateKey, compressed);
}

export function publicKeyConvert(publicKey: Buffer, compressed?: boolean) {
	return k1.publicKeyConvert(publicKey, compressed);
}

export function publicKeyConvertDetails(public_key: any) {
	public_key = utils.toBuffer(public_key);
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

export function checkAddressHex(addressHex: any) {
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

export function sign(message: Buffer, privateKey: Buffer, options: any) {
	options = Object.assign({ noncefn: ()=>rng(32) }, options);
	return k1.sign(message, privateKey, options);
}

export function verify(message: Buffer, signature: Buffer, publicKeyTo: Buffer, canonical?: boolean) {
	return k1.verify(message, signature, publicKeyTo, canonical);
}

export function recover(message: Buffer, signature: Buffer, recovery: number, compressed = true) {
	return k1.recover(message, signature, recovery, compressed);
}