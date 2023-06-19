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
import * as assert from 'assert';
import secp256k1 from './ec';
import buffer, {Buffer} from 'somes/buffer';
import BN from './bn1';;
import {keccak as sha3} from './keccak';

if (somes.haveNode) {
	var crypto = require('crypto');
} else {
	var browserCrypto = (global.crypto || (global as any).msCrypto || {}) as typeof global.crypto;
}

export function getRandomValues(len: number): Buffer {
	if (crypto) { // node
		return buffer.from(crypto.randomBytes(len));
	} else { // web
		return buffer.from(browserCrypto.getRandomValues(new Uint8Array(len)));
	}
}

/**
 * RLP Encoding based on: https://github.com/ethereum/wiki/wiki/%5BEnglish%5D-RLP
 * This function takes in a data, convert it to buffer if not, and a length for recursion
 *
 * @param {Buffer,String,Integer,Array} data - will be converted to buffer
 * @returns {Buffer} - returns buffer of encoded data
 **/
export function rlp_encode(input: Buffer | ArrayLike<any> | string | number): Buffer {
	if (input instanceof Array) {
		var output = []
		for (var i = 0; i < input.length; i++) {
			output.push(rlp_encode(input[i]))
		}
		var buf = buffer.concat(output)
		return buffer.concat([rlp_encodeLength(buf.length, 192), buf])
	} else {
		var bf = toBuffer(input);
		if (bf.length === 1 && bf[0] < 128) {
			return bf;
		} else {
			return buffer.concat([rlp_encodeLength(bf.length, 128), bf])
		}
	}
}

/**
 * RLP Decoding based on: {@link https://github.com/ethereum/wiki/wiki/%5BEnglish%5D-RLP|RLP}
 * @param {Buffer,String,Integer,Array} data - will be converted to buffer
 * @returns {Array} - returns decode Array of Buffers containg the original message
 **/
export function rlp_decode(input: Buffer, stream = false): any {
	if (!input || input.length === 0) {
		return [buffer.from([])];
	}

	input = toBuffer(input)
	var decoded = rlp_decode2(input)

	if (stream) {
		return decoded;
	}

	assert.strictEqual(decoded.remainder.length, 0, 'invalid remainder')
	return decoded.data
}

function rlp_decode2(input: Buffer): { remainder: Buffer, data: any } {
	var length, llength, data, innerRemainder, d
	var decoded: any[] = [];
	var firstByte = input[0]

	if (firstByte <= 0x7f) {
		// a single byte whose value is in the [0x00, 0x7f] range, that byte is its own RLP encoding.
		return {
			data: input.slice(0, 1),
			remainder: input.slice(1),
		}
	} else if (firstByte <= 0xb7) {
		// string is 0-55 bytes long. A single byte with value 0x80 plus the length of the string followed by the string
		// The range of the first byte is [0x80, 0xb7]
		length = firstByte - 0x7f

		// set 0x80 null to 0
		if (firstByte === 0x80) {
			data = buffer.from([])
		} else {
			data = input.slice(1, length)
		}

		if (length === 2 && data[0] < 0x80) {
			throw new Error('invalid rlp encoding: byte must be less 0x80')
		}

		return {
			data: data,
			remainder: input.slice(length)
		}
	} else if (firstByte <= 0xbf) {
		llength = firstByte - 0xb6
		length = safeParseInt(input.slice(1, llength).toString('hex'), 16)
		data = input.slice(llength, length + llength)
		if (data.length < length) {
			throw (new Error('invalid RLP'))
		}
		return {
			data: data,
			remainder: input.slice(length + llength)
		}
	} else if (firstByte <= 0xf7) {
		// a list between  0-55 bytes long
		length = firstByte - 0xbf
		innerRemainder = input.slice(1, length)
		while (innerRemainder.length) {
			d = rlp_decode2(innerRemainder)
			decoded.push(d.data);
			innerRemainder = d.remainder
		}
		return {
			data: decoded,
			remainder: input.slice(length)
		}
	} else {
		// a list  over 55 bytes long
		llength = firstByte - 0xf6
		length = safeParseInt(input.slice(1, llength).toString('hex'), 16)
		var totalLength = llength + length
		if (totalLength > input.length) {
			throw new Error('invalid rlp: total length is larger than the data')
		}

		innerRemainder = input.slice(llength, totalLength)
		if (innerRemainder.length === 0) {
			throw new Error('invalid rlp, List has a invalid length')
		}

		while (innerRemainder.length) {
			d = rlp_decode2(innerRemainder)
			decoded.push(d.data)
			innerRemainder = d.remainder
		}

		return {
			data: decoded,
			remainder: input.slice(totalLength)
		}
	}
}

function rpl_intToHex(i: number) {
	var hex = i.toString(16)
	if (hex.length % 2) {
		hex = '0' + hex
	}
	return hex
}

function rlp_encodeLength(len: number, offset: number) {
	if (len < 56) {
		return buffer.from([len + offset])
	} else {
		var hexLength = rpl_intToHex(len)
		var lLength = hexLength.length / 2
		var firstByte = rpl_intToHex(offset + 55 + lLength)
		return buffer.from(firstByte + hexLength, 'hex')
	}
}

export function rlp_getLength(input: Buffer | number[] | string) {
	if (!input || input.length === 0) {
		return buffer.from([]);
	}
	input = toBuffer(input)
	var firstByte = input[0]
	if (firstByte <= 0x7f) {
		return input.length
	} else if (firstByte <= 0xb7) {
		return firstByte - 0x7f
	} else if (firstByte <= 0xbf) {
		return firstByte - 0xb6
	} else if (firstByte <= 0xf7) {
		// a list between  0-55 bytes long
		return firstByte - 0xbf
	} else {
		// a list  over 55 bytes long
		var llength = firstByte - 0xf6
		var length = safeParseInt(input.slice(1, llength).toString('hex'), 16)
		return llength + length
	}
}

function safeParseInt(v: string, base: number) {
	if (v.slice(0, 2) === '00') {
		throw (new Error('invalid RLP: extra zeros'))
	}
	return parseInt(v, base)
}

/**
 * Creates Keccak hash of the input
 * @param {Buffer|Array|String|Number} a the input data
 * @param {Number} [bits=256] the Keccak width
 * @return {Buffer}
 */
export function keccak(a: string | number | ArrayLike<number>, bits = 256) {
	a = toBuffer(a);
	if (!bits) bits = 256;
	return buffer.from(sha3(a, bits).data);
}

/**
 * Creates SHA-3 hash of the RLP encoded version of the input
 * @param {Buffer|Array|String|Number} a the input data
 * @return {Buffer}
 */
export function rlphash(a: ArrayLike<number> | string | number) {
	return buffer.from(sha3(rlp_encode(a)).data);
}

/**
 * ECDSA sign
 * @param {Buffer} msgHash
 * @param {Buffer} privateKey
 * @return {Object}
 */
export function ecsign(msgHash: Buffer, privateKey: Buffer) {
	var sig = secp256k1.sign(msgHash, privateKey);
	var ret = {} as { r: Buffer, s: Buffer, v: number };
	ret.r = sig.signature.slice(0, 32);
	ret.s = sig.signature.slice(32, 64);
	ret.v = sig.recovery + 27;
	return ret;
}

/**
 * ECDSA public key recovery from signature
 * @param {Buffer} msgHash
 * @param {Number} v
 * @param {Buffer} r
 * @param {Buffer} s
 * @return {Buffer} publicKey
 */
export function ecrecover(msgHash: Buffer, v: number, r: Buffer, s: Buffer) {
	var signature = buffer.concat([setLength(r, 32), setLength(s, 32)], 64);
	var recovery = v - 27;
	if (recovery !== 0 && recovery !== 1) {
		throw new Error('Invalid signature v value');
	}
	var senderPubKey = secp256k1.recover(msgHash, signature, recovery);
	return secp256k1.publicKeyConvert(senderPubKey, false).slice(1);
}

/**
 * Returns the ethereum address of a given public key.
 * Accepts "Ethereum public keys" and SEC1 encoded keys.
 * @param {Buffer} pubKey The two points of an uncompressed key, unless sanitize is enabled
 * @param {Boolean} [sanitize=false] Accept public keys in other formats
 * @return {Buffer}
 */
export function publicToAddress(pubKey: Buffer, sanitize = false) {
	pubKey = toBuffer(pubKey);
	if (sanitize && pubKey.length !== 64) {
		pubKey = secp256k1.publicKeyConvert(pubKey, false).slice(1);
	}
	assert.equal(pubKey.length,64);
	// Only take the lower 160bits of the hash
	return buffer.from(sha3(pubKey).data.slice(-20));
}

/**
 * Returns a buffer filled with 0s
 * @method zeros
 * @param {Number} bytes  the number of bytes the buffer should be
 * @return {Buffer}
 */
export function zeros(bytes: number) {
	return buffer.allocUnsafe(bytes).fill(0);
}

/**
 * Left Pads an `Array` or `Buffer` with leading zeros till it has `length` bytes.
 * Or it truncates the beginning if it exceeds.
 * @method lsetLength
 * @param {Buffer|Array} msg the value to pad
 * @param {Number} length the number of bytes the output should be
 * @param {Boolean} [right=false] whether to start padding form the left or right
 * @return {Buffer|Array}
 */
export function setLength(message: ArrayLike<number>, length: number, right = false) {
	var buf = zeros(length);
	var msg = toBuffer(message);
	if (right) {
		if (msg.length < length) {
			msg.copy(buf);
			return buf;
		}
		return msg.slice(0, length);
	} else {
		if (msg.length < length) {
			msg.copy(buf, length - msg.length);
			return buf;
		}
		return msg.slice(-length);
	}
}

/**
 * Converts a `Buffer` to a `Number`
 * @param {Buffer} buf
 * @return {Number}
 * @throws If the input number exceeds 53 bits.
 */
export function bufferToInt(buf: Uint8Array) {
	return new BN(toBuffer(buf)).toNumber();
}

/**
 * Returns a `Boolean` on whether or not the a `String` starts with '0x'
 * @param {String} str the string input value
 * @return {Boolean} a boolean if it is or is not hex prefixed
 * @throws if the str input is not a string
 */
 export function isHexPrefixed(str: string) {
	if (typeof str !== 'string') {
		throw new Error("[is-hex-prefixed] value must be type 'string', is currently type " + 
			(typeof str) + ", while checking isHexPrefixed.");
	}
	return str.slice(0, 2) === '0x';
}

/**
 * Removes '0x' from a given `String` is present
 * @param {String} str the string value
 * @return {String|Optional} a string by pass if necessary
 */
 export function stripHexPrefix<T>(str: T): T {
	if (typeof str !== 'string') {
		return str;
	}
	return isHexPrefixed(str) ? str.slice(2) : str as any;
}

/**
 * Pads a `String` to have an even length
 * @param {String} value
 * @return {String} output
 */
export function padToEven(value: string) {
	var a = value; // eslint-disable-line

	if (typeof a !== 'string') {
		throw new Error(`[ethjs-util] while padding to even, \
			value must be string, is currently ${typeof a}, while padToEven.`);
	}

	if (a.length % 2) {
		a = `0${a}`;
	}

	return a;
}

/**
 * Is the string a hex string.
 *
 * @method check if string is hex string of specific length
 * @param {String} value
 * @param {Number} length
 * @returns {Boolean} output the string is a hex string
 */
export function isHexString(value: string, length?: number) {
	if (typeof(value) !== 'string' || !value.match(/^0x[0-9A-Fa-f]*$/)) {
		return false;
	}

	if (length && value.length !== 2 + 2 * length) {
		return false;
	}

	return true;
}

/**
 * Attempts to turn a value into a `Buffer`. As input it supports `Buffer`, `String`, 
 * `Number`, null/undefined, `BN` and other objects with a `toArray()` method.
 * @param {*} v the value
 */
export function toBuffer(v?: string | Uint8Array | ArrayLike<number> | BN | { toArray: ()=>number[] } | number | bigint | null): Buffer {
	var r: Buffer;
	if (v instanceof Uint8Array) {
		r = buffer.from(v);
	} else if (Array.isArray(v)) {
		r = buffer.from(v);
	} else if (typeof v === 'string') {
		if (isHexString(v)) {
			r = buffer.from(padToEven(stripHexPrefix(v)), 'hex');
		} else {
			r = buffer.from(v);
		}
	} else if (typeof v === 'number' || typeof v === 'bigint') {
		r = intToBuffer(v);
	} else if (v === null || v === undefined) {
		r = buffer.allocUnsafe(0);
	} else if (BN.isBN(v)) {
		r = buffer.from(v.toArrayLike(Array as any));
	} else if ((v as any).toArray) {
		// converts a BN to a Buffer
		r = buffer.from((v as any).toArray());
	} else {
		throw new Error('invalid type');
	}
	return r;
}

/**
 * Converts a `Buffer` or `Array` to JSON
 * @param {Buffer|Array} ba
 * @return {Array|String|null}
 */
export function baToJSON(ba: Uint8Array | any[]): string | string[] | null {
	if (buffer.isTypedArray(ba)) {
		return '0x' + buffer.from(ba).toString('hex');
	} else if (ba instanceof Array) {
		var array: string[] = [];
		for (var i = 0; i < ba.length; i++) {
			array.push(baToJSON(ba[i]) as string);
		}
		return array;
	}
	return null;
}

/**
 * Trims leading zeros from a `Buffer` or an `Array`
 * @param {Buffer|Array|String} a
 * @return {Buffer|Array|String}
 */
export function stripZeros<T extends string | Buffer | Array<number>>(_a: T) {
	let a = stripHexPrefix(_a);
	var first = a[0];
	while (a.length > 0 && first.toString() === '0') {
		a = a.slice(1) as any;
		first = a[0];
	}
	return a;
}

/**
 * Converts a `Number` into a hex `String`
 * @param {Number} i
 * @return {String}
 */
export function intToHex(i: number) {
	var hex = i.toString(16); // eslint-disable-line
	return '0x' + hex;
}

/**
 * Converts an `Number` to a `Buffer`
 * @param {Number} i
 * @return {Buffer}
 */
export function intToBuffer(i: number | bigint) {
	var hex = i.toString(16);
	return buffer.from(padToEven(hex), 'hex');
}

export default {
	getRandomValues,// = getRandomValues;
	rlp_encode,// = rlp_encode;
	rlp_decode,// = rlp_decode;
	rlp_getLength,// = rlp_getLength;
	keccak,// = keccak;
	rlphash,// = rlphash;
	ecsign,// = ecsign;
	ecrecover,// = ecrecover;
	publicToAddress,
	pubToAddress: publicToAddress,// = exports.publicToAddress = publicToAddress;
	zeros,// = zeros;
	setLength,
	setLengthLeft: setLength,// = exports.setLength = setLength;
	bufferToInt,// = bufferToInt;
	isHexPrefixed,// = isHexPrefixed;
	stripHexPrefix,// = stripHexPrefix;
	padToEven,// = padToEven;
	isHexString,// = isHexString;
	toBuffer,// = toBuffer;
	baToJSON,// = baToJSON;
	intToHex,// = intToHex;
	unpad: stripZeros,// = exports.stripZeros = stripZeros;
	stripZeros,
	intToBuffer,// = intToBuffer;
};