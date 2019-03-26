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

var secp256k1 = require('./secp256k1');
var assert = require('assert');
var rlp = require('./rlp');
var BN = require('bn.js');
var { keccak } = require("./keccak");

var _typeof = (typeof Symbol === "function" && typeof Symbol.iterator === "symbol") ? 
function (obj) { return typeof obj; } :
function (obj) {
	return (
		obj && typeof Symbol === "function" && 
		obj.constructor === Symbol && obj !== Symbol.prototype ? "symbol" : typeof obj
	);
};

/**
 * Creates Keccak hash of the input
 * @param {Buffer|Array|String|Number} a the input data
 * @param {Number} [bits=256] the Keccak width
 * @return {Buffer}
 */
exports.keccak = function(a, bits) {
	a = exports.toBuffer(a);
	if (!bits) bits = 256;

	return new Buffer(keccak(a, bits).data);
};

/**
 * Creates SHA-3 hash of the RLP encoded version of the input
 * @param {Buffer|Array|String|Number} a the input data
 * @return {Buffer}
 */
exports.rlphash = function(a) {
	return exports.keccak(rlp.encode(a));
};

/**
 * ECDSA sign
 * @param {Buffer} msgHash
 * @param {Buffer} privateKey
 * @return {Object}
 */
exports.ecsign = function(msgHash, privateKey) {
	var sig = secp256k1.sign(msgHash, privateKey);

	var ret = {};
	ret.r = sig.signature.slice(0, 32);
	ret.s = sig.signature.slice(32, 64);
	ret.v = sig.recovery + 27;
	return ret;
};

/**
 * ECDSA public key recovery from signature
 * @param {Buffer} msgHash
 * @param {Number} v
 * @param {Buffer} r
 * @param {Buffer} s
 * @return {Buffer} publicKey
 */
exports.ecrecover = function(msgHash, v, r, s) {
	var signature = Buffer.concat([exports.setLength(r, 32), exports.setLength(s, 32)], 64);
	var recovery = v - 27;
	if (recovery !== 0 && recovery !== 1) {
		throw new Error('Invalid signature v value');
	}
	var senderPubKey = secp256k1.recover(msgHash, signature, recovery);
	return secp256k1.publicKeyConvert(senderPubKey, false).slice(1);
};

/**
 * Returns the ethereum address of a given public key.
 * Accepts "Ethereum public keys" and SEC1 encoded keys.
 * @param {Buffer} pubKey The two points of an uncompressed key, unless sanitize is enabled
 * @param {Boolean} [sanitize=false] Accept public keys in other formats
 * @return {Buffer}
 */
exports.pubToAddress = exports.publicToAddress = function(pubKey, sanitize) {
	pubKey = exports.toBuffer(pubKey);
	if (sanitize && pubKey.length !== 64) {
		pubKey = secp256k1.publicKeyConvert(pubKey, false).slice(1);
	}
	assert(pubKey.length === 64);
	// Only take the lower 160bits of the hash
	return exports.keccak(pubKey).slice(-20);
};

/**
 * Returns a buffer filled with 0s
 * @method zeros
 * @param {Number} bytes  the number of bytes the buffer should be
 * @return {Buffer}
 */
exports.zeros = function(bytes) {
	return Buffer.allocUnsafe(bytes).fill(0);
};

/**
 * Left Pads an `Array` or `Buffer` with leading zeros till it has `length` bytes.
 * Or it truncates the beginning if it exceeds.
 * @method lsetLength
 * @param {Buffer|Array} msg the value to pad
 * @param {Number} length the number of bytes the output should be
 * @param {Boolean} [right=false] whether to start padding form the left or right
 * @return {Buffer|Array}
 */
exports.setLengthLeft = exports.setLength = function(msg, length, right) {
	var buf = exports.zeros(length);
	msg = exports.toBuffer(msg);
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
};

/**
 * Converts a `Buffer` to a `Number`
 * @param {Buffer} buf
 * @return {Number}
 * @throws If the input number exceeds 53 bits.
 */
exports.bufferToInt = function (buf) {
	return new BN(exports.toBuffer(buf)).toNumber();
};

/**
 * Returns a `Boolean` on whether or not the a `String` starts with '0x'
 * @param {String} str the string input value
 * @return {Boolean} a boolean if it is or is not hex prefixed
 * @throws if the str input is not a string
 */
exports.isHexPrefixed = function(str) {
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
exports.stripHexPrefix = function(str) {
	if (typeof str !== 'string') {
		return str;
	}

	return exports.isHexPrefixed(str) ? str.slice(2) : str;
}

/**
 * Pads a `String` to have an even length
 * @param {String} value
 * @return {String} output
 */
exports.padToEven = function(value) {
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
exports.isHexString = function(value, length) {
	if (typeof(value) !== 'string' || !value.match(/^0x[0-9A-Fa-f]*$/)) {
		return false;
	}

	if (length && value.length !== 2 + 2 * length) { return false; }

	return true;
}

/**
 * Attempts to turn a value into a `Buffer`. As input it supports `Buffer`, `String`, 
 * `Number`, null/undefined, `BN` and other objects with a `toArray()` method.
 * @param {*} v the value
 */
exports.toBuffer = function(v) {
	if (!Buffer.isBuffer(v)) {
		if (Array.isArray(v)) {
			v = Buffer.from(v);
		} else if (typeof v === 'string') {
			if (exports.isHexString(v)) {
				v = Buffer.from(exports.padToEven(exports.stripHexPrefix(v)), 'hex');
			} else {
				v = Buffer.from(v);
			}
		} else if (typeof v === 'number') {
			v = exports.intToBuffer(v);
		} else if (v === null || v === undefined) {
			v = Buffer.allocUnsafe(0);
		} else if (BN.isBN(v)) {
			v = v.toArrayLike(Buffer);
		} else if (v.toArray) {
			// converts a BN to a Buffer
			v = Buffer.from(v.toArray());
		} else {
			throw new Error('invalid type');
		}
	}
	return v;
};

/**
 * Converts a `Buffer` or `Array` to JSON
 * @param {Buffer|Array} ba
 * @return {Array|String|null}
 */
exports.baToJSON = function (ba) {
	if (Buffer.isBuffer(ba)) {
		return '0x' + ba.toString('hex');
	} else if (ba instanceof Array) {
		var array = [];
		for (var i = 0; i < ba.length; i++) {
			array.push(exports.baToJSON(ba[i]));
		}
		return array;
	}
};

/**
 * Trims leading zeros from a `Buffer` or an `Array`
 * @param {Buffer|Array|String} a
 * @return {Buffer|Array|String}
 */
exports.unpad = exports.stripZeros = function (a) {
	a = exports.stripHexPrefix(a);
	var first = a[0];
	while (a.length > 0 && first.toString() === '0') {
		a = a.slice(1);
		first = a[0];
	}
	return a;
};

/**
 * Converts a `Number` into a hex `String`
 * @param {Number} i
 * @return {String}
 */
exports.intToHex = function(i) {
	var hex = i.toString(16); // eslint-disable-line
	return '0x' + hex;
}

/**
 * Converts an `Number` to a `Buffer`
 * @param {Number} i
 * @return {Buffer}
 */
exports.intToBuffer = function(i) {
	var hex = exports.intToHex(i);
	return new Buffer(exports.padToEven(hex.slice(2)), 'hex');
}

/**
 * Defines properties on a `Object`. It make the assumption that underlying data is binary.
 * @param {Object} self the `Object` to define properties on
 * @param {Array} fields an array fields to define. Fields can contain:
 * * `name` - the name of the properties
 * * `length` - the number of bytes the field can have
 * * `allowLess` - if the field can be less than the length
 * * `allowEmpty`
 * @param {*} data data to be validated against the definitions
 */
exports.defineProperties = function (self, fields, data) {
	self.raw = [];
	self._fields = [];

	// attach the `toJSON`
	self.toJSON = function (label) {
		if (label) {
			var obj = {};
			self._fields.forEach(function (field) {
				obj[field] = '0x' + self[field].toString('hex');
			});
			return obj;
		}
		return exports.baToJSON(this.raw);
	};

	self.serialize = function serialize() {
		return rlp.encode(self.raw);
	};

	fields.forEach(function (field, i) {
		self._fields.push(field.name);
		function getter() {
			return self.raw[i];
		}
		function setter(v) {
			v = exports.toBuffer(v);

			if (v.toString('hex') === '00' && !field.allowZero) {
				v = Buffer.allocUnsafe(0);
			}

			if (field.allowLess && field.length) {
				v = exports.stripZeros(v);
				assert(field.length >= v.length, 
					'The field ' + field.name + ' must not have more ' + field.length + ' bytes');
			}
			else if (!(field.allowZero && v.length === 0) && field.length) {
				assert(field.length === v.length, 
					'The field ' + field.name + ' must have byte length of ' + field.length);
			}

			self.raw[i] = v;
		}

		Object.defineProperty(self, field.name, {
			enumerable: true,
			configurable: true,
			get: getter,
			set: setter
		});

		if (field.default) {
			self[field.name] = field.default;
		}

		// attach alias
		if (field.alias) {
			Object.defineProperty(self, field.alias, {
				enumerable: false,
				configurable: true,
				set: setter,
				get: getter
			});
		}
	});

	// if the constuctor is passed data
	if (data) {
		if (typeof data === 'string') {
			data = Buffer.from(exports.stripHexPrefix(data), 'hex');
		}

		if (Buffer.isBuffer(data)) {
			data = rlp.decode(data);
		}

		if (Array.isArray(data)) {
			if (data.length > self._fields.length) {
				throw new Error('wrong number of fields in data');
			}

			// make sure all the items are buffers
			data.forEach(function (d, i) {
				self[self._fields[i]] = exports.toBuffer(d);
			});
		} else if ((typeof data === 'undefined' ? 'undefined' : _typeof(data)) === 'object') {
			var keys = Object.keys(data);
			fields.forEach(function (field) {
				if (keys.indexOf(field.name) !== -1) self[field.name] = data[field.name];
				if (keys.indexOf(field.alias) !== -1) self[field.alias] = data[field.alias];
			});
		} else {
			throw new Error('invalid data');
		}
	}
};