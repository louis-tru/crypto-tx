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

'use strict';

var utils = require('somes').default;
var Buffer = require('buffer').Buffer;
var BN = require('bn.js');
var EC = require('elliptic').ec;

var errno = require('../errno');

var ec = new EC('secp256k1');
var ecparams = ec.curve;

if (utils.haveNode) {
	var crypto = require('crypto');
} else {
	var hash_js = require('hash.js');
}

function loadCompressedPublicKey (first, xBuffer) {
	var x = new BN(xBuffer)

	// overflow
	if (x.cmp(ecparams.p) >= 0) return null
	x = x.toRed(ecparams.red)

	// compute corresponding Y
	var y = x.redSqr().redIMul(x).redIAdd(ecparams.b).redSqrt()
	if ((first === 0x03) !== y.isOdd()) y = y.redNeg()

	return ec.keyPair({ pub: { x: x, y: y } })
}

function loadUncompressedPublicKey (first, xBuffer, yBuffer) {
	var x = new BN(xBuffer)
	var y = new BN(yBuffer)

	// overflow
	if (x.cmp(ecparams.p) >= 0 || y.cmp(ecparams.p) >= 0) return null

	x = x.toRed(ecparams.red)
	y = y.toRed(ecparams.red)

	// is odd flag
	if ((first === 0x06 || first === 0x07) && y.isOdd() !== (first === 0x07)) return null

	// x*x*x + b = y*y
	var x3 = x.redSqr().redIMul(x)
	if (!y.redSqr().redISub(x3.redIAdd(ecparams.b)).isZero()) return null

	return ec.keyPair({ pub: { x: x, y: y } })
}

function loadPublicKey (publicKey) {
	var first = publicKey[0]
	switch (first) {
		case 0x02:
		case 0x03:
			if (publicKey.length !== 33) return null
			return loadCompressedPublicKey(first, publicKey.slice(1, 33))
		case 0x04:
		case 0x06:
		case 0x07:
			if (publicKey.length !== 65) return null
			return loadUncompressedPublicKey(first, publicKey.slice(1, 33), publicKey.slice(33, 65))
		default:
			return null
	}
}

exports.privateKeyVerify = function (privateKey) {
	var bn = new BN(privateKey)
	return bn.cmp(ecparams.n) < 0 && !bn.isZero()
}

exports.privateKeyExport = function (privateKey, compressed) {
	var d = new BN(privateKey)
	if (d.cmp(ecparams.n) >= 0 || d.isZero()) throw new Error(errno.EC_PRIVATE_KEY_EXPORT_DER_FAIL)

	return Buffer.from(ec.keyFromPrivate(privateKey).getPublic(compressed, true))
}

exports.privateKeyNegate = function (privateKey) {
	var bn = new BN(privateKey)
	return bn.isZero() ? Buffer.alloc(32) : 
		ecparams.n.sub(bn).umod(ecparams.n).toArrayLike(Buffer, 'be', 32);
}

exports.privateKeyModInverse = function (privateKey) {
	var bn = new BN(privateKey)
	if (bn.cmp(ecparams.n) >= 0 || bn.isZero()) throw new Error(errno.EC_PRIVATE_KEY_RANGE_INVALID)

	return bn.invm(ecparams.n).toArrayLike(Buffer, 'be', 32)
}

exports.privateKeyTweakAdd = function (privateKey, tweak) {
	var bn = new BN(tweak)
	if (bn.cmp(ecparams.n) >= 0) throw new Error(errno.EC_PRIVATE_KEY_TWEAK_ADD_FAIL)

	bn.iadd(new BN(privateKey))
	if (bn.cmp(ecparams.n) >= 0) bn.isub(ecparams.n)
	if (bn.isZero()) throw new Error(errno.EC_PRIVATE_KEY_TWEAK_ADD_FAIL)

	return bn.toArrayLike(Buffer, 'be', 32)
}

exports.privateKeyTweakMul = function (privateKey, tweak) {
	var bn = new BN(tweak)
	if (bn.cmp(ecparams.n) >= 0 || bn.isZero()) throw new Error(errno.EC_PRIVATE_KEY_TWEAK_MUL_FAIL)

	bn.imul(new BN(privateKey))
	if (bn.cmp(ecparams.n)) bn = bn.umod(ecparams.n)

	return bn.toArrayLike(Buffer, 'be', 32)
}

exports.publicKeyCreate = function (privateKey, compressed) {
	var d = new BN(privateKey)
	if (d.cmp(ecparams.n) >= 0 || d.isZero()) throw new Error(errno.EC_PUBLIC_KEY_CREATE_FAIL)

	return Buffer.from(ec.keyFromPrivate(privateKey).getPublic(compressed, true))
}

exports.publicKeyConvert = function (publicKey, compressed) {
	var pair = loadPublicKey(publicKey)
	if (pair === null) throw new Error(errno.EC_PUBLIC_KEY_PARSE_FAIL)

	return Buffer.from(pair.getPublic(compressed, true))
}

exports.publicKeyVerify = function (publicKey) {
	return loadPublicKey(publicKey) !== null
}

exports.publicKeyTweakAdd = function (publicKey, tweak, compressed) {
	var pair = loadPublicKey(publicKey)
	if (pair === null) throw new Error(errno.EC_PUBLIC_KEY_PARSE_FAIL)

	tweak = new BN(tweak)
	if (tweak.cmp(ecparams.n) >= 0) throw new Error(errno.EC_PUBLIC_KEY_TWEAK_ADD_FAIL)

	return Buffer.from(ecparams.g.mul(tweak).add(pair.pub).encode(true, compressed))
}

exports.publicKeyTweakMul = function (publicKey, tweak, compressed) {
	var pair = loadPublicKey(publicKey)
	if (pair === null) throw new Error(errno.EC_PUBLIC_KEY_PARSE_FAIL)

	tweak = new BN(tweak)
	if (tweak.cmp(ecparams.n) >= 0 || tweak.isZero()) 
		throw new Error(errno.EC_PUBLIC_KEY_TWEAK_MUL_FAIL)

	return Buffer.from(pair.pub.mul(tweak).encode(true, compressed))
}

exports.publicKeyCombine = function (publicKeys, compressed) {
	var pairs = new Array(publicKeys.length)
	for (var i = 0; i < publicKeys.length; ++i) {
		pairs[i] = loadPublicKey(publicKeys[i])
		if (pairs[i] === null) throw new Error(errno.EC_PUBLIC_KEY_PARSE_FAIL)
	}

	var point = pairs[0].pub
	for (var j = 1; j < pairs.length; ++j) point = point.add(pairs[j].pub)
	if (point.isInfinity()) throw new Error(errno.EC_PUBLIC_KEY_COMBINE_FAIL)

	return Buffer.from(point.encode(true, compressed))
}

exports.signatureNormalize = function (signature) {
	var r = new BN(signature.slice(0, 32))
	var s = new BN(signature.slice(32, 64))
	if (r.cmp(ecparams.n) >= 0 || s.cmp(ecparams.n) >= 0) 
		throw new Error(errno.ECDSA_SIGNATURE_PARSE_FAIL)

	var result = Buffer.from(signature)
	if (s.cmp(ec.nh) === 1) ecparams.n.sub(s).toArrayLike(Buffer, 'be', 32).copy(result, 32)

	return result
}

exports.signatureExport = function (signature) {
	var r = signature.slice(0, 32)
	var s = signature.slice(32, 64)
	if (new BN(r).cmp(ecparams.n) >= 0 || new BN(s).cmp(ecparams.n) >= 0)
		throw new Error(errno.ECDSA_SIGNATURE_PARSE_FAIL)

	return { r: r, s: s }
}

exports.signatureImport = function (sigObj) {
	var r = new BN(sigObj.r)
	if (r.cmp(ecparams.n) >= 0) r = new BN(0)

	var s = new BN(sigObj.s)
	if (s.cmp(ecparams.n) >= 0) s = new BN(0)

	return Buffer.concat([
		r.toArrayLike(Buffer, 'be', 32),
		s.toArrayLike(Buffer, 'be', 32)
	])
}

exports.sign = function (message, privateKey, noncefn, data) {
	if (typeof noncefn === 'function') {
		var getNonce = noncefn
		noncefn = function (counter) {
			var nonce = getNonce(message, privateKey, null, data, counter)
			if (/*!Buffer.isBuffer(nonce)*/!(nonce instanceof Uint8Array) || nonce.length !== 32) {
				throw new Error(errno.ECDSA_SIGN_FAIL)
			}
			return new BN(nonce)
		}
	}

	var d = new BN(privateKey)
	if (d.cmp(ecparams.n) >= 0 || d.isZero()) throw new Error(errno.ECDSA_SIGN_FAIL)

	var result = ec.sign(message, privateKey, { canonical: true, k: noncefn, pers: data })
	return {
		signature: Buffer.concat([
			result.r.toArrayLike(Buffer, 'be', 32),
			result.s.toArrayLike(Buffer, 'be', 32)
		]),
		recovery: result.recoveryParam
	}
}

exports.verify = function (message, signature, publicKey, canonical) {
	var sigObj = {r: signature.slice(0, 32), s: signature.slice(32, 64)}

	var sigr = new BN(sigObj.r)
	var sigs = new BN(sigObj.s)
	if (sigr.cmp(ecparams.n) >= 0 || sigs.cmp(ecparams.n) >= 0) 
		throw new Error(errno.ECDSA_SIGNATURE_PARSE_FAIL)

	if (sigr.isZero() || sigs.isZero()) return false

	if (canonical && sigs.cmp(ec.nh) === 1)
		return false;

	var pair = loadPublicKey(publicKey)
	if (pair === null) throw new Error(errno.EC_PUBLIC_KEY_PARSE_FAIL)

	return ec.verify(message, sigObj, {x: pair.pub.x, y: pair.pub.y})
}

exports.recover = function (message, signature, recovery, compressed) {
	var sigObj = {r: signature.slice(0, 32), s: signature.slice(32, 64)}

	var sigr = new BN(sigObj.r)
	var sigs = new BN(sigObj.s)
	if (sigr.cmp(ecparams.n) >= 0 || sigs.cmp(ecparams.n) >= 0) 
		throw new Error(errno.ECDSA_SIGNATURE_PARSE_FAIL)

	try {
		if (sigr.isZero() || sigs.isZero()) throw new Error()

		var point = ec.recoverPubKey(message, sigObj, recovery)
		return Buffer.from(point.encode(true, compressed))
	} catch (err) {
		throw new Error(errno.ECDSA_RECOVER_FAIL)
	}
}

exports.getKeyRecoveryParam = function(message, signature, publicKey) {
	var pair = loadPublicKey(publicKey)
	if (pair === null) throw new Error(errno.EC_PUBLIC_KEY_PARSE_FAIL)
	keyPair.getPublic('binify');
	return ec.getKeyRecoveryParam(message, {r: signature.slice(0, 32),s: signature.slice(32, 64)}, pair.pub);
};

exports.ecdh = function (publicKey, privateKey) {
	var shared = exports.ecdhUnsafe(publicKey, privateKey, true);
	if (crypto) {
		return crypto.createHash('sha256').update(shared).digest();
	} else {
		return new Buffer.from(hash_js.sha256().update(shared).digest());
	}
}

exports.ecdhUnsafe = function (publicKey, privateKey, compressed) {
	var pair = loadPublicKey(publicKey)
	if (pair === null) throw new Error(errno.EC_PUBLIC_KEY_PARSE_FAIL)

	var scalar = new BN(privateKey)
	if (scalar.cmp(ecparams.n) >= 0 || scalar.isZero()) throw new Error(errno.ECDH_FAIL)

	return Buffer.from(pair.pub.mul(scalar).encode(true, compressed))
}
