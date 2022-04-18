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

import utils from 'somes';
import buffer, {Buffer} from 'somes/buffer';
import * as BN from 'bn.js';
import {ec as ECBase, curves} from 'elliptic';
import errno from '../errno';

if (utils.haveNode) {
	var crypto = require('crypto');
} else {
	var hash_js = require('hash.js');
}

function loadCompressedPublicKey(self: EC, first: number, xBuffer: Buffer) {
	let _x = new BN(xBuffer)

	// overflow
	if (_x.cmp(self.curve.p) >= 0) return null;
	let x = _x.toRed(self.curve.red);

	// compute corresponding Y
	var y = x.redSqr().redIMul(x).redIAdd(self.curve.b).redSqrt()
	if ((first === 0x03) !== y.isOdd()) y = y.redNeg()

	return self.keyPair({ pub: { x, y } as any })
}

function loadUncompressedPublicKey(self: EC, first: number, xBuffer: Buffer, yBuffer: Buffer) {
	let _x = new BN(xBuffer)
	let _y = new BN(yBuffer)

	// overflow
	if (_x.cmp(self.curve.p) >= 0 || _y.cmp(self.curve.p) >= 0) return null

	let x = _x.toRed(self.curve.red)
	let y = _y.toRed(self.curve.red)

	// is odd flag
	if ((first === 0x06 || first === 0x07) && y.isOdd() !== (first === 0x07)) return null

	// x*x*x + b = y*y
	var x3 = x.redSqr().redIMul(x)
	if (!y.redSqr().redISub(x3.redIAdd(self.curve.b)).isZero()) return null

	return self.keyPair({ pub: { x, y } as any })
}

function loadPublicKey(self: EC, publicKey: Buffer) {
	var first = publicKey[0]
	switch (first) {
		case 0x02:
		case 0x03:
			if (publicKey.length !== 33) return null
			return loadCompressedPublicKey(self, first, publicKey.slice(1, 33))
		case 0x04:
		case 0x06:
		case 0x07:
			if (publicKey.length !== 65) return null
			return loadUncompressedPublicKey(self, first, publicKey.slice(1, 33), publicKey.slice(33, 65))
		default:
			return null
	}
}

export interface Signature {
	r: Buffer;
	s: Buffer;
}

type noncefn = (message: Buffer, privateKey: Buffer, a: any, data: Buffer | undefined, counter: number)=>Buffer;

export class EC extends ECBase {

	constructor(options: string | curves.PresetCurve) {
		super(options)
	}

	privateKeyVerify(privateKey: Buffer) {
		var bn = new BN(privateKey)
		return bn.cmp(this.curve.n) < 0 && !bn.isZero()
	}

	privateKeyExport(privateKey: Buffer, compressed = true) {
		var d = new BN(privateKey)
		if (d.cmp(this.curve.n) >= 0 || d.isZero()) throw new Error(errno.EC_PRIVATE_KEY_EXPORT_DER_FAIL)

		return buffer.from(this.keyFromPrivate(privateKey).getPublic(compressed, 'array'))
	}

	privateKeyNegate(privateKey: Buffer) {
		var bn = new BN(privateKey)
		return bn.isZero() ? buffer.alloc(32) : 
			buffer.from(this.curve.n.sub(bn).umod(this.curve.n).toArrayLike(Uint8Array as any, 'be', 32));
	}

	privateKeyModInverse(privateKey: Buffer) {
		var bn = new BN(privateKey)
		if (bn.cmp(this.curve.n) >= 0 || bn.isZero()) throw new Error(errno.EC_PRIVATE_KEY_RANGE_INVALID)

		return buffer.from(bn.invm(this.curve.n).toArrayLike(Uint8Array as any, 'be', 32));
	}

	privateKeyTweakAdd(privateKey: Buffer, tweak: Buffer) {
		var bn = new BN(tweak)
		if (bn.cmp(this.curve.n) >= 0) throw new Error(errno.EC_PRIVATE_KEY_TWEAK_ADD_FAIL)

		bn.iadd(new BN(privateKey))
		if (bn.cmp(this.curve.n) >= 0) bn.isub(this.curve.n)
		if (bn.isZero()) throw new Error(errno.EC_PRIVATE_KEY_TWEAK_ADD_FAIL)

		return buffer.from(bn.toArrayLike(Uint8Array as any, 'be', 32));
	}

	privateKeyTweakMul(privateKey: Buffer, tweak: Buffer) {
		var bn = new BN(tweak)
		if (bn.cmp(this.curve.n) >= 0 || bn.isZero()) throw new Error(errno.EC_PRIVATE_KEY_TWEAK_MUL_FAIL)

		bn.imul(new BN(privateKey))
		if (bn.cmp(this.curve.n)) bn = bn.umod(this.curve.n)

		return buffer.from(bn.toArrayLike(Uint8Array as any, 'be', 32));
	}

	publicKeyCreate(privateKey: Buffer, compressed: boolean) {
		var d = new BN(privateKey)
		if (d.cmp(this.curve.n) >= 0 || d.isZero()) throw new Error(errno.EC_PUBLIC_KEY_CREATE_FAIL)

		return buffer.from(this.keyFromPrivate(privateKey).getPublic(compressed, 'array'))
	}

	publicKeyConvert(publicKey: Buffer, compressed = true) {
		var pair = loadPublicKey(this, publicKey)
		if (pair === null) throw new Error(errno.EC_PUBLIC_KEY_PARSE_FAIL)

		return buffer.from(pair.getPublic(compressed, 'array'))
	}

	publicKeyVerify(publicKey: Buffer) {
		return loadPublicKey(this, publicKey) !== null
	}

	publicKeyTweakAdd(publicKey: Buffer, _tweak: Buffer, compressed = true) {
		var pair = loadPublicKey(this, publicKey)
		if (pair === null) throw new Error(errno.EC_PUBLIC_KEY_PARSE_FAIL)

		let tweak = new BN(_tweak)
		if (tweak.cmp(this.curve.n) >= 0) throw new Error(errno.EC_PUBLIC_KEY_TWEAK_ADD_FAIL)

		return buffer.from(this.curve.g.mul(tweak).add(pair.getPublic()).encode('array', compressed))
	}

	publicKeyTweakMul(publicKey: Buffer, _tweak: Buffer, compressed = true) {
		var pair = loadPublicKey(this, publicKey)
		if (pair === null) throw new Error(errno.EC_PUBLIC_KEY_PARSE_FAIL)

		let tweak = new BN(_tweak)
		if (tweak.cmp(this.curve.n) >= 0 || tweak.isZero()) 
			throw new Error(errno.EC_PUBLIC_KEY_TWEAK_MUL_FAIL)

		return buffer.from(pair.getPublic().mul(tweak).encode('array', compressed))
	}

	publicKeyCombine(publicKeys: Buffer[], compressed = true) {
		var pairs = new Array(publicKeys.length)
		for (var i = 0; i < publicKeys.length; ++i) {
			pairs[i] = loadPublicKey(this, publicKeys[i])
			if (pairs[i] === null) throw new Error(errno.EC_PUBLIC_KEY_PARSE_FAIL)
		}

		var point = pairs[0].pub
		for (var j = 1; j < pairs.length; ++j) point = point.add(pairs[j].pub)
		if (point.isInfinity()) throw new Error(errno.EC_PUBLIC_KEY_COMBINE_FAIL)

		return buffer.from(point.encode(true, compressed))
	}

	signatureNormalize(signature: Buffer) {
		var r = new BN(signature.slice(0, 32))
		var s = new BN(signature.slice(32, 64))
		if (r.cmp(this.curve.n) >= 0 || s.cmp(this.curve.n) >= 0) 
			throw new Error(errno.ECDSA_SIGNATURE_PARSE_FAIL)

		var result = buffer.from(signature)
		if (s.cmp(this.nh) === 1) 
			this.curve.n.sub(s).toArrayLike(Uint8Array, 'be', 32).copy(result, 32)

		return result
	}

	signatureExport(signature: Buffer) {
		var r = signature.slice(0, 32)
		var s = signature.slice(32, 64)
		if (new BN(r).cmp(this.curve.n) >= 0 || new BN(s).cmp(this.curve.n) >= 0)
			throw new Error(errno.ECDSA_SIGNATURE_PARSE_FAIL)

		return { r: r, s: s }
	}

	signatureImport(sigObj: Signature) {
		var r = new BN(sigObj.r)
		if (r.cmp(this.curve.n) >= 0) r = new BN(0)

		var s = new BN(sigObj.s)
		if (s.cmp(this.curve.n) >= 0) s = new BN(0)

		return buffer.concat([
			buffer.from(r.toArrayLike(Uint8Array as any, 'be', 32)),
			buffer.from(s.toArrayLike(Uint8Array as any, 'be', 32))
		])
	}

	sign2(message: Buffer, privateKey: Buffer, noncefn?: noncefn, data?: Buffer)
	{
		var k = null;
		if (typeof noncefn === 'function') {
			k = function (counter: number) {
				var nonce = noncefn(message, privateKey, null, data, counter)
				if (!(nonce instanceof Uint8Array) || nonce.length !== 32) {
					throw new Error(errno.ECDSA_SIGN_FAIL)
				}
				return new BN(nonce);
			}
		}

		var d = new BN(privateKey)
		if (d.cmp(this.curve.n) >= 0 || d.isZero()) throw new Error(errno.ECDSA_SIGN_FAIL)

		var result = super.sign(message, privateKey as any, { canonical: true, k: k as any, pers: data });
		return {
			signature: buffer.concat([
				buffer.from(result.r.toArrayLike(Uint8Array as any, 'be', 32)),
				buffer.from(result.s.toArrayLike(Uint8Array as any, 'be', 32))
			]),
			recovery: result.recoveryParam as number
		}
	}

	verifySign(message: Buffer, signature: Buffer, publicKey: Buffer, canonical = true) {
		var sigObj = {r: signature.slice(0, 32), s: signature.slice(32, 64)}

		var sigr = new BN(sigObj.r)
		var sigs = new BN(sigObj.s)
		if (sigr.cmp(this.curve.n) >= 0 || sigs.cmp(this.curve.n) >= 0) 
			throw new Error(errno.ECDSA_SIGNATURE_PARSE_FAIL)

		if (sigr.isZero() || sigs.isZero()) return false

		if (canonical && sigs.cmp(this.nh) === 1)
			return false;

		var pair = loadPublicKey(this, publicKey)
		if (pair === null) throw new Error(errno.EC_PUBLIC_KEY_PARSE_FAIL)

		return super.verify(message, sigObj, pair);
	}

	recover(message: Buffer, signature: Buffer, recovery: number, compressed = true) {
		var sigObj = {r: signature.slice(0, 32), s: signature.slice(32, 64)}

		var sigr = new BN(sigObj.r)
		var sigs = new BN(sigObj.s)
		if (sigr.cmp(this.curve.n) >= 0 || sigs.cmp(this.curve.n) >= 0) 
			throw new Error(errno.ECDSA_SIGNATURE_PARSE_FAIL)

		try {
			if (sigr.isZero() || sigs.isZero()) throw new Error()

			var point = this.recoverPubKey(message, sigObj, recovery)
			return buffer.from(point.encode('array', compressed))
		} catch (err) {
			throw new Error(errno.ECDSA_RECOVER_FAIL)
		}
	}

	getKeyRecoveryParam2(message: Buffer, signature: Buffer, publicKey: Buffer) {
		var pair = loadPublicKey(this, publicKey)
		if (pair === null) throw new Error(errno.EC_PUBLIC_KEY_PARSE_FAIL)
		var r = signature.slice(0, 32);
		var s = signature.slice(32, 64);
		var pub = new BN(pair.getPublic('array'));
		return super.getKeyRecoveryParam(message as any, {r, s}, pub);
	};

	ecdh(publicKey: Buffer, privateKey: Buffer) {
		var shared = this.ecdhUnsafe(publicKey, privateKey, true);
		if (crypto) {
			return crypto.createHash('sha256').update(shared).digest();
		} else {
			return buffer.from(hash_js.sha256().update(shared).digest());
		}
	}

	ecdhUnsafe(publicKey: Buffer, privateKey: Buffer, compressed = true) {
		var pair = loadPublicKey(this, publicKey)
		if (pair === null) throw new Error(errno.EC_PUBLIC_KEY_PARSE_FAIL)

		var scalar = new BN(privateKey)
		if (scalar.cmp(this.curve.n) >= 0 || scalar.isZero()) throw new Error(errno.ECDH_FAIL);

		return buffer.from(pair.getPublic().mul(scalar).encode('array', compressed))
	}

}