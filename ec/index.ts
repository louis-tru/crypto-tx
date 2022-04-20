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

import * as assert from '../assert';
import {Buffer} from 'somes/buffer';
import * as der from './der';
import errno from '../errno';
import * as rng from 'somes/rng';
import {EC} from './ec';
import {curves} from 'elliptic';
import {sm2p256v1} from './sm2';

function initCompressedValue (value?: boolean, defaultValue?: any) {
	if (value === undefined)
		return defaultValue;
	assert.isBoolean(value, errno.COMPRESSED_TYPE_INVALID);
	return value;
}

export class SafeEC {
	readonly ec: EC;

	constructor(ec: EC) {
		this.ec = ec
	}

	privateKeyVerify(privateKey: Buffer) {
		assert.isBuffer(privateKey, errno.EC_PRIVATE_KEY_TYPE_INVALID)
		return privateKey.length === 32 && this.ec.privateKeyVerify(privateKey)
	}

	privateKeyExport(privateKey: Buffer, compressed = true) {
		assert.isBuffer(privateKey, errno.EC_PRIVATE_KEY_TYPE_INVALID)
		assert.isBufferLength(privateKey, 32, errno.EC_PRIVATE_KEY_LENGTH_INVALID)

		compressed = initCompressedValue(compressed, true)
		var publicKey = this.ec.privateKeyExport(privateKey, compressed)

		return der.privateKeyExport(privateKey, publicKey, compressed)
	}

	privateKeyImport(privateKey: Buffer) {
		assert.isBuffer(privateKey, errno.EC_PRIVATE_KEY_TYPE_INVALID)

		var privKey = der.privateKeyImport(privateKey)
		if (privKey && privKey.length === 32 && this.ec.privateKeyVerify(privKey)) {
			return privKey
		}
		throw new Error(errno.EC_PRIVATE_KEY_IMPORT_DER_FAIL)
	}

	privateKeyNegate(privateKey: Buffer) {
		assert.isBuffer(privateKey, errno.EC_PRIVATE_KEY_TYPE_INVALID)
		assert.isBufferLength(privateKey, 32, errno.EC_PRIVATE_KEY_LENGTH_INVALID)

		return this.ec.privateKeyNegate(privateKey)
	}

	privateKeyModInverse(privateKey: Buffer) {
		assert.isBuffer(privateKey, errno.EC_PRIVATE_KEY_TYPE_INVALID)
		assert.isBufferLength(privateKey, 32, errno.EC_PRIVATE_KEY_LENGTH_INVALID)

		return this.ec.privateKeyModInverse(privateKey)
	}

	privateKeyTweakAdd(privateKey: Buffer, tweak: Buffer) {
		assert.isBuffer(privateKey, errno.EC_PRIVATE_KEY_TYPE_INVALID)
		assert.isBufferLength(privateKey, 32, errno.EC_PRIVATE_KEY_LENGTH_INVALID)

		assert.isBuffer(tweak, errno.TWEAK_TYPE_INVALID)
		assert.isBufferLength(tweak, 32, errno.TWEAK_LENGTH_INVALID)

		return this.ec.privateKeyTweakAdd(privateKey, tweak)
	}

	privateKeyTweakMul(privateKey: Buffer, tweak: Buffer) {
		assert.isBuffer(privateKey, errno.EC_PRIVATE_KEY_TYPE_INVALID)
		assert.isBufferLength(privateKey, 32, errno.EC_PRIVATE_KEY_LENGTH_INVALID)

		assert.isBuffer(tweak, errno.TWEAK_TYPE_INVALID)
		assert.isBufferLength(tweak, 32, errno.TWEAK_LENGTH_INVALID)

		return this.ec.privateKeyTweakMul(privateKey, tweak)
	}

	publicKeyCreate(privateKey: Buffer, compressed = true) {
		assert.isBuffer(privateKey, errno.EC_PRIVATE_KEY_TYPE_INVALID)
		assert.isBufferLength(privateKey, 32, errno.EC_PRIVATE_KEY_LENGTH_INVALID)

		compressed = initCompressedValue(compressed, true)

		return this.ec.publicKeyCreate(privateKey, compressed)
	}

	publicKeyConvert(publicKey: Buffer, compressed = true) {
		assert.isBuffer(publicKey, errno.EC_PUBLIC_KEY_TYPE_INVALID)
		assert.isBufferLength2(publicKey, 33, 65, errno.EC_PUBLIC_KEY_LENGTH_INVALID)

		compressed = initCompressedValue(compressed, true)

		return this.ec.publicKeyConvert(publicKey, compressed)
	}

	publicKeyVerify(publicKey: Buffer) {
		assert.isBuffer(publicKey, errno.EC_PUBLIC_KEY_TYPE_INVALID)
		return this.ec.publicKeyVerify(publicKey)
	}

	publicKeyTweakAdd(publicKey: Buffer, tweak: Buffer, compressed = true) {
		assert.isBuffer(publicKey, errno.EC_PUBLIC_KEY_TYPE_INVALID)
		assert.isBufferLength2(publicKey, 33, 65, errno.EC_PUBLIC_KEY_LENGTH_INVALID)

		assert.isBuffer(tweak, errno.TWEAK_TYPE_INVALID)
		assert.isBufferLength(tweak, 32, errno.TWEAK_LENGTH_INVALID)

		compressed = initCompressedValue(compressed, true)

		return this.ec.publicKeyTweakAdd(publicKey, tweak, compressed)
	}

	publicKeyTweakMul(publicKey: Buffer, tweak: Buffer, compressed = true) {
		assert.isBuffer(publicKey, errno.EC_PUBLIC_KEY_TYPE_INVALID)
		assert.isBufferLength2(publicKey, 33, 65, errno.EC_PUBLIC_KEY_LENGTH_INVALID)

		assert.isBuffer(tweak, errno.TWEAK_TYPE_INVALID)
		assert.isBufferLength(tweak, 32, errno.TWEAK_LENGTH_INVALID)

		compressed = initCompressedValue(compressed, true)

		return this.ec.publicKeyTweakMul(publicKey, tweak, compressed)
	}

	publicKeyCombine(publicKeys: Buffer[], compressed = true) {
		assert.isArray(publicKeys, errno.EC_PUBLIC_KEYS_TYPE_INVALID)
		assert.isLengthGTZero(publicKeys, errno.EC_PUBLIC_KEYS_LENGTH_INVALID)
		for (var i = 0; i < publicKeys.length; ++i) {
			assert.isBuffer(publicKeys[i], errno.EC_PUBLIC_KEY_TYPE_INVALID)
			assert.isBufferLength2(publicKeys[i], 33, 65, errno.EC_PUBLIC_KEY_LENGTH_INVALID)
		}

		compressed = initCompressedValue(compressed, true)

		return this.ec.publicKeyCombine(publicKeys, compressed)
	}

	signatureNormalize(signature: Buffer) {
		assert.isBuffer(signature, errno.ECDSA_SIGNATURE_TYPE_INVALID)
		assert.isBufferLength(signature, 64, errno.ECDSA_SIGNATURE_LENGTH_INVALID)

		return this.ec.signatureNormalize(signature)
	}

	signatureExport(signature: Buffer) {
		assert.isBuffer(signature, errno.ECDSA_SIGNATURE_TYPE_INVALID)
		assert.isBufferLength(signature, 64, errno.ECDSA_SIGNATURE_LENGTH_INVALID)

		var sigObj = this.ec.signatureExport(signature)
		return der.signatureExport(sigObj)
	}

	signatureImport(sig: Buffer) {
		assert.isBuffer(sig, errno.ECDSA_SIGNATURE_TYPE_INVALID)
		assert.isLengthGTZero(sig, errno.ECDSA_SIGNATURE_LENGTH_INVALID)

		var sigObj = der.signatureImport(sig)
		if (sigObj) return this.ec.signatureImport(sigObj)

		throw new Error(errno.ECDSA_SIGNATURE_PARSE_DER_FAIL)
	}

	signatureImportLax(sig: Buffer) {
		assert.isBuffer(sig, errno.ECDSA_SIGNATURE_TYPE_INVALID)
		assert.isLengthGTZero(sig, errno.ECDSA_SIGNATURE_LENGTH_INVALID)

		var sigObj = der.signatureImportLaxexport(sig)
		if (sigObj) return this.ec.signatureImport(sigObj)

		throw new Error(errno.ECDSA_SIGNATURE_PARSE_DER_FAIL)
	}

	sign(message: Buffer, privateKey: Buffer, options?: { noncefn?: (()=>Buffer)|null, data?: Buffer }) {
		assert.isBuffer(message, errno.MSG32_TYPE_INVALID)
		assert.isBufferLength(message, 32, errno.MSG32_LENGTH_INVALID)

		assert.isBuffer(privateKey, errno.EC_PRIVATE_KEY_TYPE_INVALID)
		assert.isBufferLength(privateKey, 32, errno.EC_PRIVATE_KEY_LENGTH_INVALID)

		var data;
		var noncefn = function() { return rng.rng(32) };
		if (options !== undefined) {
			assert.isObject(options, errno.OPTIONS_TYPE_INVALID)

			if (options.data !== undefined) {
				assert.isBuffer(options.data, errno.OPTIONS_DATA_TYPE_INVALID)
				assert.isBufferLength(options.data, 32, errno.OPTIONS_DATA_LENGTH_INVALID)
				data = options.data
			}

			if (options.noncefn !== undefined) {
				if (options.noncefn) {
					assert.isFunction(options.noncefn, errno.OPTIONS_NONCEFN_TYPE_INVALID)
					noncefn = options.noncefn
				} else {
					(noncefn as any) = null;
				}
			}
		}

		return this.ec.sign2(message, privateKey, noncefn, data);
	}

	verify(message: Buffer, signature: Buffer, publicKey: Buffer, canonical = false) {
		assert.isBuffer(message, errno.MSG32_TYPE_INVALID)
		assert.isBufferLength(message, 32, errno.MSG32_LENGTH_INVALID)

		assert.isBuffer(signature, errno.ECDSA_SIGNATURE_TYPE_INVALID)
		assert.isBufferLength(signature, 64, errno.ECDSA_SIGNATURE_LENGTH_INVALID)

		assert.isBuffer(publicKey, errno.EC_PUBLIC_KEY_TYPE_INVALID)
		assert.isBufferLength2(publicKey, 33, 65, errno.EC_PUBLIC_KEY_LENGTH_INVALID)

		return this.ec.verifySign(message, signature, publicKey, canonical)
	}

	recover(message: Buffer, signature: Buffer, recovery: number, compressed = true) {
		assert.isBuffer(message, errno.MSG32_TYPE_INVALID)
		assert.isBufferLength(message, 32, errno.MSG32_LENGTH_INVALID)

		assert.isBuffer(signature, errno.ECDSA_SIGNATURE_TYPE_INVALID)
		assert.isBufferLength(signature, 64, errno.ECDSA_SIGNATURE_LENGTH_INVALID)

		assert.isNumber(recovery, errno.RECOVERY_ID_TYPE_INVALID)
		assert.isNumberInInterval(recovery, -1, 4, errno.RECOVERY_ID_VALUE_INVALID)

		compressed = initCompressedValue(compressed, true)

		return this.ec.recover(message, signature, recovery, compressed)
	}

	ecdh(publicKey: Buffer, privateKey: Buffer) {
		assert.isBuffer(publicKey, errno.EC_PUBLIC_KEY_TYPE_INVALID)
		assert.isBufferLength2(publicKey, 33, 65, errno.EC_PUBLIC_KEY_LENGTH_INVALID)

		assert.isBuffer(privateKey, errno.EC_PRIVATE_KEY_TYPE_INVALID)
		assert.isBufferLength(privateKey, 32, errno.EC_PRIVATE_KEY_LENGTH_INVALID)

		return this.ec.ecdh(publicKey, privateKey)
	}

	ecdhUnsafe(publicKey: Buffer, privateKey: Buffer, compressed = true) {
		assert.isBuffer(publicKey, errno.EC_PUBLIC_KEY_TYPE_INVALID)
		assert.isBufferLength2(publicKey, 33, 65, errno.EC_PUBLIC_KEY_LENGTH_INVALID)

		assert.isBuffer(privateKey, errno.EC_PRIVATE_KEY_TYPE_INVALID)
		assert.isBufferLength(privateKey, 32, errno.EC_PRIVATE_KEY_LENGTH_INVALID)

		compressed = initCompressedValue(compressed, true)

		return this.ec.ecdhUnsafe(publicKey, privateKey, compressed)
	}
}

export const k1 = new SafeEC(new EC('secp256k1'));
export const sm2 = new SafeEC(new EC(new curves.PresetCurve(sm2p256v1)));

export default k1;