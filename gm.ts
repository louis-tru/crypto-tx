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
import {sm2} from './ec';
import {genPrivateKey} from './account';
import { BigInteger } from 'jsbn';
import errno from './errno';
import * as assert from './assert';

const sm2_N = new BigInteger(sm2.ec.curve.n.toString(), 10);

function genRandomPoint() {
	const k = genPrivateKey();
	const KeyPair = sm2.ec.keyFromPrivate(k);
	const x1 = KeyPair.getPublic().getX();
	return {
		k: new BigInteger(k.toString('hex'), 16),
		x1: new BigInteger(x1.toString(), 10),
	};
}

export function sign(msg: Buffer, privateKey: Buffer) {
	assert.isBuffer(msg, errno.MSG32_TYPE_INVALID)
	assert.isBufferLength(msg, 32, errno.MSG32_LENGTH_INVALID)

	assert.isBuffer(privateKey, errno.EC_PRIVATE_KEY_TYPE_INVALID)
	assert.isBufferLength(privateKey, 32, errno.EC_PRIVATE_KEY_LENGTH_INVALID)

	const dA = new BigInteger(privateKey.toString('hex'), 16)
	const e = new BigInteger(msg.toString('hex'), 16)
	// k
	let k = null
	let r = null
	let s = null

	do {
		do {
			let point = genRandomPoint();
			k = point.k
			// r = (e + x1) mod n
			r = e.add(point.x1).mod(sm2_N)
		} while (r.equals(BigInteger.ZERO) || r.add(k).equals(sm2_N))
		// s = ((1 + dA)^-1 * (k - r * dA)) mod n
		s = dA.add(BigInteger.ONE).modInverse(sm2_N).multiply(k.subtract(r.multiply(dA))).mod(sm2_N);
	} while (s.equals(BigInteger.ZERO));

	// asn.1 der 编码 sign
	var [r1, s1] = [r,s].map(e=>{
		let h = e.toString(16);
		if (h.length % 2 === 1)
			h = '0' + h; // 补齐到整字节
		else if (!h.match(/^[0-7]/))
			h = '00' + h; // 非0开头，则补一个全0字节
		return '02' + (h.length / 2).toString(16) + h;
	});
	const sign = '30' + ((r1.length + s1.length) / 2).toString(16) + r1 + s1;

	return sign;
}
