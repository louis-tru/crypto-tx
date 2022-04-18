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
import uuid from 'somes/hash/uuid';
import * as scrypt from 'scrypt-js';
import * as assert from './assert';
import * as keccak from './keccak';
import buffer, {Buffer} from 'somes/buffer';
import * as account from './account';
import * as utils from './utils';

if (somes.haveNode) {
	var cryp = require('crypto');
} else {
	var cryp = require('crypto-browserify'); // TODO
}

//import * as crypt from 'crypto';

export interface EncryptOptions {
	kdf?: 'pbkdf2' | 'scrypt',
	dklen?: number,
	salt?: Buffer,
	iv?: Buffer,
	c?: number,
	n?: number,
	r?: number,
	p?: number,
	cipher?: 'aes-128-gcm' | 'aes-192-gcm' | 'aes-256-gcm',
	uuid?: Buffer,
}

export interface Keystore {
	version: number,
	id: string,
	address: string,
	crypto: {
		ciphertext: string,
		cipherparams: {
			iv: string
		},
		cipher: 'aes-128-gcm' | 'aes-192-gcm' | 'aes-256-gcm',
		kdf: 'pbkdf2' | 'scrypt',
		kdfparams: {
			dklen: number,
			salt: string,
			c?: number,
			prf?: 'hmac-sha256',
			// scrypt
			n?: number,
			r?: number,
			p?: number,
		},
		mac: string,
	}
}

export function encryptPrivateKey(privateKey: Buffer, password: string, options?: EncryptOptions) {
	/* jshint maxcomplexity: 20 */

	privateKey = utils.toBuffer(privateKey);
	var publicKey = account.getPublic(privateKey);
	var details = account.publicKeyConvertDetails(publicKey);

	options = options || {};
	var salt = options.salt || account.getRandomValues(32);
	var iv = options.iv || account.getRandomValues(16);

	var derivedKey;
	var kdf = options.kdf || 'scrypt';
	var kdfparams: any = {
		dklen: options.dklen || 32,
		salt: salt.toString('hex'),
		//n: 0, c: 0, prf: '', r: 0, p: 0,
	};

	if (kdf === 'pbkdf2') {
		kdfparams.c = options.c || 262144;
		kdfparams.prf = 'hmac-sha256';
		derivedKey = cryp.pbkdf2Sync(buffer.from(password), buffer.from(kdfparams.salt, 'hex'), kdfparams.c, kdfparams.dklen, 'sha256');
	} else if (kdf === 'scrypt') {
		// FIXME: support progress reporting callback
		kdfparams.n = options.n || 8192; // 2048 4096 8192 16384
		kdfparams.r = options.r || 8;
		kdfparams.p = options.p || 1;
		derivedKey = scrypt.syncScrypt(buffer.from(password), buffer.from(kdfparams.salt, 'hex'), kdfparams.n, kdfparams.r, kdfparams.p, kdfparams.dklen);
	} else {
		throw new Error('Unsupported kdf');
	}

	derivedKey = buffer.from(derivedKey);

	var cipher = cryp.createCipheriv(options.cipher || 'aes-128-ctr', derivedKey.slice(0, 16), iv);
	if (!cipher) {
		throw new Error('Unsupported cipher');
	}

	var ciphertext = buffer.concat([cipher.update(privateKey), cipher.final()]);

	var mac = keccak.keccak(buffer.concat([derivedKey.slice(16, 32), ciphertext])).hex.replace('0x', '');

	return {
		version: 3,
		id: uuid(options.uuid || cryp.randomBytes(16)),
		address: details.addressHex,
		crypto: {
			ciphertext: ciphertext.toString('hex'),
			cipherparams: {
				iv: iv.toString('hex')
			},
			cipher: options.cipher || 'aes-128-ctr',
			kdf: kdf,
			kdfparams: kdfparams,
			mac: mac,
		}
	};
}

export function decryptPrivateKey(keystore_v3: Keystore, password: string) {
	/* jshint maxcomplexity: 10 */

	assert.isString(password, 'No password given.');
	assert.isObject(keystore_v3, 'No v3Keystore given.');

	var json = keystore_v3;

	if (json.version !== 3) {
		throw new Error('Not a valid V3 wallet');
	}

	var derivedKey;
	var kdfparams;
	if (json.crypto.kdf === 'scrypt') {
		kdfparams = json.crypto.kdfparams;

		// FIXME: support progress reporting callback
		derivedKey = scrypt.syncScrypt(buffer.from(password), buffer.from(kdfparams.salt, 'hex'),
			kdfparams.n as number, kdfparams.r as number, kdfparams.p as number, kdfparams.dklen);
	} else if (json.crypto.kdf === 'pbkdf2') {
		kdfparams = json.crypto.kdfparams;

		if (kdfparams.prf !== 'hmac-sha256') {
			throw new Error('Unsupported parameters to PBKDF2');
		}
		derivedKey = cryp.pbkdf2Sync(buffer.from(password), buffer.from(kdfparams.salt, 'hex'), kdfparams.c, kdfparams.dklen, 'sha256');
	} else {
		throw new Error('Unsupported key derivation scheme');
	}

	derivedKey = buffer.from(derivedKey);

	var ciphertext = buffer.from(json.crypto.ciphertext, 'hex');

	var mac = keccak.keccak(buffer.concat([derivedKey.slice(16, 32), ciphertext])).hex.slice(2);
	if (mac !== json.crypto.mac) {
		throw new Error('Key derivation failed - possibly wrong password');
	}

	var decipher = cryp.createDecipheriv(json.crypto.cipher, derivedKey.slice(0, 16), buffer.from(json.crypto.cipherparams.iv, 'hex'));
	var privateKey = buffer.concat([decipher.update(ciphertext), decipher.final()]);

	return privateKey;
}