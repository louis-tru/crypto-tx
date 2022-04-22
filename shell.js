#!/usr/bin/env node
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

var crypto = require('./index');
var assert = require('./assert');
var argument = require('somes/arguments');
var buffer = require('somes/buffer').default;
var toBuffer = require('./utils').toBuffer;
var sign = require('./sign');
var rng = require('somes/rng');
var somes = require('somes').default;
var buffer = require('somes/buffer').default;
var keystore = require('./keystore');
var gm = require('./gm');
var ec = require('./ec');
var btc = require('./btc');
var opts = argument.options;
var help_info = argument.helpInfo;
var def_opts = argument.defOpts;

def_opts(['G'],             0,  '-G          cmd gen private and public keys');
def_opts(['C'],             0,  '-C          cmd convert output public key and address');
def_opts(['F'],             0,  '-F          Format address');
def_opts(['E'],             0,  '-E          cmd encryptECIES');
def_opts(['D'],             0,  '-D          cmd decryptECIES');
def_opts(['S'],             0,  '-S          cmd sign data or hash');
def_opts(['S2'],            0,  '-S2         cmd sign Arguments From Types');
def_opts(['R'],             0,  '-R          cmd recovery public key from signature');
def_opts(['V'],             0,  '-V          cmd verify public key from hash or data');
def_opts(['H'],             0,  '-H          gen data message hash keccak 256');
def_opts(['KS'],            0,  '-KS         export keystore');
def_opts(['k', 'private'], '',  '-private,-k privateKey hex');
def_opts(['p', 'public' ], '',  '-public,-p  publicKey hex');
def_opts(['d', 'data'],    '',  '-data,-d    encrypt or decrypt data');
def_opts(['hash'],         '',  '-hash       length 256 hash data');
def_opts(['sign', 's'],    '',  '-sign,-s    signature 65 bytes rsv or 64 bytes rs hex');
def_opts(['nonce'],        '',  '-nonce      signature 32 bytes hex nonce data or none');
def_opts(['iv'],           '',  '-iv         IV 16 bytes hex');
def_opts(['json'],          0,  '-json       convert output result to json [{0}]');
def_opts(['pwd'],          '',  '-pwd        set keystore pawwdord');

function printHelp(code = -1) {
	process.stdout.write('Usage:\n');
	process.stdout.write('  crypto-tx -G [-json]\n');
	process.stdout.write('  crypto-tx -C -p publicKey [-k privateKey] \n');
	process.stdout.write(
		'  crypto-tx -E '+
		'[-k privateKey] -p publicKeyTo -d originaltext [-iv value] [-json] \n');
	process.stdout.write(
		'  crypto-tx -D '+
		'-k privateKey -p ephemPublicKey -d ciphertext -iv value \n');
	process.stdout.write(
		'  crypto-tx -S -k privateKey -d data [-json] [-nonce hex] \n');
	process.stdout.write(
		'  crypto-tx -S2 -k privateKey -d data:type [-json] [-nonce hex] \n');
	process.stdout.write(
		'  crypto-tx -R -d data:type [-hash message] -sign signature 65 bytes rsv hex [-json] \n');
	process.stdout.write(
		'  crypto-tx -V -d data:type [-hash message] -sign signature 64 bytes rs hex -p publicKey hex [-json] \n');
	process.stdout.write(
		'  crypto-tx -F -d address hex address \n');
	process.stdout.write(
		'  crypto-tx -KS -k privateKey -pwd passwork Export keystore \n');
	process.stdout.write('Options:\n');
	process.stdout.write('  ' + help_info.join('\n  ') + '\n');
	process.exit(code);
}

function message() {
	// var d = data();
	// console.log(d + '')
	return buffer.from(crypto.keccak(data()).data);
}

function data() {
	somes.assert(opts.d, 'bad arg -d data');
	var rawData = Array.isArray(opts.d) ? opts.d: [opts.d];
	var data = rawData.map(e=>e.split(':')[0]);
	var types = rawData.map(e=>e.split(':')[1]);
	return sign.concat(data, types);
}

async function encrypt() {
	if (!opts.p || !opts.d)
		printHelp();

	var privateKey = opts.k ? toBuffer(opts.k): crypto.genPrivateKey();
	var publicKey = crypto.getPublic(privateKey);
	var publicKeyTo = toBuffer(opts.p);
	var originaltext = toBuffer(opts.d);
	// console.log('opts.iv', !!opts.iv)
	var iv = opts.iv ? toBuffer(opts.iv): crypto.getRandomValues(16);

	assert.isBufferLength(privateKey, 32, 'Bad privateKey length');
	assert.isBufferLength2(publicKeyTo, 33, 65, 'Bad ephemPublicKey length');
	assert.isBufferLength(iv, 16, 'Bad iv length Must 128 bit');

	var { mac, ciphertext, iv } = await crypto.encryptECIES(publicKeyTo, originaltext, {
		iv, ephemPrivateKey: privateKey, 
	});

	var result = {
		ciphertext: '0x' + ciphertext.toString('hex'),
		ephemPublicKey: '0x' + publicKey.toString('hex'),
		iv: '0x' + buffer.from(iv).toString('hex'),
		mac: '0x' + mac.toString('hex'),
	};

	if (opts.json) {
		console.log(JSON.stringify(result));
	} else {
		console.log('ciphertext:', result.ciphertext);
		console.log('ephemPublicKey:', result.ephemPublicKey);
		console.log('iv:', result.iv);
		console.log('mac:', result.mac);
	}
}

async function decrypt() {
	if (!opts.p || !opts.d || !opts.k || !opts.iv)
		printHelp();

	var privateKey = toBuffer(opts.k);
	var ephemPublicKey = toBuffer(opts.p);
	var ciphertext = toBuffer(opts.d);
	var iv = toBuffer(opts.iv);

	assert.isBufferLength(privateKey, 32, 'Bad privateKey length');
	assert.isBufferLength2(ephemPublicKey, 33, 65, 'Bad ephemPublicKey length');
	assert.isBufferLength(iv, 16, 'Bad iv length Must 128 bit');

	var r = await crypto.decryptECIES(privateKey, {
		ephemPublicKey, ciphertext, iv,
	});

	console.log('0x' + r.toString('hex'), r + '');
}

function getNonce(opts) {
	var nonce = rng.rng(32);
	var noncefn = function() {
		return nonce
	};
	if (opts.nonce) {
		if (opts.nonce == 'none') {
			nonce = '';
			noncefn = null;
		} else {
			nonce = toBuffer(opts.nonce);
		}
	}
	return {
		nonce: nonce ? '0x' + nonce.toString('hex'): 'none', noncefn,
	};
}

function sign1() {
	if (!opts.k || (!opts.d && !opts.hash))
		printHelp();

	var privateKey = toBuffer(opts.k);
	var data = opts.d ? toBuffer(crypto.keccak(toBuffer(opts.d)).hex): toBuffer(opts.hash);

	assert.isBufferLength(privateKey, 32, 'Bad privateKey length');
	assert.isBufferLength(data, 32, 'Bad data length');

	var {nonce, noncefn} = getNonce(opts);

	var signature = crypto.sign(data, privateKey, {noncefn});
	var signature_buf = buffer.concat([signature.signature, buffer.from([signature.recovery])]);

	if (opts.json) {
		console.log({
			signature: '0x' + signature_buf.toString('hex'),
			nonce: nonce,
			message: '0x' + data.toString('hex'),
		});
	} else {
		console.log('signature: 0x' + signature_buf.toString('hex'));
		console.log('nonce: ' + nonce);
		console.log('message: 0x' + data.toString('hex'));
	}
}

function sign2() {
	if (!opts.k || !opts.d)
		printHelp();

	var rawData = Array.isArray(opts.d) ? opts.d: [opts.d];

	var data = rawData.map(e=>e.split(':')[0]);
	var types = rawData.map(e=>e.split(':')[1]);
	var {nonce, noncefn} = getNonce(opts);
	var rsv = sign.signArgumentsFromTypes(data, types, toBuffer(opts.k), { noncefn });

	if (opts.json) {
		rsv.nonce = nonce;
		console.log(rsv);
	} else {
		console.log('R:', rsv.r);
		console.log('S:', rsv.s);
		console.log('V:', rsv.v);
		console.log('nonce: ', nonce);
		console.log('message: ', rsv.message);
		
		var s = buffer.concat([
			Buffer.from(rsv.r.slice(2) + rsv.s.slice(2), 'hex'), 
			Buffer.from([rsv.v])
		]);
		console.log('sign:', '0x' + s.toString('hex'));
	}
}

function exportKeystore() {
	if (!opts.k || !opts.pwd)
		printHelp();

	var store = keystore.encryptPrivateKey(toBuffer(opts.k), String(opts.pwd));

	console.log(JSON.stringify(store, null, 2));
}

function recovery() {
	// console.log(opts.sign)
	if ((!opts.d && !opts.hash) || !opts.sign)
		printHelp();

	if (opts.d) {
		var msg = message();
	} else {
		var msg = toBuffer(opts.hash);
	}

	var signature = toBuffer(opts.sign);

	// console.log(msg, msg.length, signature.length)

	var public_key = crypto.recover(msg, signature.slice(0, 64), signature[64]);
	var public_key_0 = crypto.publicKeyConvert(public_key);
	var public_key_1 = crypto.publicKeyConvert(public_key, false);
	var address = crypto.publicToAddress(public_key_0);

	if (opts.json) {
		console.log({
			address, 
			publicKey: '0x' + public_key_0.toString('hex'),
			publicKeyLong: '0x' + public_key_1.toString('hex'),
		});
	} else {
		console.log('address:', address);
		console.log('publicKey:', '0x' + public_key_0.toString('hex'));
		console.log('publicKeyLong:', '0x' + public_key_1.toString('hex'));
	}
}

function verify() {
	// console.log(opts.sign)
	if ((!opts.d && !opts.hash) || !opts.sign || !opts.p)
		printHelp();

	if (opts.d) {
		var msg = message();
	} else {
		var msg = toBuffer(opts.hash);
	}

	var signature = toBuffer(opts.sign);
	var publicKey = toBuffer(opts.p);

	// console.log(msg.length, signature.length, publicKey.length);

	// (message, signature, publicKey)
	var ok = crypto.verify(msg, signature, publicKey);

	console.log(ok);
}

function format() {
	if (!opts.d) {
		printHelp();
	} else {
		var address = '0x' + crypto.toChecksumAddress(Buffer.from(opts.d.slice(2), 'hex'));
		console.log(address);
	}
}

async function main() {

	if (opts.E) {
		await encrypt();
	} else if (opts.D) {
		await decrypt();
	} else if (opts.G) {
		if (opts.k) {
			var privateKey = toBuffer(opts.k);
			assert.isBufferLength(privateKey, 32, 'Bad privateKey length');
		} else {
			var privateKey = crypto.genPrivateKey();
		}
		var nonce = rng.rng(32);
		var publicKey_0 = crypto.getPublic(privateKey, true);
		var publicKey_1 = crypto.getPublic(privateKey, false);
		var result = {
			private: privateKey.toString('base64'),
			privateKey: '0x' + privateKey.toString('hex'),
			publicKey: '0x' + publicKey_0.toString('hex'),
			publicKey1: '0x' + publicKey_1.toString('hex'),
			address: crypto.publicToAddress(publicKey_0),
			nonce: '0x' + nonce.toString('hex'),
			K1Key: gm.keyToString(privateKey, 'K1', 'PVT_K1_'),
			K1Pub: gm.keyToString(ec.k1.publicKeyCreate(privateKey), 'K1', 'PUB_K1_'),
			GMKey: gm.keyToString(privateKey, 'GM', 'PVT_GM_'),
			GMPub: gm.keyToString(ec.sm2.publicKeyCreate(privateKey), 'GM', 'PUB_GM_'),
			btcWIFKey: btc.getWIFKey(privateKey).toString('base58'),
			addressBtc: btc.getAddressFromPrivateKey(privateKey).toString('base58'),
		};
		if (opts.json) {
			console.log(JSON.stringify(result));
		} else {
			console.log('private:   ', result.private);
			console.log('privateKey:', result.privateKey);
			console.log('publicKey: ', result.publicKey);
			console.log('publicKey1:', result.publicKey1);
			console.log('address:   ', result.address);
			console.log('nonce:', result.nonce);
			console.log('K1Key:', gm.keyToString(privateKey, 'K1', 'PVT_K1_'));
			console.log('K1Pub:', gm.keyToString(ec.k1.publicKeyCreate(privateKey), 'K1', 'PUB_K1_'));
			console.log('GMKey:', gm.keyToString(privateKey, 'GM', 'PVT_GM_'));
			console.log('GMPub:', gm.keyToString(ec.sm2.publicKeyCreate(privateKey), 'GM', 'PUB_GM_'));
			console.log('btcWIFKey: ', btc.getWIFKey(privateKey).toString('base58'));
			console.log('btcAddress:', btc.getAddressFromPrivateKey(privateKey).toString('base58'));
		}
	} else if (opts.C) {
		if (!opts.p && !opts.k)
			printHelp(0);

		var public_key = opts.k ? crypto.getPublic(toBuffer(opts.k)) : toBuffer(opts.p);
		var public_key_0 = crypto.publicKeyConvert(public_key);
		var public_key_1 = crypto.publicKeyConvert(public_key, false);

		console.log('address:', crypto.publicToAddress(public_key_0));
		console.log('publicKey:', '0x' + public_key_0.toString('hex'));
		console.log('publicKeyLong:', '0x' + public_key_1.toString('hex'));
	} else if (opts.S) {
		// crypto-tx -k 0x2a50f73626d277e0b135eded15c9178ee5133a3e3c872ee6787bc5d28bbcfe0c -hash 0xa532bdfa7687d196cdd2ed8fef48b4eed1d3d765b4d6d9bf5af291c9d2321303  -S
		sign1();
	} else if (opts.S2) {
		// crypto-tx -k 0x8bd71af62734df779b28b3bfc1a52582e6c0108fbec174d91ce5ba8d2788fb89 -d 0x94CcfFF7c18647c5c8C8255886E2f42B5B8d80a9:address \
		// -d 0xD1a67514A2126C5b7A0f5DD59003aB0F3464bbf8:address -d 0x1:uint256 -d 0xd580c78d48631a60f09fd9356670764577f27786c0c3c415a033b76a92222f43:uint256 -S2
		sign2();
	} else if (opts.R) {
		recovery();
	} else if (opts.V) {
		verify();
	} else if (opts.F) {
		format();
	} else if (opts.KS) {
		exportKeystore();
	} else if (opts.H) {
		if (!opts.d)
			printHelp();
		else {
			// console.log(opts.d)
			console.log('keccak256 hash:', '0x' + message().toString('hex'));
		}
		
	} else {
		printHelp(0);
	}
}

main().catch(console.error);