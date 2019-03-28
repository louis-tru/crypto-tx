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
var assert = require('./secp256k1/assert');
var arguments = require('qkit/arguments');
var toBuffer = require('./utils').toBuffer;
var opts = arguments.options;
var help_info = arguments.helpInfo;
var def_opts = arguments.defOpts;

// def_opts(['help', 'h'], 0,   '-h   print help info');
def_opts(['E'],         0,   '-E   cmd encryptECIES [{0}]');
def_opts(['D'],         0,   '-D   cmd decryptECIES [{0}]');
def_opts(['G'],         0,   '-G   cmd gen private and public keys [{0}]');
def_opts(['k'],         '',  '-k   privateKey hex');
def_opts(['p'],         '',  '-p   publicKey hex');
def_opts(['d'],         '',  '-d   encrypt or decrypt data');
def_opts(['iv'],        '',  '-iv  IV 16 bytes hex');

function printHelp(code = -1) {
	process.stdout.write('Usage:\n');
	process.stdout.write('  crypto-tx -G\n');
	process.stdout.write(
		'  crypto-tx -E '+
		'[-k privateKey] -p publicKeyTo -d originaltext [-iv value] \n');
	process.stdout.write(
		'  crypto-tx -D '+
		'-k privateKey -p ephemPublicKey -d ciphertext [-iv value] \n');
	process.stdout.write('Options:\n');
	process.stdout.write('  ' + help_info.join('\n  ') + '\n');
	process.exit(code);
}

async function encrypt() {
	if (!opts.p || !opts.d)
		printHelp();

	var privateKey = opts.k ? toBuffer(opts.k): crypto.genPrivateKey();
	var publicKey = crypto.getPublic(privateKey);
	var publicKeyTo = toBuffer(opts.p);
	var originaltext = toBuffer(opts.d);
	var iv = opts.iv ? toBuffer(opts.iv): crypto.defaultEncryptIV();

	assert.isBufferLength(privateKey, 32, 'Bad privateKey length');
	assert.isBufferLength2(publicKeyTo, 33, 65, 'Bad ephemPublicKey length');
	assert.isBufferLength(iv, 16, 'Bad iv length');

	var { mac, ciphertext } = await crypto.encryptECIES(publicKeyTo, originaltext, {
		iv, ephemPrivateKey: privateKey, 
	});

	console.log('ciphertext: 0x' + ciphertext.toString('hex'));
	console.log('ephemPublicKey: 0x' + publicKey.toString('hex'));
	console.log('iv: 0x' + Buffer.from(iv).toString('hex'));
	console.log('mac: 0x' + mac.toString('hex'));
}

async function decrypt() {
	if (!opts.p || !opts.d || !opts.k)
		printHelp();

	var privateKey = toBuffer(opts.k);
	var ephemPublicKey = toBuffer(opts.p);
	var ciphertext = toBuffer(opts.d);
	var iv = opts.iv ? toBuffer(opts.iv): crypto.defaultEncryptIV();

	assert.isBufferLength(privateKey, 32, 'Bad privateKey length');
	assert.isBufferLength2(ephemPublicKey, 33, 65, 'Bad ephemPublicKey length');
	assert.isBufferLength(iv, 16, 'Bad iv length');

	var r = await crypto.decryptECIES(privateKey, {
		ephemPublicKey, ciphertext, iv,
	});

	console.log('0x' + r.toString('hex'));
}

async function main() {

	if (opts.E) {
		await encrypt();
	} else if (opts.D) {
		await decrypt();
	} else if (opts.G) {
		var privateKey = crypto.genPrivateKey();
		var publicKey = crypto.getPublic(privateKey);
		// var publicKey = crypto.getPublicCompressed(privateKey);
		console.log('privateKey: 0x' + privateKey.toString('hex'));
		console.log('publicKey:  0x' + publicKey.toString('hex'));
	} else {
		printHelp(0);
	}
}

main().catch(console.error);