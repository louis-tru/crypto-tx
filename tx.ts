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
import buffer, {Buffer} from 'somes/buffer';
import utils from './utils';
import fees from './fees';
import {BN} from './bn1';
//import secp256k1 from './ec';

const N_DIV_2 = new BN('7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0', 16);

interface Field {
	name: string,
	alias?: string;
	length?: number,
	allowLess?: boolean,
	allowZero?: boolean,
	default: Buffer,
}

export interface ITransactionSigner {
	sign(message: Buffer): Promise<{ signature: Buffer, recovery: number }>;
}

const fields: Field[] = [
	{
		name: 'nonce',
		length: 32,
		allowLess: true,
		default: buffer.from([]),
	}, {
		name: 'gasPrice',
		length: 32,
		allowLess: true,
		default: buffer.from([]),
	}, {
		name: 'gasLimit',
		alias: 'gas',
		length: 32,
		allowLess: true,
		default: buffer.from([]),
	}, {
		name: 'to',
		allowZero: true,
		length: 20,
		default: buffer.from([]),
	}, {
		name: 'value',
		length: 32,
		allowLess: true,
		default: buffer.from([]),
	}, {
		name: 'data',
		alias: 'input',
		allowZero: true,
		default: buffer.from([]),
	}, {
		name: 'v',
		allowZero: true,
		default: buffer.from([0x1c])
	}, {
		name: 'r',
		length: 32,
		allowZero: true,
		allowLess: true,
		default: buffer.from([]),
	}, {
		name: 's',
		length: 32,
		allowZero: true,
		allowLess: true,
		default: buffer.from([]),
	}
];

export class Transaction {

	private _chainId: number;
	private _homestead: boolean;
	readonly raw: any[] = [];
	private _fields: string[] = [];
	private _from?: Buffer;
	private _senderPubKey?: Buffer;

	readonly nonce = buffer.Zero;
	readonly gasPrice = buffer.Zero;
	readonly gasLimit = buffer.Zero;
	readonly to = buffer.Zero;
	readonly value = buffer.Zero;
	readonly data = buffer.Zero;
	readonly v = buffer.Zero;
	readonly r = buffer.Zero;
	readonly s = buffer.Zero;

	constructor(opts: Dict) {
		// Define Properties
		var self = this
		var _this = self as any;

		fields.forEach(function (field: Field, i: number) {
			self._fields.push(field.name);

			var prop = {
				enumerable: true,
				configurable: true,
				get() {
					return self.raw[i];
				},
				set(_v: any) {
					let v = utils.toBuffer(_v);
	
					if (v.toString('hex') === '00' && !field.allowZero) {
						v = buffer.allocUnsafe(0);
					}
	
					if (field.allowLess && field.length) {
						v = utils.stripZeros(v);
						somes.assert(field.length >= v.length, 
							'The field ' + field.name + ' must not have more ' + field.length + ' bytes');
					}
					else if (!(field.allowZero && v.length === 0) && field.length) {
						somes.assert(field.length === v.length, 
							'The field ' + field.name + ' must have byte length of ' + field.length);
					}
	
					self.raw[i] = v;
				},
			};

			Object.defineProperty(self, field.name, prop);

			if (field.default) {
				_this[field.name] = field.default;
			}

			// attach alias
			if (field.alias)
				Object.defineProperty(self, field.alias, Object.assign(prop, { enumerable: false }));
		});

		opts = opts || {}
		//if the constuctor is passed data
		if (typeof opts === 'string') {
			opts = buffer.from(utils.stripHexPrefix(opts), 'hex');
		}
		if (buffer.isUint8Array(opts)) {
			opts = utils.rlp_decode(opts as any);
		}

		if (Array.isArray(opts)) {
			if (opts.length > self._fields.length) {
				throw new Error('wrong number of fields in data');
			}
			// make sure all the items are buffers
			opts.forEach(function (d, i) {
				_this[self._fields[i]] = utils.toBuffer(d);
			});
		}
		else if (typeof opts == 'object' && !buffer.isUint8Array(opts)) {
			var keys = Object.keys(opts);

			for (var field of fields) {
				if (keys.indexOf(field.name) !== -1)
					_this[field.name] = opts[field.name];
				if (keys.indexOf(field.alias!) !== -1) 
					_this[field.alias!] = opts[field.alias!];
			}
		}
		else {
			throw new Error('invalid data');
		}

		Object.defineProperty(this, 'from', {
			enumerable: true,
			configurable: true,
			get: this.getSenderAddress.bind(this)
		});

		// calculate chainId from signature
		let sigV = utils.bufferToInt(this.v);
		let chainId = Math.floor((sigV - 35) / 2);
		if (chainId < 0) chainId = 0;

		// set chainId
		this._chainId = chainId || opts.chainId || 0;
		this._homestead = true;
	}

	// attach the `toJSON`
	toJSON(label?: boolean) {
		if (label) {
			var self = this;
			var obj = {} as any;
			self._fields.forEach(function (field: string) {
				obj[field] = '0x' + (self as any)[field].toString('hex');
			});
			return obj;
		}
		return utils.baToJSON(this.raw);
	}

	serialize() {
		return utils.rlp_encode(this.raw);
	}

	/**
	 * If the tx's `to` is to the creation address
	 * @return {Boolean}
	 */
	toCreationAddress () {
		return this.to.toString('hex') === '';
	}

	/**
	 * Computes a sha3-256 hash of the serialized tx
	 * @param {Boolean} [includeSignature=true] whether or not to inculde the signature
	 * @return {Buffer}
	 */
	hash(includeSignature = true) {
		if (includeSignature === undefined) includeSignature = true;

		// EIP155 spec:
		// when computing the hash of a transaction for purposes of signing or recovering,
		// instead of hashing only the first six elements (ie. nonce, gasprice, startgas, to, value, data),
		// hash nine elements, with v replaced by CHAIN_ID, r = 0 and s = 0

		let items
		if (includeSignature) {
			items = this.raw;
		} else {
			if (this._chainId > 0) {
				var _this = this as any;
				const raw = this.raw.slice();
				_this.v = this._chainId;
				_this.r = 0;
				_this.s = 0;
				items = this.raw;
				_this.raw = raw;
			} else {
				items = this.raw.slice(0, 6);
			}
		}

		// create hash
		return utils.rlphash(items);
	}

	/**
	 * returns chain ID
	 * @return {Buffer}
	 */
	getChainId () {
		return this._chainId;
	}

	/**
	 * returns the sender's address
	 * @return {Buffer}
	 */
	getSenderAddress() {
		if (this._from) {
			return this._from;
		}
		const pubkey = this.getSenderPublicKey();
		this._from = utils.publicToAddress(pubkey!);
		return this._from;
	}

	/**
	 * returns the public key of the sender
	 * @return {Buffer}
	 */
	getSenderPublicKey() {
		if (!this._senderPubKey || !this._senderPubKey.length) {
			if (!this.verifySignature()) throw new Error('Invalid Signature');
		}
		return this._senderPubKey!;
	}

	/**
	 * Determines if the signature is valid
	 * @return {Boolean}
	 */
	verifySignature() {
		const msgHash = this.hash(false)
		// All transaction signatures whose s-value is greater than secp256k1n/2 are considered invalid.
		if (this._homestead && new BN(this.s).cmp(N_DIV_2) === 1) {
			return false;
		}

		try {
			let v = utils.bufferToInt(this.v)
			if (this._chainId > 0) {
				v -= this._chainId * 2 + 8;
			}
			this._senderPubKey = utils.ecrecover(msgHash, v, this.r, this.s);
		} catch (e) {
			return false;
		}

		return !!this._senderPubKey;
	}

	/**
	 * sign a transaction with a given private key
	 * @param {Signer} signer
	 */
	async sign(signer: ITransactionSigner) {
		const msgHash = this.hash(false);

		var sig = await signer.sign(msgHash);
		var rsv = {
			r: sig.signature.slice(0, 32),
			s: sig.signature.slice(32, 64),
			v: sig.recovery + 27,
		};
		if (this._chainId > 0) {
			rsv.v += this._chainId * 2 + 8;
		}

		Object.assign(this, rsv);
	}

	/**
	 * The amount of gas paid for the data in this tx
	 * @return {BN}
	 */
	getDataFee () {
		const data = this.raw[5];
		const cost = new BN(0);
		for (let i = 0; i < data.length; i++) {
			data[i] === 0 ? cost.iaddn(fees.txDataZeroGas.v) : cost.iaddn(fees.txDataNonZeroGas.v);
		}
		return cost;
	}

	/**
	 * the minimum amount of gas the tx must have (DataFee + TxFee + Creation Fee)
	 * @return {BN}
	 */
	getBaseFee () {
		const fee = this.getDataFee().iaddn(fees.txGas.v)
		if (this._homestead && this.toCreationAddress()) {
			fee.iaddn(fees.txCreation.v);
		}
		return fee
	}

	/**
	 * the up front amount that an account must have for this transaction to be valid
	 * @return {BN}
	 */
	getUpfrontCost () {
		return new BN(this.gasLimit)
			.imul(new BN(this.gasPrice))
			.iadd(new BN(this.value));
	}

	/**
	 * validates the signature and checks to see if it has enough gas
	 * @param {Boolean} [stringError=false] whether to return a string 
	 *   with a description of why the validation failed or return a Boolean
	 * @return {Boolean|String}
	 */
	validate (stringError = false) {
		const errors = []
		if (!this.verifySignature()) {
			errors.push('Invalid Signature');
		}

		if (this.getBaseFee().cmp(new BN(this.gasLimit)) > 0) {
			errors.push([`gas limit is too low. Need at least ${this.getBaseFee()}`]);
		}

		if (stringError === undefined || stringError === false) {
			return errors.length === 0;
		} else {
			return errors.join(' ');
		}
	}
}

// var rawTx = {
// 	nonce: '0x00',
// 	gasPrice: '0x09184e72a000', 
// 	gasLimit: '0x2710',
// 	to: '0x0000000000000000000000000000000000000000',
// 	value: '0x00', 
// 	data: '0x7f7465737432000000000000000000000000000000000000000000000000000000600057',
// 	// EIP 155 chainId - mainnet: 1, ropsten: 3
// 	chainId: 3
// }

export async function signTx(signer: ITransactionSigner, rawTx: any) {

	var tx = new Transaction(rawTx);

	await tx.sign(signer);

	var serializedTx = tx.serialize();

	return {
		rawTx: rawTx,
		signTx: serializedTx,
		serializedTx: serializedTx,
		hash: tx.hash(),
		rsv: { r: tx.r, s: tx.s, v: tx.v },
	};
}