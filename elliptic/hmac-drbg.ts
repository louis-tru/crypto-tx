'use strict';

var hash = require('hash.js');
import hash_ from 'somes/hash';
import * as utils from './utils';
const assert = utils.assert;

export default class HmacDRBG {

	hash: any;
	predResist: any;
	outLen: number;
	minEntropy: any;
	reseed: number = 0;
	reseedInterval: any;
	K: any;
	V: any;

	constructor(options: any) {
		this.hash = options.hash;
		this.predResist = !!options.predResist;

		this.outLen = this.hash.outSize;
		this.minEntropy = options.minEntropy || this.hash.hmacStrength;

		// this.reseed = null;
		this.reseedInterval = null;
		this.K = null;
		this.V = null;

		var entropy = utils.toArray(options.entropy, options.entropyEnc);
		var nonce = utils.toArray(options.nonce, options.nonceEnc);
		var pers = utils.toArray(options.pers, options.persEnc);
		assert(entropy.length >= (this.minEntropy / 8),
					'Not enough entropy. Minimum is: ' + this.minEntropy + ' bits');
		this._init(entropy, nonce, pers);
	}

	 private _init(entropy, nonce, pers) {
		var seed = entropy.concat(nonce).concat(pers);

		this.K = new Array(this.outLen / 8);
		this.V = new Array(this.outLen / 8);
		for (var i = 0; i < this.V.length; i++) {
			this.K[i] = 0x00;
			this.V[i] = 0x01;
		}

		this._update(seed);
		this.reseed = 1;
		this.reseedInterval = 0x1000000000000;  // 2^48
	}

	private _hmac() {
		return new hash.hmac(this.hash, this.K);
	}

	private _update(seed) {
		var kmac = this._hmac()
									.update(this.V)
									.update([ 0x00 ]);
		if (seed)
			kmac = kmac.update(seed);
		this.K = kmac.digest();
		this.V = this._hmac().update(this.V).digest();
		if (!seed)
			return;

		this.K = this._hmac()
								.update(this.V)
								.update([ 0x01 ])
								.update(seed)
								.digest();
		this.V = this._hmac().update(this.V).digest();
	}

	private _reseed(entropy, entropyEnc, add, addEnc) {
		// Optional entropy enc
		if (typeof entropyEnc !== 'string') {
			addEnc = add;
			add = entropyEnc;
			entropyEnc = null;
		}

		entropy = utils.toBuffer(entropy, entropyEnc);
		add = utils.toBuffer(add, addEnc);

		assert(entropy.length >= (this.minEntropy / 8),
					'Not enough entropy. Minimum is: ' + this.minEntropy + ' bits');

		this._update(entropy.concat(add || []));
		this.reseed = 1;
	}

	generate(len, enc, add, addEnc) {
		if (this.reseed > this.reseedInterval)
			throw new Error('Reseed is required');

		// Optional encoding
		if (typeof enc !== 'string') {
			addEnc = add;
			add = enc;
			enc = null;
		}

		// Optional additional data
		if (add) {
			add = utils.toArray(add, addEnc);
			this._update(add);
		}

		var temp = [];
		while (temp.length < len) {
			this.V = this._hmac().update(this.V).digest();
			temp = temp.concat(this.V);
		}

		var res = temp.slice(0, len);
		this._update(add);
		this.reseed++;
		return utils.encode(res, enc);
	}

}