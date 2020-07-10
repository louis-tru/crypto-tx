
import * as utils from '../utils';

var assert = utils.assert;
var cachedProperty = utils.cachedProperty;
var parseBytes = utils.parseBytes;

/**
* @param {EDDSA} eddsa - eddsa instance
* @param {Array<Bytes>|Object} sig -
* @param {Array<Bytes>|Point} [sig.R] - R point as Point or bytes
* @param {Array<Bytes>|bn} [sig.S] - S scalar as bn or bytes
* @param {Array<Bytes>} [sig.Rencoded] - R point encoded
* @param {Array<Bytes>} [sig.Sencoded] - S scalar encoded
*/
export default class Signature {

	eddsa: any;
	_R: any;
	_S: any;
	_Rencoded: any;
	_Sencoded: any;

	constructor(eddsa, sig) {
		this.eddsa = eddsa;

		if (typeof sig !== 'object')
			sig = parseBytes(sig);

		if (Array.isArray(sig)) {
			sig = {
				R: sig.slice(0, eddsa.encodingLength),
				S: sig.slice(eddsa.encodingLength)
			};
		}

		assert(sig.R && sig.S, 'Signature without R or S');

		if (eddsa.isPoint(sig.R))
			this._R = sig.R;
		if (typeof sig.S == 'bigint' /*instanceof BN*/)
			this._S = sig.S;

		this._Rencoded = Array.isArray(sig.R) ? sig.R : sig.Rencoded;
		this._Sencoded = Array.isArray(sig.S) ? sig.S : sig.Sencoded;
	}

	@cachedProperty S() {
		return this.eddsa.decodeInt(this.Sencoded());
	}

	@cachedProperty R() {
		return this.eddsa.decodePoint(this.Rencoded());
	}

	@cachedProperty Rencoded() {
		return this.eddsa.encodePoint(this.R());
	}

	@cachedProperty Sencoded() {
		return this.eddsa.encodeInt(this.S());
	}

	toBytes() {
		return this.Rencoded().concat(this.Sencoded());
	}

	toHex() {
		return utils.encode(this.toBytes(), 'hex').toUpperCase();
	}
}
