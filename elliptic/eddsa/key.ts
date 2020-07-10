
import * as utils from '../utils';

const assert = utils.assert;
const parseBytes = utils.parseBytes;
const cachedProperty = utils.cachedProperty;

/**
* @param {EDDSA} eddsa - instance
* @param {Object} params - public/private key parameters
*
* @param {Array<Byte>} [params.secret] - secret seed bytes
* @param {Point} [params.pub] - public key point (aka `A` in eddsa terms)
* @param {Array<Byte>} [params.pub] - public key point encoded as bytes
*
*/
export default class KeyPair {

	eddsa: any;
	_secret: any;
	_pub: any;
	_pubBytes: any;

	constructor(eddsa, params) {
		this.eddsa = eddsa;
		this._secret = parseBytes(params.secret);
		if (eddsa.isPoint(params.pub))
			this._pub = params.pub;
		else
			this._pubBytes = parseBytes(params.pub);
	}

	static fromPublic(eddsa, pub) {
		if (pub instanceof KeyPair)
			return pub;
		return new KeyPair(eddsa, { pub: pub });
	}

	static fromSecret(eddsa, secret) {
		if (secret instanceof KeyPair)
			return secret;
		return new KeyPair(eddsa, { secret: secret });
	}

	secret() {
		return this._secret;
	}

	sign(message) {
		assert(this._secret, 'KeyPair can only verify');
		return this.eddsa.sign(message, this);
	}
	
	verify(message, sig) {
		return this.eddsa.verify(message, sig, this);
	}
	
	getSecret(enc) {
		assert(this._secret, 'KeyPair is public only');
		return utils.encode(this.secret(), enc);
	}
	
	getPublic(enc) {
		return utils.encode(this.pubBytes(), enc);
	}
		
	@cachedProperty pubBytes() {
		return this.eddsa.encodePoint(this.pub());
	}

	@cachedProperty pub() {
		if (this._pubBytes)
			return this.eddsa.decodePoint(this._pubBytes);
		return this.eddsa.g.mul(this.priv());
	}

	@cachedProperty privBytes() {
		var eddsa = this.eddsa;
		var hash = this.hash();
		var lastIx = eddsa.encodingLength - 1;

		var a = hash.slice(0, eddsa.encodingLength);
		a[0] &= 248;
		a[lastIx] &= 127;
		a[lastIx] |= 64;

		return a;
	}

	@cachedProperty priv() {
		return this.eddsa.decodeInt(this.privBytes());
	}

	@cachedProperty hash() {
		return this.eddsa.hash().update(this.secret()).digest();
	}

	@cachedProperty messagePrefix() {
		return this.hash().slice(this.eddsa.encodingLength);
	}

}