
var hash = require('hash.js');
import * as utils from '../utils';
import curves, {Type,Curve} from '../curves';
var assert = utils.assert;
var parseBytes = utils.parseBytes;
var KeyPair = require('./key');
var Signature = require('./signature');

export class EDDSA {

	curve: Curve;
	g: any;
	pointClass: any;
	encodingLength: number;
	hash: any;

	constructor(curveType: Type) {
		assert(curveType === 'ed25519', 'only tested with ed25519 so far');

		var curve = curves[curveType].curve;
		this.curve = curve;
		this.g = curve.g;
		this.g.precompute(curve.n.bitLength() + 1);

		this.pointClass = curve.point().constructor;
		this.encodingLength = Math.ceil(curve.n.bitLength() / 8);
		this.hash = hash.sha512;
	}

	/**
	* @param {Array|String} message - message bytes
	* @param {Array|String|KeyPair} secret - secret bytes or a keypair
	* @returns {Signature} - signature
	*/
	sign(message, secret) {
		message = parseBytes(message);
		var key = this.keyFromSecret(secret);
		var r = this.hashInt(key.messagePrefix(), message);
		var R = this.g.mul(r);
		var Rencoded = this.encodePoint(R);
		var s_ = this.hashInt(Rencoded, key.pubBytes(), message)
								.mul(key.priv());
		var S = r.add(s_).umod(this.curve.n);
		return this.makeSignature({ R: R, S: S, Rencoded: Rencoded });
	}

	/**
	* @param {Array} message - message bytes
	* @param {Array|String|Signature} sig - sig bytes
	* @param {Array|String|Point|KeyPair} pub - public key
	* @returns {Boolean} - true if public key matches sig of message
	*/
	verify(message, sig, pub) {
		message = parseBytes(message);
		sig = this.makeSignature(sig);
		var key = this.keyFromPublic(pub);
		var h = this.hashInt(sig.Rencoded(), key.pubBytes(), message);
		var SG = this.g.mul(sig.S());
		var RplusAh = sig.R().add(key.pub().mul(h));
		return RplusAh.eq(SG);
	}

	hashInt() {
		var hash = this.hash();
		for (var i = 0; i < arguments.length; i++)
			hash.update(arguments[i]);
		return utils.intFromLE(hash.digest()).umod(this.curve.n);
	}

	keyFromPublic(pub) {
		return KeyPair.fromPublic(this, pub);
	}

	keyFromSecret(secret) {
		return KeyPair.fromSecret(this, secret);
	}

	makeSignature(sig) {
		if (sig instanceof Signature)
			return sig;
		return new Signature(this, sig);
	}

	/**
	* * https://tools.ietf.org/html/draft-josefsson-eddsa-ed25519-03#section-5.2
	*
	* EDDSA defines methods for encoding and decoding points and integers. These are
	* helper convenience methods, that pass along to utility functions implied
	* parameters.
	*
	*/
	encodePoint(point) {
		var enc = point.getY().toArray('le', this.encodingLength);
		enc[this.encodingLength - 1] |= point.getX().isOdd() ? 0x80 : 0;
		return enc;
	}

	decodePoint(bytes) {
		bytes = utils.parseBytes(bytes);

		var lastIx = bytes.length - 1;
		var normed = bytes.slice(0, lastIx).concat(bytes[lastIx] & ~0x80);
		var xIsOdd = (bytes[lastIx] & 0x80) !== 0;

		var y = utils.intFromLE(normed);
		return this.curve.pointFromY(y, xIsOdd);
	}

	encodeInt(num) {
		return num.toArray('le', this.encodingLength);
	}

	decodeInt(bytes) {
		return utils.intFromLE(bytes);
	}

	isPoint(val) {
		return val instanceof this.pointClass;
	}
}