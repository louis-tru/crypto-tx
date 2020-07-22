
import BN from '../../bn';

export default class KeyPair {

	ec: any;
	priv: any;
	pub: any;

	constructor(ec: any, options: any) {
		this.ec = ec;
		this.priv = null;
		this.pub = null;

		// KeyPair(ec, { priv: ..., pub: ... })
		if (options.priv)
			this._importPrivate(options.priv, options.privEnc);
		if (options.pub)
			this._importPublic(options.pub, options.pubEnc);
	}

	fromPublic(ec: any, pub: any, enc: any) {
		if (pub instanceof KeyPair)
			return pub;

		return new KeyPair(ec, {
			pub: pub,
			pubEnc: enc
		});
	};

	fromPrivate(ec: any, priv: any, enc: any) {
		if (priv instanceof KeyPair)
			return priv;

		return new KeyPair(ec, {
			priv: priv,
			privEnc: enc
		});
	};

	validate() {
		var pub = this.getPublic();

		if (pub.isInfinity())
			return { result: false, reason: 'Invalid public key' };
		if (!pub.validate())
			return { result: false, reason: 'Public key is not a point' };
		if (!pub.mul(this.ec.curve.n).isInfinity())
			return { result: false, reason: 'Public key * N != O' };

		return { result: true, reason: null };
	};

	getPublic(compact?: any, enc?: any) {
		// compact is optional argument
		if (typeof compact === 'string') {
			enc = compact;
			compact = null;
		}

		if (!this.pub)
			this.pub = this.ec.g.mul(this.priv);

		if (!enc)
			return this.pub;

		return this.pub.encode(enc, compact);
	};

	getPrivate(enc: any) {
		if (enc === 'hex')
			return this.priv.toString(16, 2);
		else
			return this.priv;
	};

	private _importPrivate(key: any, enc: any) {
		this.priv = new BN(key, enc || 16);

		// Ensure that the priv won't be bigger than n, otherwise we may fail
		// in fixed multiplication method
		this.priv = this.priv.umod(this.ec.curve.n);
	};

	private _importPublic(key: any, enc: any) {
		if (key.x || key.y) {
			this.pub = this.ec.curve.point(key.x, key.y);
			return;
		}
		this.pub = this.ec.curve.decodePoint(key, enc);
	};

	// ECDH
	derive(pub: any) {
		return pub.mul(this.priv).getX();
	};

	// ECDSA
	sign(msg: any, enc: any, options: any) {
		return this.ec.sign(msg, this, enc, options);
	};

	verify(msg: any, signature: any) {
		return this.ec.verify(msg, signature, this);
	};

	inspect() {
		return '<Key priv: ' + (this.priv && this.priv.toString(16, 2)) +
					' pub: ' + (this.pub && this.pub.inspect()) + ' >';
	};

}