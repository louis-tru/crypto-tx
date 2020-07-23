
import * as utils from '../utils';
import BN, {Red, MPrimeType} from '../../bn';

const getNAF = utils.getNAF;
const getJSF = utils.getJSF;
const assert = utils.assert;

export interface BaseCurveOptions {
	p: string;
	g?: string;
	n?: string;
	gRed?: Red;
	prime?: BN | MPrimeType;
}

export default abstract class BaseCurve {
	type: string;
	p: BN;
	red: Red;
	zero: BN;
	one: BN;
	two: BN;
	n?: BN;
	g?: any;

	private _wnafT1: number[];
	private _wnafT2: BasePoint[];
	private _wnafT3: number[];
	private _wnafT4: number[];

	constructor(type: string, conf: BaseCurveOptions) {
		this.type = type;
		this.p = new BN(conf.p, 16);

		// Use Montgomery, when there is no fast reduction for the prime
		this.red = conf.prime ? BN.red(conf.prime) : BN.mont(this.p);

		// Useful for many curves
		this.zero = new BN(0).toRed(this.red);
		this.one = new BN(1).toRed(this.red);
		this.two = new BN(2).toRed(this.red);

		// Curve configuration, optional
		if (conf.n) this.n = new BN(conf.n, 16);
		if (conf.g) this.g = this.pointFromJSON(conf.g, conf.gRed);

		// Temporary arrays
		this._wnafT1 = new Array(4);
		this._wnafT2 = new Array(4);
		this._wnafT3 = new Array(4);
		this._wnafT4 = new Array(4);
	}

	abstract pointFromJSON(obj: any, red: any): any;
	abstract point(): void;
	abstract validate(): void;
	abstract jpoint(x?: BN, y?: BN, z?: BN): BasePoint;

	protected _fixedNafMul(p: BasePoint, k: BN) {
		assert(p.precomputed);
		var doubles = p._getDoubles(0, 1);

		var naf = getNAF(k, 1);
		var I = (1 << (doubles.step + 1)) - (doubles.step % 2 === 0 ? 2 : 1);
		I /= 3;

		// Translate into more windowed form
		var repr = [];
		for (var j = 0; j < naf.length; j += doubles.step) {
			var nafW = 0;
			for (let k = j + doubles.step - 1; k >= j; k--)
				nafW = (nafW << 1) + naf[k];
			repr.push(nafW);
		}

		var a = this.jpoint();
		var b = this.jpoint();
		for (var i = I; i > 0; i--) {
			for (var j = 0; j < repr.length; j++) {
				var nafW = repr[j];
				if (nafW === i)
					b = b.mixedAdd(doubles.points[j]);
				else if (nafW === -i)
					b = b.mixedAdd(doubles.points[j].neg());
			}
			a = a.add(b);
		}
		return a.toP();
	}

	protected _wnafMul(p: BasePoint, k: BN) {
		var w = 4;

		// Precompute window
		var nafPoints = p._getNAFPoints(w);
		w = nafPoints.wnd;
		var wnd = nafPoints.points;

		// Get NAF form
		var naf = getNAF(k, w);

		// Add `this`*(N+1) for every w-NAF index
		var acc = this.jpoint();
		for (var i = naf.length - 1; i >= 0; i--) {
			// Count zeroes
			let k = 0;
			for (; i >= 0 && naf[i] === 0; i--)
				k++;
			if (i >= 0)
				k++;
			acc = acc.dblp(k);

			if (i < 0)
				break;
			var z = naf[i];
			assert(z !== 0);
			if (p.type === 'affine') {
				// J +- P
				if (z > 0)
					acc = acc.mixedAdd(wnd[(z - 1) >> 1]);
				else
					acc = acc.mixedAdd(wnd[(-z - 1) >> 1].neg());
			} else {
				// J +- J
				if (z > 0)
					acc = acc.add(wnd[(z - 1) >> 1]);
				else
					acc = acc.add(wnd[(-z - 1) >> 1].neg());
			}
		}
		return p.type === 'affine' ? acc.toP() : acc;
	}

	protected _wnafMulAdd(defW: number, points: BasePoint[], coeffs: BN[], len: number) {
		var wndWidth = this._wnafT1;
		var wnd = this._wnafT2;
		var naf = this._wnafT3;

		// Fill all arrays
		var max = 0;
		for (var i = 0; i < len; i++) {
			var p = points[i];
			var nafPoints = p._getNAFPoints(defW);
			wndWidth[i] = nafPoints.wnd;
			wnd[i] = nafPoints.points;
		}

		// Comb small window NAFs
		for (var i = len - 1; i >= 1; i -= 2) {
			var a = i - 1;
			var b = i;
			if (wndWidth[a] !== 1 || wndWidth[b] !== 1) {
				naf[a] = getNAF(coeffs[a], wndWidth[a]);
				naf[b] = getNAF(coeffs[b], wndWidth[b]);
				max = Math.max(naf[a].length, max);
				max = Math.max(naf[b].length, max);
				continue;
			}

			var comb = [
				points[a], /* 1 */
				null, /* 3 */
				null, /* 5 */
				points[b] /* 7 */
			];

			// Try to avoid Projective points, if possible
			if (points[a].y.cmp(points[b].y) === 0) {
				comb[1] = points[a].add(points[b]);
				comb[2] = points[a].toJ().mixedAdd(points[b].neg());
			} else if (points[a].y.cmp(points[b].y.redNeg()) === 0) {
				comb[1] = points[a].toJ().mixedAdd(points[b]);
				comb[2] = points[a].add(points[b].neg());
			} else {
				comb[1] = points[a].toJ().mixedAdd(points[b]);
				comb[2] = points[a].toJ().mixedAdd(points[b].neg());
			}

			var index = [
				-3, /* -1 -1 */
				-1, /* -1 0 */
				-5, /* -1 1 */
				-7, /* 0 -1 */
				0, /* 0 0 */
				7, /* 0 1 */
				5, /* 1 -1 */
				1, /* 1 0 */
				3  /* 1 1 */
			];

			var jsf = getJSF(coeffs[a], coeffs[b]);
			max = Math.max(jsf[0].length, max);
			naf[a] = new Array(max);
			naf[b] = new Array(max);
			for (var j = 0; j < max; j++) {
				var ja = jsf[0][j] | 0;
				var jb = jsf[1][j] | 0;

				naf[a][j] = index[(ja + 1) * 3 + (jb + 1)];
				naf[b][j] = 0;
				wnd[a] = comb;
			}
		}

		var acc = this.jpoint(null, null, null);
		var tmp = this._wnafT4;
		for (var i = max; i >= 0; i--) {
			var k = 0;

			while (i >= 0) {
				var zero = true;
				for (var j = 0; j < len; j++) {
					tmp[j] = naf[j][i] | 0;
					if (tmp[j] !== 0)
						zero = false;
				}
				if (!zero)
					break;
				k++;
				i--;
			}
			if (i >= 0)
				k++;
			acc = acc.dblp(k);
			if (i < 0)
				break;

			for (var j = 0; j < len; j++) {
				var z = tmp[j];
				var p;
				if (z === 0)
					continue;
				else if (z > 0)
					p = wnd[j][(z - 1) >> 1];
				else if (z < 0)
					p = wnd[j][(-z - 1) >> 1].neg();

				if (p.type === 'affine')
					acc = acc.mixedAdd(p);
				else
					acc = acc.add(p);
			}
		}
		// Zeroify references
		for (var i = 0; i < len; i++)
			wnd[i] = null;
		return acc.toP();
	}

	decodePoint(bytes, enc) {
		bytes = utils.toArray(bytes, enc);

		var len = this.p.byteLength();

		// uncompressed, hybrid-odd, hybrid-even
		if ((bytes[0] === 0x04 || bytes[0] === 0x06 || bytes[0] === 0x07) &&
				bytes.length - 1 === 2 * len) {
			if (bytes[0] === 0x06)
				assert(bytes[bytes.length - 1] % 2 === 0);
			else if (bytes[0] === 0x07)
				assert(bytes[bytes.length - 1] % 2 === 1);

			var res =  this.point(bytes.slice(1, 1 + len),
														bytes.slice(1 + len, 1 + 2 * len));

			return res;
		} else if ((bytes[0] === 0x02 || bytes[0] === 0x03) &&
								bytes.length - 1 === len) {
			return this.pointFromX(bytes.slice(1, 1 + len), bytes[0] === 0x03);
		}
		throw new Error('Unknown point format');
	}

}

interface Precomputed {
	doubles: {
		step: number;
		points: BasePoint[];
	};
	naf: {
		wnd: number;
		points: BasePoint[];
	};
	beta: BasePoint | null;
}

export abstract class BasePoint {

	curve: BaseCurve;
	type: string;
	precomputed: Precomputed | null;

	constructor(curve: BaseCurve, type: string) {
		this.curve = curve;
		this.type = type;
		this.precomputed = null;
	}

	abstract dbl(): BasePoint;
	abstract add(arg: BasePoint | null): BasePoint;
	abstract getX(): BN;
	abstract getY(): BN;
	abstract mixedAdd(p: BasePoint): BasePoint;
	abstract neg(_precompute?: boolean): BasePoint;
	abstract toP(): BasePoint;

	eq(/*other*/) {
		throw new Error('Not implemented');
	};

	validate() {
		return this.curve.validate(this);
	};

	encodeCompressed(enc?: utils.Encoding) {
		return this.encode(enc, true);
	};

	private _encode(compact?: boolean) {
		var len = this.curve.p.byteLength();
		var x = this.getX().toArray('be', len);

		if (compact)
			return [ this.getY().isEven() ? 0x02 : 0x03 ].concat(x);

		return [ 0x04 ].concat(x, this.getY().toArray('be', len)) ;
	};

	encode(enc?: utils.Encoding, compact?: boolean) {
		return utils.encode(this._encode(compact), enc);
	};

	precompute(power: number) {
		if (this.precomputed)
			return this;

		var precomputed: Precomputed = {
			naf: this._getNAFPoints(8),
			doubles: this._getDoubles(4, power),
			beta: this._getBeta(),
		};
		this.precomputed = precomputed;

		return this;
	};

	private _hasDoubles(k: BN) {
		if (!this.precomputed)
			return false;

		var doubles = this.precomputed.doubles;
		if (!doubles)
			return false;

		return doubles.points.length >= Math.ceil((k.bitLength() + 1) / doubles.step);
	};

	/*private */_getDoubles(step: number, power: number) {
		if (this.precomputed && this.precomputed.doubles)
			return this.precomputed.doubles;

		var doubles: BasePoint[] = [ this ];
		var acc: BasePoint = this;
		for (var i = 0; i < power; i += step) {
			for (var j = 0; j < step; j++)
				acc = acc.dbl();
			doubles.push(acc);
		}
		return {
			step: step,
			points: doubles
		};
	};

	/*private */_getNAFPoints(wnd: number) {
		if (this.precomputed && this.precomputed.naf)
			return this.precomputed.naf;

		var res: BasePoint[] = [ this ];
		var max = (1 << wnd) - 1;
		var dbl = max === 1 ? null : this.dbl();
		for (var i = 1; i < max; i++)
			res[i] = res[i - 1].add(dbl);
		return {
			wnd: wnd,
			points: res
		};
	};

	protected _getBeta(): BasePoint | null {
		return null;
	};

	dblp(k: number) {
		var r: BasePoint = this;
		for (var i = 0; i < k; i++)
			r = r.dbl();
		return r;
	};

}