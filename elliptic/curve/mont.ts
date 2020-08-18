
import * as utils from '../utils';
import BN, {BNArg} from '../../bn';
import Curve, {Point,CurveOptions} from './base';

export interface MontCurveOptions extends CurveOptions {
	a: string;
	b: string;
}

export default class MontCurve extends Curve {
	a: BN;
	b: BN;
	i4: BN;
	a24: BN;

	constructor(conf: MontCurveOptions) {
		super('mont', conf);
		this.a = new BN(conf.a, 16).toRed(this.red);
		this.b = new BN(conf.b, 16).toRed(this.red);
		this.i4 = new BN(4).toRed(this.red).redInvm();
		this.two = new BN(2).toRed(this.red);
		this.a24 = this.i4.redMul(this.a.redAdd(this.two));
	}

	pointFromJSON(obj: any, red: any): any {
		return Point.fromJSON(this, obj);
	}

	point(x: number[], y: number[]): Point {
		new MontPoint(this, x, y);
		throw 'Err';
	}

	validate(point: Point): boolean {
		var x = point.normalize().x;
		var x2 = x.redSqr();
		var rhs = x2.redMul(x).redAdd(x2.redMul(this.a)).redAdd(x);
		var y = rhs.redSqrt();
		return y.redSqr().cmp(rhs) === 0;
	}

	jpoint(x?: BN, y?: BN, z?: BN): Point {
		throw 'Err';
	}

	pointFromX(x: number[], odd?: boolean): Point {
		throw 'Err';
	}

	decodePoint(bytes: number[] | string | object, enc?: 'hex') {
		return this.point(utils.toArray(bytes, enc), [1]) as Point;
	};

}

export class MontPoint extends Point {
	x: BN;
	z: BN;

	constructor(curve: Curve, x?: BNArg, z?: BNArg) {
		super(curve, 'projective');
		if (!x || !z) {
			this.x = this.curve.one;
			this.z = this.curve.zero;
		} else {
			this.x = new BN(x, 16);
			this.z = new BN(z, 16);
			if (!this.x.red)
				this.x = this.x.toRed(this.curve.red);
			if (!this.z.red)
				this.z = this.z.toRed(this.curve.red);
		}
	}

	precompute() {
		// No-op
		return this;
	};

	_encode() {
		return this.getX().toArray('be', this.curve.p.byteLength());
	};

	static fromJSON(curve: Curve, obj: BNArg[]) {
		return new MontPoint(curve, obj[0], obj[1] || curve.one);
	};

	inspect() {
		if (this.isInfinity())
			return '<EC Point Infinity>';
		return '<EC Point x: ' + this.x.fromRed().toString(16, 2) +
				' z: ' + this.z.fromRed().toString(16, 2) + '>';
	};

	isInfinity() {
		// XXX This code assumes that zero is always zero in red
		return this.z.cmpn(0) === 0;
	};

	dbl() {
		// http://hyperelliptic.org/EFD/g1p/auto-montgom-xz.html#doubling-dbl-1987-m-3
		// 2M + 2S + 4A

		// A = X1 + Z1
		var a = this.x.redAdd(this.z);
		// AA = A^2
		var aa = a.redSqr();
		// B = X1 - Z1
		var b = this.x.redSub(this.z);
		// BB = B^2
		var bb = b.redSqr();
		// C = AA - BB
		var c = aa.redSub(bb);
		// X3 = AA * BB
		var nx = aa.redMul(bb);
		// Z3 = C * (BB + A24 * C)
		var nz = c.redMul(bb.redAdd(this.curve.a24.redMul(c)));
		return this.curve.point(nx, nz);
	};

	add(): Point {
		throw new Error('Not supported on Montgomery curve');
	};

	diffAdd(p: Point, diff: MontPoint) {
		// http://hyperelliptic.org/EFD/g1p/auto-montgom-xz.html#diffadd-dadd-1987-m-3
		// 4M + 2S + 6A

		// A = X2 + Z2
		var a = this.x.redAdd(this.z);
		// B = X2 - Z2
		var b = this.x.redSub(this.z);
		// C = X3 + Z3
		var c = p.x.redAdd(p.z);
		// D = X3 - Z3
		var d = p.x.redSub(p.z);
		// DA = D * A
		var da = d.redMul(a);
		// CB = C * B
		var cb = c.redMul(b);
		// X5 = Z1 * (DA + CB)^2
		var nx = diff.z.redMul(da.redAdd(cb).redSqr());
		// Z5 = X1 * (DA - CB)^2
		var nz = diff.x.redMul(da.redISub(cb).redSqr());
		return this.curve.point(nx, nz);
	};

	mul(k: BN) {
		var t = k.clone();
		var a = this; // (N / 2) * Q + Q
		var b = this.curve.point(null, null); // (N / 2) * Q
		var c = this; // Q

		for (var bits = []; t.cmpn(0) !== 0; t.iushrn(1))
			bits.push(t.andln(1));

		for (var i = bits.length - 1; i >= 0; i--) {
			if (bits[i] === 0) {
				// N * Q + Q = ((N / 2) * Q + Q)) + (N / 2) * Q
				a = a.diffAdd(b, c);
				// N * Q = 2 * ((N / 2) * Q + Q))
				b = b.dbl();
			} else {
				// N * Q = ((N / 2) * Q + Q) + ((N / 2) * Q)
				b = a.diffAdd(b, c);
				// N * Q + Q = 2 * ((N / 2) * Q + Q)
				a = a.dbl();
			}
		}
		return b;
	};

	mulAdd() {
		throw new Error('Not supported on Montgomery curve');
	};

	eq(other: Point) {
		return this.getX().cmp(other.getX()) === 0;
	};

	normalize() {
		this.x = this.x.redMul(this.z.redInvm());
		this.z = this.curve.one;
		return this;
	};

	getX() {
		// Normalize coordinates
		this.normalize();

		return this.x.fromRed();
	};

	getY(): BN {
		throw 'Err';
	}

	mixedAdd(p: Point): Point {
		throw 'Err';
	}

	neg(_precompute?: boolean): Point {
		throw 'Err';
	}

	toP(): Point {
		throw 'Err';
	}

	toJ(): Point {
		throw 'Err';
	}

	get y(): BN {
		throw 'Err';
	}

}