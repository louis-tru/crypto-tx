
import utils from 'somes';
import {IBuffer,IBufferIMPL} from 'somes/buffer';

const assert = utils.assert;

function parseHex (str: string, start: number, end: number) {
	var r = 0;
	var len = Math.min(str.length, end);
	for (var i = start; i < len; i++) {
		var c = str.charCodeAt(i) - 48;

		r <<= 4;

		// 'a' - 'f'
		if (c >= 49 && c <= 54) {
			r |= c - 49 + 0xa;

		// 'A' - 'F'
		} else if (c >= 17 && c <= 22) {
			r |= c - 17 + 0xa;

		// '0' - '9'
		} else {
			r |= c & 0xf;
		}
	}
	return r;
}

function parseBase (str: string, start: number, end: number, mul: number) {
	var r = 0;
	var len = Math.min(str.length, end);
	for (var i = start; i < len; i++) {
		var c = str.charCodeAt(i) - 48;

		r *= mul;

		// 'a'
		if (c >= 49) {
			r += c - 49 + 0xa;

		// 'A'
		} else if (c >= 17) {
			r += c - 17 + 0xa;

		// '0' - '9'
		} else {
			r += c;
		}
	}
	return r;
}

/*

var zeros = [];
var groupSizes = [];
var groupBases = [];

var s = '';
var i = -1;
while (++i < BN.wordSize) {
	zeros[i] = s;
	s += '0';
}
groupSizes[0] = 0;
groupSizes[1] = 0;
groupBases[0] = 0;
groupBases[1] = 0;
var base = 2 - 1;
while (++base < 36 + 1) {
	var groupSize = 0;
	var groupBase = 1;
	while (groupBase < (1 << BN.wordSize) / base) {
		groupBase *= base;
		groupSize += 1;
	}
	groupSizes[base] = groupSize;
	groupBases[base] = groupBase;
}

*/

var zeros = [
	'',
	'0',
	'00',
	'000',
	'0000',
	'00000',
	'000000',
	'0000000',
	'00000000',
	'000000000',
	'0000000000',
	'00000000000',
	'000000000000',
	'0000000000000',
	'00000000000000',
	'000000000000000',
	'0000000000000000',
	'00000000000000000',
	'000000000000000000',
	'0000000000000000000',
	'00000000000000000000',
	'000000000000000000000',
	'0000000000000000000000',
	'00000000000000000000000',
	'000000000000000000000000',
	'0000000000000000000000000'
];

var groupSizes = [
	0, 0,
	25, 16, 12, 11, 10, 9, 8,
	8, 7, 7, 7, 7, 6, 6,
	6, 6, 6, 6, 6, 5, 5,
	5, 5, 5, 5, 5, 5, 5,
	5, 5, 5, 5, 5, 5, 5
];

var groupBases = [
	0, 0,
	33554432, 43046721, 16777216, 48828125, 60466176, 40353607, 16777216,
	43046721, 10000000, 19487171, 35831808, 62748517, 7529536, 11390625,
	16777216, 24137569, 34012224, 47045881, 64000000, 4084101, 5153632,
	6436343, 7962624, 9765625, 11881376, 14348907, 17210368, 20511149,
	24300000, 28629151, 33554432, 39135393, 45435424, 52521875, 60466176
];

function toBitArray (num: BN) {
	var w = new Array(num.bitLength());

	for (var bit = 0; bit < w.length; bit++) {
		var off = (bit / 26) | 0;
		var wbit = bit % 26;

		w[bit] = (num.words[off] & (1 << wbit)) >>> wbit;
	}

	return w;
}

function jumboMulTo (self: BN, num: BN, out: BN) {
	var fftm = new FFTM();
	return fftm.mulp(self, num, out);
}

const _countBits = Math.clz32 ? function (w: number) {
	return 32 - Math.clz32(w);
}: function(w: number) {
	var t = w;
	var r = 0;
	if (t >= 0x1000) {
		r += 13;
		t >>>= 13;
	}
	if (t >= 0x40) {
		r += 7;
		t >>>= 7;
	}
	if (t >= 0x8) {
		r += 4;
		t >>>= 4;
	}
	if (t >= 0x02) {
		r += 2;
		t >>>= 2;
	}
	return r + t;
};

// Cooley-Tukey algorithm for FFT
// slightly revisited to rely on looping instead of recursion

class FFTM {

	makeRBT (N: number) {
		var t = new Array(N);
		var l = _countBits(N) - 1;
		for (var i = 0; i < N; i++) {
			t[i] = this.revBin(i, l, N);
		}

		return t;
	};

	// Returns binary-reversed representation of `x`
	revBin (x: number, l: number, N: number) {
		if (x === 0 || x === N - 1) return x;

		var rb = 0;
		for (var i = 0; i < l; i++) {
			rb |= (x & 1) << (l - i - 1);
			x >>= 1;
		}

		return rb;
	};

	// Performs "tweedling" phase, therefore 'emulating'
	// behaviour of the recursive algorithm
	permute (rbt: number[], rws: number[], iws: number[], rtws: number[], itws: number[], N: number) {
		for (var i = 0; i < N; i++) {
			rtws[i] = rws[rbt[i]];
			itws[i] = iws[rbt[i]];
		}
	};

	transform (rws: number[], iws: number[], rtws: number[], itws: number[], N: number, rbt: number[]) {
		this.permute(rbt, rws, iws, rtws, itws, N);

		for (var s = 1; s < N; s <<= 1) {
			var l = s << 1;

			var rtwdf = Math.cos(2 * Math.PI / l);
			var itwdf = Math.sin(2 * Math.PI / l);

			for (var p = 0; p < N; p += l) {
				var rtwdf_ = rtwdf;
				var itwdf_ = itwdf;

				for (var j = 0; j < s; j++) {
					var re = rtws[p + j];
					var ie = itws[p + j];

					var ro = rtws[p + j + s];
					var io = itws[p + j + s];

					var rx = rtwdf_ * ro - itwdf_ * io;

					io = rtwdf_ * io + itwdf_ * ro;
					ro = rx;

					rtws[p + j] = re + ro;
					itws[p + j] = ie + io;

					rtws[p + j + s] = re - ro;
					itws[p + j + s] = ie - io;

					/* jshint maxdepth : false */
					if (j !== l) {
						rx = rtwdf * rtwdf_ - itwdf * itwdf_;

						itwdf_ = rtwdf * itwdf_ + itwdf * rtwdf_;
						rtwdf_ = rx;
					}
				}
			}
		}
	};

	guessLen13b (n: number, m: number) {
		var N = Math.max(m, n) | 1;
		var odd = N & 1;
		var i = 0;
		for (N = N / 2 | 0; N; N = N >>> 1) {
			i++;
		}

		return 1 << i + 1 + odd;
	};

	conjugate (rws: number[], iws: number[], N: number) {
		if (N <= 1) return;

		for (var i = 0; i < N / 2; i++) {
			var t = rws[i];

			rws[i] = rws[N - i - 1];
			rws[N - i - 1] = t;

			t = iws[i];

			iws[i] = -iws[N - i - 1];
			iws[N - i - 1] = -t;
		}
	};

	normalize13b (ws: number[], N: number) {
		var carry = 0;
		for (var i = 0; i < N / 2; i++) {
			var w = Math.round(ws[2 * i + 1] / N) * 0x2000 +
				Math.round(ws[2 * i] / N) +
				carry;

			ws[i] = w & 0x3ffffff;

			if (w < 0x4000000) {
				carry = 0;
			} else {
				carry = w / 0x4000000 | 0;
			}
		}

		return ws;
	};

	convert13b (ws: number[], len: number, rws: number[], N: number) {
		var carry = 0;
		for (var i = 0; i < len; i++) {
			carry = carry + (ws[i] | 0);

			rws[2 * i] = carry & 0x1fff; carry = carry >>> 13;
			rws[2 * i + 1] = carry & 0x1fff; carry = carry >>> 13;
		}

		// Pad with zeroes
		for (i = 2 * len; i < N; ++i) {
			rws[i] = 0;
		}

		assert(carry === 0);
		assert((carry & ~0x1fff) === 0);
	};

	stub (N: number) {
		var ph = new Array(N);
		for (var i = 0; i < N; i++) {
			ph[i] = 0;
		}

		return ph;
	};

	mulp (x: BN, y: BN, out: BN) {
		var N = 2 * this.guessLen13b(x.length, y.length);

		var rbt = this.makeRBT(N);

		var _ = this.stub(N);

		var rws = new Array(N);
		var rwst = new Array(N);
		var iwst = new Array(N);

		var nrws = new Array(N);
		var nrwst = new Array(N);
		var niwst = new Array(N);

		var rmws = out.words;
		rmws.length = N;

		this.convert13b(x.words, x.length, rws, N);
		this.convert13b(y.words, y.length, nrws, N);

		this.transform(rws, _, rwst, iwst, N, rbt);
		this.transform(nrws, _, nrwst, niwst, N, rbt);

		for (var i = 0; i < N; i++) {
			var rx = rwst[i] * nrwst[i] - iwst[i] * niwst[i];
			iwst[i] = rwst[i] * niwst[i] + iwst[i] * nrwst[i];
			rwst[i] = rx;
		}

		this.conjugate(rwst, iwst, N);
		this.transform(rwst, iwst, rmws, _, N, rbt);
		this.conjugate(rmws, _, N);
		this.normalize13b(rmws, N);

		(out as any)._negative = x.negative ^ y.negative; // TODO private visit
		(out as any)._length = x.length + y.length; // TODO private visit
		return out.strip();
	};

}

export interface ArrayLikeMut<T> {
	readonly length: number;
	[n: number]: T;
}

export interface ArrayLikeMutConstructor<T> {
	new(length: number): ArrayLikeMut<T>;
}

export type Endian = 'be' | 'le';
// export type BNArg = number | string | ArrayLike<number> | BN;

export default class BN {

	private _negative: number;
	private _words: number[];
	private _length: number;
	private _red: Red | null;

	get negative() { return this._negative }
	get words() { return this._words }
	get length() { return this._length }
	get red() { return this._red }

	private static smallMulTo (self: BN, num: BN, out: BN) {
		out._negative = num._negative ^ self._negative;
		var len = (self._length + num.length) | 0;
		out._length = len;
		len = (len - 1) | 0;

		// Peel one iteration (compiler can't do it, because of code complexity)
		var a = self._words[0] | 0;
		var b = num._words[0] | 0;
		var r = a * b;

		var lo = r & 0x3ffffff;
		var carry = (r / 0x4000000) | 0;
		out._words[0] = lo;

		for (var k = 1; k < len; k++) {
			// Sum all words with the same `i + j = k` and accumulate `ncarry`,
			// note that ncarry could be >= 0x3ffffff
			var ncarry = carry >>> 26;
			var rword = carry & 0x3ffffff;
			var maxJ = Math.min(k, num.length - 1);
			for (var j = Math.max(0, k - self.length + 1); j <= maxJ; j++) {
				var i = (k - j) | 0;
				a = self._words[i] | 0;
				b = num._words[j] | 0;
				r = a * b + rword;
				ncarry += (r / 0x4000000) | 0;
				rword = r & 0x3ffffff;
			}
			out._words[k] = rword | 0;
			carry = ncarry | 0;
		}
		if (carry !== 0) {
			out._words[k] = carry | 0;
		} else {
			out._length--;
		}

		return out.strip();
	}

	// TODO(indutny): it may be reasonable to omit it for users who don't need
	// to work with 256-bit numbers, otherwise it gives 20% improvement for 256-bit
	// multiplication (like elliptic secp256k1).
	private static comb10MulTo = !Math.imul ? BN.smallMulTo: function (self: BN, num: BN, out: BN) {
		var a = self._words;
		var b = num._words;
		var o = out._words;
		var c = 0;
		var lo;
		var mid;
		var hi;
		var a0 = a[0] | 0;
		var al0 = a0 & 0x1fff;
		var ah0 = a0 >>> 13;
		var a1 = a[1] | 0;
		var al1 = a1 & 0x1fff;
		var ah1 = a1 >>> 13;
		var a2 = a[2] | 0;
		var al2 = a2 & 0x1fff;
		var ah2 = a2 >>> 13;
		var a3 = a[3] | 0;
		var al3 = a3 & 0x1fff;
		var ah3 = a3 >>> 13;
		var a4 = a[4] | 0;
		var al4 = a4 & 0x1fff;
		var ah4 = a4 >>> 13;
		var a5 = a[5] | 0;
		var al5 = a5 & 0x1fff;
		var ah5 = a5 >>> 13;
		var a6 = a[6] | 0;
		var al6 = a6 & 0x1fff;
		var ah6 = a6 >>> 13;
		var a7 = a[7] | 0;
		var al7 = a7 & 0x1fff;
		var ah7 = a7 >>> 13;
		var a8 = a[8] | 0;
		var al8 = a8 & 0x1fff;
		var ah8 = a8 >>> 13;
		var a9 = a[9] | 0;
		var al9 = a9 & 0x1fff;
		var ah9 = a9 >>> 13;
		var b0 = b[0] | 0;
		var bl0 = b0 & 0x1fff;
		var bh0 = b0 >>> 13;
		var b1 = b[1] | 0;
		var bl1 = b1 & 0x1fff;
		var bh1 = b1 >>> 13;
		var b2 = b[2] | 0;
		var bl2 = b2 & 0x1fff;
		var bh2 = b2 >>> 13;
		var b3 = b[3] | 0;
		var bl3 = b3 & 0x1fff;
		var bh3 = b3 >>> 13;
		var b4 = b[4] | 0;
		var bl4 = b4 & 0x1fff;
		var bh4 = b4 >>> 13;
		var b5 = b[5] | 0;
		var bl5 = b5 & 0x1fff;
		var bh5 = b5 >>> 13;
		var b6 = b[6] | 0;
		var bl6 = b6 & 0x1fff;
		var bh6 = b6 >>> 13;
		var b7 = b[7] | 0;
		var bl7 = b7 & 0x1fff;
		var bh7 = b7 >>> 13;
		var b8 = b[8] | 0;
		var bl8 = b8 & 0x1fff;
		var bh8 = b8 >>> 13;
		var b9 = b[9] | 0;
		var bl9 = b9 & 0x1fff;
		var bh9 = b9 >>> 13;

		out._negative = self._negative ^ num._negative;
		out._length = 19;
		/* k = 0 */
		lo = Math.imul(al0, bl0);
		mid = Math.imul(al0, bh0);
		mid = (mid + Math.imul(ah0, bl0)) | 0;
		hi = Math.imul(ah0, bh0);
		var w0 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
		c = (((hi + (mid >>> 13)) | 0) + (w0 >>> 26)) | 0;
		w0 &= 0x3ffffff;
		/* k = 1 */
		lo = Math.imul(al1, bl0);
		mid = Math.imul(al1, bh0);
		mid = (mid + Math.imul(ah1, bl0)) | 0;
		hi = Math.imul(ah1, bh0);
		lo = (lo + Math.imul(al0, bl1)) | 0;
		mid = (mid + Math.imul(al0, bh1)) | 0;
		mid = (mid + Math.imul(ah0, bl1)) | 0;
		hi = (hi + Math.imul(ah0, bh1)) | 0;
		var w1 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
		c = (((hi + (mid >>> 13)) | 0) + (w1 >>> 26)) | 0;
		w1 &= 0x3ffffff;
		/* k = 2 */
		lo = Math.imul(al2, bl0);
		mid = Math.imul(al2, bh0);
		mid = (mid + Math.imul(ah2, bl0)) | 0;
		hi = Math.imul(ah2, bh0);
		lo = (lo + Math.imul(al1, bl1)) | 0;
		mid = (mid + Math.imul(al1, bh1)) | 0;
		mid = (mid + Math.imul(ah1, bl1)) | 0;
		hi = (hi + Math.imul(ah1, bh1)) | 0;
		lo = (lo + Math.imul(al0, bl2)) | 0;
		mid = (mid + Math.imul(al0, bh2)) | 0;
		mid = (mid + Math.imul(ah0, bl2)) | 0;
		hi = (hi + Math.imul(ah0, bh2)) | 0;
		var w2 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
		c = (((hi + (mid >>> 13)) | 0) + (w2 >>> 26)) | 0;
		w2 &= 0x3ffffff;
		/* k = 3 */
		lo = Math.imul(al3, bl0);
		mid = Math.imul(al3, bh0);
		mid = (mid + Math.imul(ah3, bl0)) | 0;
		hi = Math.imul(ah3, bh0);
		lo = (lo + Math.imul(al2, bl1)) | 0;
		mid = (mid + Math.imul(al2, bh1)) | 0;
		mid = (mid + Math.imul(ah2, bl1)) | 0;
		hi = (hi + Math.imul(ah2, bh1)) | 0;
		lo = (lo + Math.imul(al1, bl2)) | 0;
		mid = (mid + Math.imul(al1, bh2)) | 0;
		mid = (mid + Math.imul(ah1, bl2)) | 0;
		hi = (hi + Math.imul(ah1, bh2)) | 0;
		lo = (lo + Math.imul(al0, bl3)) | 0;
		mid = (mid + Math.imul(al0, bh3)) | 0;
		mid = (mid + Math.imul(ah0, bl3)) | 0;
		hi = (hi + Math.imul(ah0, bh3)) | 0;
		var w3 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
		c = (((hi + (mid >>> 13)) | 0) + (w3 >>> 26)) | 0;
		w3 &= 0x3ffffff;
		/* k = 4 */
		lo = Math.imul(al4, bl0);
		mid = Math.imul(al4, bh0);
		mid = (mid + Math.imul(ah4, bl0)) | 0;
		hi = Math.imul(ah4, bh0);
		lo = (lo + Math.imul(al3, bl1)) | 0;
		mid = (mid + Math.imul(al3, bh1)) | 0;
		mid = (mid + Math.imul(ah3, bl1)) | 0;
		hi = (hi + Math.imul(ah3, bh1)) | 0;
		lo = (lo + Math.imul(al2, bl2)) | 0;
		mid = (mid + Math.imul(al2, bh2)) | 0;
		mid = (mid + Math.imul(ah2, bl2)) | 0;
		hi = (hi + Math.imul(ah2, bh2)) | 0;
		lo = (lo + Math.imul(al1, bl3)) | 0;
		mid = (mid + Math.imul(al1, bh3)) | 0;
		mid = (mid + Math.imul(ah1, bl3)) | 0;
		hi = (hi + Math.imul(ah1, bh3)) | 0;
		lo = (lo + Math.imul(al0, bl4)) | 0;
		mid = (mid + Math.imul(al0, bh4)) | 0;
		mid = (mid + Math.imul(ah0, bl4)) | 0;
		hi = (hi + Math.imul(ah0, bh4)) | 0;
		var w4 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
		c = (((hi + (mid >>> 13)) | 0) + (w4 >>> 26)) | 0;
		w4 &= 0x3ffffff;
		/* k = 5 */
		lo = Math.imul(al5, bl0);
		mid = Math.imul(al5, bh0);
		mid = (mid + Math.imul(ah5, bl0)) | 0;
		hi = Math.imul(ah5, bh0);
		lo = (lo + Math.imul(al4, bl1)) | 0;
		mid = (mid + Math.imul(al4, bh1)) | 0;
		mid = (mid + Math.imul(ah4, bl1)) | 0;
		hi = (hi + Math.imul(ah4, bh1)) | 0;
		lo = (lo + Math.imul(al3, bl2)) | 0;
		mid = (mid + Math.imul(al3, bh2)) | 0;
		mid = (mid + Math.imul(ah3, bl2)) | 0;
		hi = (hi + Math.imul(ah3, bh2)) | 0;
		lo = (lo + Math.imul(al2, bl3)) | 0;
		mid = (mid + Math.imul(al2, bh3)) | 0;
		mid = (mid + Math.imul(ah2, bl3)) | 0;
		hi = (hi + Math.imul(ah2, bh3)) | 0;
		lo = (lo + Math.imul(al1, bl4)) | 0;
		mid = (mid + Math.imul(al1, bh4)) | 0;
		mid = (mid + Math.imul(ah1, bl4)) | 0;
		hi = (hi + Math.imul(ah1, bh4)) | 0;
		lo = (lo + Math.imul(al0, bl5)) | 0;
		mid = (mid + Math.imul(al0, bh5)) | 0;
		mid = (mid + Math.imul(ah0, bl5)) | 0;
		hi = (hi + Math.imul(ah0, bh5)) | 0;
		var w5 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
		c = (((hi + (mid >>> 13)) | 0) + (w5 >>> 26)) | 0;
		w5 &= 0x3ffffff;
		/* k = 6 */
		lo = Math.imul(al6, bl0);
		mid = Math.imul(al6, bh0);
		mid = (mid + Math.imul(ah6, bl0)) | 0;
		hi = Math.imul(ah6, bh0);
		lo = (lo + Math.imul(al5, bl1)) | 0;
		mid = (mid + Math.imul(al5, bh1)) | 0;
		mid = (mid + Math.imul(ah5, bl1)) | 0;
		hi = (hi + Math.imul(ah5, bh1)) | 0;
		lo = (lo + Math.imul(al4, bl2)) | 0;
		mid = (mid + Math.imul(al4, bh2)) | 0;
		mid = (mid + Math.imul(ah4, bl2)) | 0;
		hi = (hi + Math.imul(ah4, bh2)) | 0;
		lo = (lo + Math.imul(al3, bl3)) | 0;
		mid = (mid + Math.imul(al3, bh3)) | 0;
		mid = (mid + Math.imul(ah3, bl3)) | 0;
		hi = (hi + Math.imul(ah3, bh3)) | 0;
		lo = (lo + Math.imul(al2, bl4)) | 0;
		mid = (mid + Math.imul(al2, bh4)) | 0;
		mid = (mid + Math.imul(ah2, bl4)) | 0;
		hi = (hi + Math.imul(ah2, bh4)) | 0;
		lo = (lo + Math.imul(al1, bl5)) | 0;
		mid = (mid + Math.imul(al1, bh5)) | 0;
		mid = (mid + Math.imul(ah1, bl5)) | 0;
		hi = (hi + Math.imul(ah1, bh5)) | 0;
		lo = (lo + Math.imul(al0, bl6)) | 0;
		mid = (mid + Math.imul(al0, bh6)) | 0;
		mid = (mid + Math.imul(ah0, bl6)) | 0;
		hi = (hi + Math.imul(ah0, bh6)) | 0;
		var w6 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
		c = (((hi + (mid >>> 13)) | 0) + (w6 >>> 26)) | 0;
		w6 &= 0x3ffffff;
		/* k = 7 */
		lo = Math.imul(al7, bl0);
		mid = Math.imul(al7, bh0);
		mid = (mid + Math.imul(ah7, bl0)) | 0;
		hi = Math.imul(ah7, bh0);
		lo = (lo + Math.imul(al6, bl1)) | 0;
		mid = (mid + Math.imul(al6, bh1)) | 0;
		mid = (mid + Math.imul(ah6, bl1)) | 0;
		hi = (hi + Math.imul(ah6, bh1)) | 0;
		lo = (lo + Math.imul(al5, bl2)) | 0;
		mid = (mid + Math.imul(al5, bh2)) | 0;
		mid = (mid + Math.imul(ah5, bl2)) | 0;
		hi = (hi + Math.imul(ah5, bh2)) | 0;
		lo = (lo + Math.imul(al4, bl3)) | 0;
		mid = (mid + Math.imul(al4, bh3)) | 0;
		mid = (mid + Math.imul(ah4, bl3)) | 0;
		hi = (hi + Math.imul(ah4, bh3)) | 0;
		lo = (lo + Math.imul(al3, bl4)) | 0;
		mid = (mid + Math.imul(al3, bh4)) | 0;
		mid = (mid + Math.imul(ah3, bl4)) | 0;
		hi = (hi + Math.imul(ah3, bh4)) | 0;
		lo = (lo + Math.imul(al2, bl5)) | 0;
		mid = (mid + Math.imul(al2, bh5)) | 0;
		mid = (mid + Math.imul(ah2, bl5)) | 0;
		hi = (hi + Math.imul(ah2, bh5)) | 0;
		lo = (lo + Math.imul(al1, bl6)) | 0;
		mid = (mid + Math.imul(al1, bh6)) | 0;
		mid = (mid + Math.imul(ah1, bl6)) | 0;
		hi = (hi + Math.imul(ah1, bh6)) | 0;
		lo = (lo + Math.imul(al0, bl7)) | 0;
		mid = (mid + Math.imul(al0, bh7)) | 0;
		mid = (mid + Math.imul(ah0, bl7)) | 0;
		hi = (hi + Math.imul(ah0, bh7)) | 0;
		var w7 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
		c = (((hi + (mid >>> 13)) | 0) + (w7 >>> 26)) | 0;
		w7 &= 0x3ffffff;
		/* k = 8 */
		lo = Math.imul(al8, bl0);
		mid = Math.imul(al8, bh0);
		mid = (mid + Math.imul(ah8, bl0)) | 0;
		hi = Math.imul(ah8, bh0);
		lo = (lo + Math.imul(al7, bl1)) | 0;
		mid = (mid + Math.imul(al7, bh1)) | 0;
		mid = (mid + Math.imul(ah7, bl1)) | 0;
		hi = (hi + Math.imul(ah7, bh1)) | 0;
		lo = (lo + Math.imul(al6, bl2)) | 0;
		mid = (mid + Math.imul(al6, bh2)) | 0;
		mid = (mid + Math.imul(ah6, bl2)) | 0;
		hi = (hi + Math.imul(ah6, bh2)) | 0;
		lo = (lo + Math.imul(al5, bl3)) | 0;
		mid = (mid + Math.imul(al5, bh3)) | 0;
		mid = (mid + Math.imul(ah5, bl3)) | 0;
		hi = (hi + Math.imul(ah5, bh3)) | 0;
		lo = (lo + Math.imul(al4, bl4)) | 0;
		mid = (mid + Math.imul(al4, bh4)) | 0;
		mid = (mid + Math.imul(ah4, bl4)) | 0;
		hi = (hi + Math.imul(ah4, bh4)) | 0;
		lo = (lo + Math.imul(al3, bl5)) | 0;
		mid = (mid + Math.imul(al3, bh5)) | 0;
		mid = (mid + Math.imul(ah3, bl5)) | 0;
		hi = (hi + Math.imul(ah3, bh5)) | 0;
		lo = (lo + Math.imul(al2, bl6)) | 0;
		mid = (mid + Math.imul(al2, bh6)) | 0;
		mid = (mid + Math.imul(ah2, bl6)) | 0;
		hi = (hi + Math.imul(ah2, bh6)) | 0;
		lo = (lo + Math.imul(al1, bl7)) | 0;
		mid = (mid + Math.imul(al1, bh7)) | 0;
		mid = (mid + Math.imul(ah1, bl7)) | 0;
		hi = (hi + Math.imul(ah1, bh7)) | 0;
		lo = (lo + Math.imul(al0, bl8)) | 0;
		mid = (mid + Math.imul(al0, bh8)) | 0;
		mid = (mid + Math.imul(ah0, bl8)) | 0;
		hi = (hi + Math.imul(ah0, bh8)) | 0;
		var w8 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
		c = (((hi + (mid >>> 13)) | 0) + (w8 >>> 26)) | 0;
		w8 &= 0x3ffffff;
		/* k = 9 */
		lo = Math.imul(al9, bl0);
		mid = Math.imul(al9, bh0);
		mid = (mid + Math.imul(ah9, bl0)) | 0;
		hi = Math.imul(ah9, bh0);
		lo = (lo + Math.imul(al8, bl1)) | 0;
		mid = (mid + Math.imul(al8, bh1)) | 0;
		mid = (mid + Math.imul(ah8, bl1)) | 0;
		hi = (hi + Math.imul(ah8, bh1)) | 0;
		lo = (lo + Math.imul(al7, bl2)) | 0;
		mid = (mid + Math.imul(al7, bh2)) | 0;
		mid = (mid + Math.imul(ah7, bl2)) | 0;
		hi = (hi + Math.imul(ah7, bh2)) | 0;
		lo = (lo + Math.imul(al6, bl3)) | 0;
		mid = (mid + Math.imul(al6, bh3)) | 0;
		mid = (mid + Math.imul(ah6, bl3)) | 0;
		hi = (hi + Math.imul(ah6, bh3)) | 0;
		lo = (lo + Math.imul(al5, bl4)) | 0;
		mid = (mid + Math.imul(al5, bh4)) | 0;
		mid = (mid + Math.imul(ah5, bl4)) | 0;
		hi = (hi + Math.imul(ah5, bh4)) | 0;
		lo = (lo + Math.imul(al4, bl5)) | 0;
		mid = (mid + Math.imul(al4, bh5)) | 0;
		mid = (mid + Math.imul(ah4, bl5)) | 0;
		hi = (hi + Math.imul(ah4, bh5)) | 0;
		lo = (lo + Math.imul(al3, bl6)) | 0;
		mid = (mid + Math.imul(al3, bh6)) | 0;
		mid = (mid + Math.imul(ah3, bl6)) | 0;
		hi = (hi + Math.imul(ah3, bh6)) | 0;
		lo = (lo + Math.imul(al2, bl7)) | 0;
		mid = (mid + Math.imul(al2, bh7)) | 0;
		mid = (mid + Math.imul(ah2, bl7)) | 0;
		hi = (hi + Math.imul(ah2, bh7)) | 0;
		lo = (lo + Math.imul(al1, bl8)) | 0;
		mid = (mid + Math.imul(al1, bh8)) | 0;
		mid = (mid + Math.imul(ah1, bl8)) | 0;
		hi = (hi + Math.imul(ah1, bh8)) | 0;
		lo = (lo + Math.imul(al0, bl9)) | 0;
		mid = (mid + Math.imul(al0, bh9)) | 0;
		mid = (mid + Math.imul(ah0, bl9)) | 0;
		hi = (hi + Math.imul(ah0, bh9)) | 0;
		var w9 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
		c = (((hi + (mid >>> 13)) | 0) + (w9 >>> 26)) | 0;
		w9 &= 0x3ffffff;
		/* k = 10 */
		lo = Math.imul(al9, bl1);
		mid = Math.imul(al9, bh1);
		mid = (mid + Math.imul(ah9, bl1)) | 0;
		hi = Math.imul(ah9, bh1);
		lo = (lo + Math.imul(al8, bl2)) | 0;
		mid = (mid + Math.imul(al8, bh2)) | 0;
		mid = (mid + Math.imul(ah8, bl2)) | 0;
		hi = (hi + Math.imul(ah8, bh2)) | 0;
		lo = (lo + Math.imul(al7, bl3)) | 0;
		mid = (mid + Math.imul(al7, bh3)) | 0;
		mid = (mid + Math.imul(ah7, bl3)) | 0;
		hi = (hi + Math.imul(ah7, bh3)) | 0;
		lo = (lo + Math.imul(al6, bl4)) | 0;
		mid = (mid + Math.imul(al6, bh4)) | 0;
		mid = (mid + Math.imul(ah6, bl4)) | 0;
		hi = (hi + Math.imul(ah6, bh4)) | 0;
		lo = (lo + Math.imul(al5, bl5)) | 0;
		mid = (mid + Math.imul(al5, bh5)) | 0;
		mid = (mid + Math.imul(ah5, bl5)) | 0;
		hi = (hi + Math.imul(ah5, bh5)) | 0;
		lo = (lo + Math.imul(al4, bl6)) | 0;
		mid = (mid + Math.imul(al4, bh6)) | 0;
		mid = (mid + Math.imul(ah4, bl6)) | 0;
		hi = (hi + Math.imul(ah4, bh6)) | 0;
		lo = (lo + Math.imul(al3, bl7)) | 0;
		mid = (mid + Math.imul(al3, bh7)) | 0;
		mid = (mid + Math.imul(ah3, bl7)) | 0;
		hi = (hi + Math.imul(ah3, bh7)) | 0;
		lo = (lo + Math.imul(al2, bl8)) | 0;
		mid = (mid + Math.imul(al2, bh8)) | 0;
		mid = (mid + Math.imul(ah2, bl8)) | 0;
		hi = (hi + Math.imul(ah2, bh8)) | 0;
		lo = (lo + Math.imul(al1, bl9)) | 0;
		mid = (mid + Math.imul(al1, bh9)) | 0;
		mid = (mid + Math.imul(ah1, bl9)) | 0;
		hi = (hi + Math.imul(ah1, bh9)) | 0;
		var w10 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
		c = (((hi + (mid >>> 13)) | 0) + (w10 >>> 26)) | 0;
		w10 &= 0x3ffffff;
		/* k = 11 */
		lo = Math.imul(al9, bl2);
		mid = Math.imul(al9, bh2);
		mid = (mid + Math.imul(ah9, bl2)) | 0;
		hi = Math.imul(ah9, bh2);
		lo = (lo + Math.imul(al8, bl3)) | 0;
		mid = (mid + Math.imul(al8, bh3)) | 0;
		mid = (mid + Math.imul(ah8, bl3)) | 0;
		hi = (hi + Math.imul(ah8, bh3)) | 0;
		lo = (lo + Math.imul(al7, bl4)) | 0;
		mid = (mid + Math.imul(al7, bh4)) | 0;
		mid = (mid + Math.imul(ah7, bl4)) | 0;
		hi = (hi + Math.imul(ah7, bh4)) | 0;
		lo = (lo + Math.imul(al6, bl5)) | 0;
		mid = (mid + Math.imul(al6, bh5)) | 0;
		mid = (mid + Math.imul(ah6, bl5)) | 0;
		hi = (hi + Math.imul(ah6, bh5)) | 0;
		lo = (lo + Math.imul(al5, bl6)) | 0;
		mid = (mid + Math.imul(al5, bh6)) | 0;
		mid = (mid + Math.imul(ah5, bl6)) | 0;
		hi = (hi + Math.imul(ah5, bh6)) | 0;
		lo = (lo + Math.imul(al4, bl7)) | 0;
		mid = (mid + Math.imul(al4, bh7)) | 0;
		mid = (mid + Math.imul(ah4, bl7)) | 0;
		hi = (hi + Math.imul(ah4, bh7)) | 0;
		lo = (lo + Math.imul(al3, bl8)) | 0;
		mid = (mid + Math.imul(al3, bh8)) | 0;
		mid = (mid + Math.imul(ah3, bl8)) | 0;
		hi = (hi + Math.imul(ah3, bh8)) | 0;
		lo = (lo + Math.imul(al2, bl9)) | 0;
		mid = (mid + Math.imul(al2, bh9)) | 0;
		mid = (mid + Math.imul(ah2, bl9)) | 0;
		hi = (hi + Math.imul(ah2, bh9)) | 0;
		var w11 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
		c = (((hi + (mid >>> 13)) | 0) + (w11 >>> 26)) | 0;
		w11 &= 0x3ffffff;
		/* k = 12 */
		lo = Math.imul(al9, bl3);
		mid = Math.imul(al9, bh3);
		mid = (mid + Math.imul(ah9, bl3)) | 0;
		hi = Math.imul(ah9, bh3);
		lo = (lo + Math.imul(al8, bl4)) | 0;
		mid = (mid + Math.imul(al8, bh4)) | 0;
		mid = (mid + Math.imul(ah8, bl4)) | 0;
		hi = (hi + Math.imul(ah8, bh4)) | 0;
		lo = (lo + Math.imul(al7, bl5)) | 0;
		mid = (mid + Math.imul(al7, bh5)) | 0;
		mid = (mid + Math.imul(ah7, bl5)) | 0;
		hi = (hi + Math.imul(ah7, bh5)) | 0;
		lo = (lo + Math.imul(al6, bl6)) | 0;
		mid = (mid + Math.imul(al6, bh6)) | 0;
		mid = (mid + Math.imul(ah6, bl6)) | 0;
		hi = (hi + Math.imul(ah6, bh6)) | 0;
		lo = (lo + Math.imul(al5, bl7)) | 0;
		mid = (mid + Math.imul(al5, bh7)) | 0;
		mid = (mid + Math.imul(ah5, bl7)) | 0;
		hi = (hi + Math.imul(ah5, bh7)) | 0;
		lo = (lo + Math.imul(al4, bl8)) | 0;
		mid = (mid + Math.imul(al4, bh8)) | 0;
		mid = (mid + Math.imul(ah4, bl8)) | 0;
		hi = (hi + Math.imul(ah4, bh8)) | 0;
		lo = (lo + Math.imul(al3, bl9)) | 0;
		mid = (mid + Math.imul(al3, bh9)) | 0;
		mid = (mid + Math.imul(ah3, bl9)) | 0;
		hi = (hi + Math.imul(ah3, bh9)) | 0;
		var w12 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
		c = (((hi + (mid >>> 13)) | 0) + (w12 >>> 26)) | 0;
		w12 &= 0x3ffffff;
		/* k = 13 */
		lo = Math.imul(al9, bl4);
		mid = Math.imul(al9, bh4);
		mid = (mid + Math.imul(ah9, bl4)) | 0;
		hi = Math.imul(ah9, bh4);
		lo = (lo + Math.imul(al8, bl5)) | 0;
		mid = (mid + Math.imul(al8, bh5)) | 0;
		mid = (mid + Math.imul(ah8, bl5)) | 0;
		hi = (hi + Math.imul(ah8, bh5)) | 0;
		lo = (lo + Math.imul(al7, bl6)) | 0;
		mid = (mid + Math.imul(al7, bh6)) | 0;
		mid = (mid + Math.imul(ah7, bl6)) | 0;
		hi = (hi + Math.imul(ah7, bh6)) | 0;
		lo = (lo + Math.imul(al6, bl7)) | 0;
		mid = (mid + Math.imul(al6, bh7)) | 0;
		mid = (mid + Math.imul(ah6, bl7)) | 0;
		hi = (hi + Math.imul(ah6, bh7)) | 0;
		lo = (lo + Math.imul(al5, bl8)) | 0;
		mid = (mid + Math.imul(al5, bh8)) | 0;
		mid = (mid + Math.imul(ah5, bl8)) | 0;
		hi = (hi + Math.imul(ah5, bh8)) | 0;
		lo = (lo + Math.imul(al4, bl9)) | 0;
		mid = (mid + Math.imul(al4, bh9)) | 0;
		mid = (mid + Math.imul(ah4, bl9)) | 0;
		hi = (hi + Math.imul(ah4, bh9)) | 0;
		var w13 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
		c = (((hi + (mid >>> 13)) | 0) + (w13 >>> 26)) | 0;
		w13 &= 0x3ffffff;
		/* k = 14 */
		lo = Math.imul(al9, bl5);
		mid = Math.imul(al9, bh5);
		mid = (mid + Math.imul(ah9, bl5)) | 0;
		hi = Math.imul(ah9, bh5);
		lo = (lo + Math.imul(al8, bl6)) | 0;
		mid = (mid + Math.imul(al8, bh6)) | 0;
		mid = (mid + Math.imul(ah8, bl6)) | 0;
		hi = (hi + Math.imul(ah8, bh6)) | 0;
		lo = (lo + Math.imul(al7, bl7)) | 0;
		mid = (mid + Math.imul(al7, bh7)) | 0;
		mid = (mid + Math.imul(ah7, bl7)) | 0;
		hi = (hi + Math.imul(ah7, bh7)) | 0;
		lo = (lo + Math.imul(al6, bl8)) | 0;
		mid = (mid + Math.imul(al6, bh8)) | 0;
		mid = (mid + Math.imul(ah6, bl8)) | 0;
		hi = (hi + Math.imul(ah6, bh8)) | 0;
		lo = (lo + Math.imul(al5, bl9)) | 0;
		mid = (mid + Math.imul(al5, bh9)) | 0;
		mid = (mid + Math.imul(ah5, bl9)) | 0;
		hi = (hi + Math.imul(ah5, bh9)) | 0;
		var w14 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
		c = (((hi + (mid >>> 13)) | 0) + (w14 >>> 26)) | 0;
		w14 &= 0x3ffffff;
		/* k = 15 */
		lo = Math.imul(al9, bl6);
		mid = Math.imul(al9, bh6);
		mid = (mid + Math.imul(ah9, bl6)) | 0;
		hi = Math.imul(ah9, bh6);
		lo = (lo + Math.imul(al8, bl7)) | 0;
		mid = (mid + Math.imul(al8, bh7)) | 0;
		mid = (mid + Math.imul(ah8, bl7)) | 0;
		hi = (hi + Math.imul(ah8, bh7)) | 0;
		lo = (lo + Math.imul(al7, bl8)) | 0;
		mid = (mid + Math.imul(al7, bh8)) | 0;
		mid = (mid + Math.imul(ah7, bl8)) | 0;
		hi = (hi + Math.imul(ah7, bh8)) | 0;
		lo = (lo + Math.imul(al6, bl9)) | 0;
		mid = (mid + Math.imul(al6, bh9)) | 0;
		mid = (mid + Math.imul(ah6, bl9)) | 0;
		hi = (hi + Math.imul(ah6, bh9)) | 0;
		var w15 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
		c = (((hi + (mid >>> 13)) | 0) + (w15 >>> 26)) | 0;
		w15 &= 0x3ffffff;
		/* k = 16 */
		lo = Math.imul(al9, bl7);
		mid = Math.imul(al9, bh7);
		mid = (mid + Math.imul(ah9, bl7)) | 0;
		hi = Math.imul(ah9, bh7);
		lo = (lo + Math.imul(al8, bl8)) | 0;
		mid = (mid + Math.imul(al8, bh8)) | 0;
		mid = (mid + Math.imul(ah8, bl8)) | 0;
		hi = (hi + Math.imul(ah8, bh8)) | 0;
		lo = (lo + Math.imul(al7, bl9)) | 0;
		mid = (mid + Math.imul(al7, bh9)) | 0;
		mid = (mid + Math.imul(ah7, bl9)) | 0;
		hi = (hi + Math.imul(ah7, bh9)) | 0;
		var w16 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
		c = (((hi + (mid >>> 13)) | 0) + (w16 >>> 26)) | 0;
		w16 &= 0x3ffffff;
		/* k = 17 */
		lo = Math.imul(al9, bl8);
		mid = Math.imul(al9, bh8);
		mid = (mid + Math.imul(ah9, bl8)) | 0;
		hi = Math.imul(ah9, bh8);
		lo = (lo + Math.imul(al8, bl9)) | 0;
		mid = (mid + Math.imul(al8, bh9)) | 0;
		mid = (mid + Math.imul(ah8, bl9)) | 0;
		hi = (hi + Math.imul(ah8, bh9)) | 0;
		var w17 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
		c = (((hi + (mid >>> 13)) | 0) + (w17 >>> 26)) | 0;
		w17 &= 0x3ffffff;
		/* k = 18 */
		lo = Math.imul(al9, bl9);
		mid = Math.imul(al9, bh9);
		mid = (mid + Math.imul(ah9, bl9)) | 0;
		hi = Math.imul(ah9, bh9);
		var w18 = (((c + lo) | 0) + ((mid & 0x1fff) << 13)) | 0;
		c = (((hi + (mid >>> 13)) | 0) + (w18 >>> 26)) | 0;
		w18 &= 0x3ffffff;
		o[0] = w0;
		o[1] = w1;
		o[2] = w2;
		o[3] = w3;
		o[4] = w4;
		o[5] = w5;
		o[6] = w6;
		o[7] = w7;
		o[8] = w8;
		o[9] = w9;
		o[10] = w10;
		o[11] = w11;
		o[12] = w12;
		o[13] = w13;
		o[14] = w14;
		o[15] = w15;
		o[16] = w16;
		o[17] = w17;
		o[18] = w18;
		if (c !== 0) {
			o[19] = c;
			out._length++;
		}
		return out;
	};

	private static bigMulTo (self: BN, num: BN, out: BN) {
		out._negative = num._negative ^ self._negative;
		out._length = self.length + num.length;

		var carry = 0;
		var hncarry = 0;
		for (var k = 0; k < out.length - 1; k++) {
			// Sum all words with the same `i + j = k` and accumulate `ncarry`,
			// note that ncarry could be >= 0x3ffffff
			var ncarry = hncarry;
			hncarry = 0;
			var rword = carry & 0x3ffffff;
			var maxJ = Math.min(k, num.length - 1);
			for (var j = Math.max(0, k - self.length + 1); j <= maxJ; j++) {
				var i = k - j;
				var a = self._words[i] | 0;
				var b = num._words[j] | 0;
				var r = a * b;

				var lo = r & 0x3ffffff;
				ncarry = (ncarry + ((r / 0x4000000) | 0)) | 0;
				lo = (lo + rword) | 0;
				rword = lo & 0x3ffffff;
				ncarry = (ncarry + (lo >>> 26)) | 0;

				hncarry += ncarry >>> 26;
				ncarry &= 0x3ffffff;
			}
			out._words[k] = rword;
			carry = ncarry;
			ncarry = hncarry;
		}
		if (carry !== 0) {
			out._words[k] = carry;
		} else {
			out._length--;
		}

		return out.strip();
	}

	constructor(
		number: number | string | ArrayLike<number> | BN | null,
		base?: number | 'hex' | Endian,
		endian?: Endian
	)
	{
		if (BN.isBN(number)) {
			return number as BN;
		}

		this._negative = 0;
		this._words = [0];
		this._length = 1;

		// Reduction context
		this._red = null;

		var _base = 10;

		if (number !== null) {
			if (base === 'le' || base === 'be') {
				endian = base;
				_base = 10;
			} else if (base == 'hex') {
				_base = 16;
			}
			this._init((number || 0) as (number | string | ArrayLike<number>), _base, endian || 'be');
		}
	}

	static wordSize = 26;

	static isBN(num: any) {
		if (num instanceof BN) {
			return true;
		}
		return num !== null && typeof num === 'object' &&
			num.constructor.wordSize === BN.wordSize && Array.isArray(num._words) && num._words.length;
	};

	static max(left: BN, right: BN) {
		if (left.cmp(right) > 0) return left;
		return right;
	};

	static min(left: BN, right: BN) {
		if (left.cmp(right) < 0) return left;
		return right;
	};

	private _init (number: number | string | ArrayLike<number>, base: number, endian: Endian) {
		if (typeof number === 'number') {
			return this._initNumber(number, base, endian);
		}

		if (typeof number === 'object') {
			return this._initArray(number, base, endian);
		}

		assert(base === (base | 0) && base >= 2 && base <= 36);

		number = number.toString().replace(/\s+/g, '');
		var start = 0;
		if (number[0] === '-') {
			start++;
		}

		if (base === 16) {
			this._parseHex(number, start);
		} else {
			this._parseBase(number, base, start);
		}

		if (number[0] === '-') {
			this._negative = 1;
		}

		this.strip();

		if (endian !== 'le') 
			return;

		this._initArray(this.toArray(), base, endian);
	};

	private _initNumber (number: number, base: number, endian: Endian) {
		if (number < 0) {
			this._negative = 1;
			number = -number;
		}
		if (number < 0x4000000) {
			this._words = [ number & 0x3ffffff ];
			this._length = 1;
		} else if (number < 0x10000000000000) {
			this._words = [
				number & 0x3ffffff,
				(number / 0x4000000) & 0x3ffffff
			];
			this._length = 2;
		} else {
			assert(number < 0x20000000000000); // 2 ^ 53 (unsafe)
			this._words = [
				number & 0x3ffffff,
				(number / 0x4000000) & 0x3ffffff,
				1
			];
			this._length = 3;
		}

		if (endian !== 'le') return;

		// Reverse the bytes
		this._initArray(this.toArray(), base, endian);
	};

	private _initArray (number: ArrayLike<number>, base: number, endian: Endian) {
		// Perhaps a Uint8Array
		assert(typeof number.length === 'number');
		if (number.length <= 0) {
			this._words = [ 0 ];
			this._length = 1;
			return this;
		}

		this._length = Math.ceil(number.length / 3);
		this._words = new Array(this._length);
		for (var i = 0; i < this._length; i++) {
			this._words[i] = 0;
		}

		var j, w;
		var off = 0;
		if (endian === 'be') {
			for (i = number.length - 1, j = 0; i >= 0; i -= 3) {
				w = number[i] | (number[i - 1] << 8) | (number[i - 2] << 16);
				this._words[j] |= (w << off) & 0x3ffffff;
				this._words[j + 1] = (w >>> (26 - off)) & 0x3ffffff;
				off += 24;
				if (off >= 26) {
					off -= 26;
					j++;
				}
			}
		} else if (endian === 'le') {
			for (i = 0, j = 0; i < number.length; i += 3) {
				w = number[i] | (number[i + 1] << 8) | (number[i + 2] << 16);
				this._words[j] |= (w << off) & 0x3ffffff;
				this._words[j + 1] = (w >>> (26 - off)) & 0x3ffffff;
				off += 24;
				if (off >= 26) {
					off -= 26;
					j++;
				}
			}
		}
		return this.strip();
	};

	private _parseHex (number: string, start: number) {
		// Create possibly bigger array to ensure that it fits the number
		this._length = Math.ceil((number.length - start) / 6);
		this._words = new Array(this._length);
		for (var i = 0; i < this._length; i++) {
			this._words[i] = 0;
		}

		var j, w;
		// Scan 24-bit chunks and add them to the number
		var off = 0;
		for (i = number.length - 6, j = 0; i >= start; i -= 6) {
			w = parseHex(number, i, i + 6);
			this._words[j] |= (w << off) & 0x3ffffff;
			// NOTE: `0x3fffff` is intentional here, 26bits max shift + 24bit hex limb
			this._words[j + 1] |= w >>> (26 - off) & 0x3fffff;
			off += 24;
			if (off >= 26) {
				off -= 26;
				j++;
			}
		}
		if (i + 6 !== start) {
			w = parseHex(number, start, i + 6);
			this._words[j] |= (w << off) & 0x3ffffff;
			this._words[j + 1] |= w >>> (26 - off) & 0x3fffff;
		}
		this.strip();
	};

	private _parseBase (number: string, base: number, start: number) {
		// Initialize as zero
		this._words = [ 0 ];
		this._length = 1;

		// Find length of limb in base
		for (var limbLen = 0, limbPow = 1; limbPow <= 0x3ffffff; limbPow *= base) {
			limbLen++;
		}
		limbLen--;
		limbPow = (limbPow / base) | 0;

		var total = number.length - start;
		var mod = total % limbLen;
		var end = Math.min(total, total - mod) + start;

		var word = 0;
		for (var i = start; i < end; i += limbLen) {
			word = parseBase(number, i, i + limbLen, base);

			this.imuln(limbPow);
			if (this._words[0] + word < 0x4000000) {
				this._words[0] += word;
			} else {
				this._iaddn(word);
			}
		}

		if (mod !== 0) {
			var pow = 1;
			word = parseBase(number, i, number.length, base);

			for (i = 0; i < mod; i++) {
				pow *= base;
			}

			this.imuln(pow);
			if (this._words[0] + word < 0x4000000) {
				this._words[0] += word;
			} else {
				this._iaddn(word);
			}
		}
	};

	copy (dest: BN) {
		dest._words = new Array(this._length);
		for (var i = 0; i < this._length; i++) {
			dest._words[i] = this._words[i];
		}
		dest._length = this._length;
		dest._negative = this._negative;
		dest._red = this.red;
	};

	clone () {
		var r = new BN(null);
		this.copy(r);
		return r;
	};

	private _expand (size: number) {
		while (this._length < size) {
			this._words[this._length++] = 0;
		}
		return this;
	};

	// Remove leading `0` from `this`
	strip () {
		while (this._length > 1 && this._words[this._length - 1] === 0) {
			this._length--;
		}
		return this._normSign();
	};

	private _normSign () {
		// -0 = 0
		if (this._length === 1 && this._words[0] === 0) {
			this._negative = 0;
		}
		return this;
	};

	inspect () {
		return (this.red ? '<BN-R: ' : '<BN: ') + this.toString(16) + '>';
	};

	toString (base: number | 'hex', _padding?: number) {
		base = base || 10;
		var padding = _padding as number | 0 || 1;

		var out;
		if (base === 16 || base === 'hex') {
			out = '';
			var off = 0;
			var carry = 0;
			for (var i = 0; i < this._length; i++) {
				var w = this._words[i];
				var word = (((w << off) | carry) & 0xffffff).toString(16);
				carry = (w >>> (24 - off)) & 0xffffff;
				if (carry !== 0 || i !== this._length - 1) {
					out = zeros[6 - word.length] + word + out;
				} else {
					out = word + out;
				}
				off += 2;
				if (off >= 26) {
					off -= 26;
					i--;
				}
			}
			if (carry !== 0) {
				out = carry.toString(16) + out;
			}
			while (out.length % padding !== 0) {
				out = '0' + out;
			}
			if (this._negative !== 0) {
				out = '-' + out;
			}
			return out;
		}

		if (base === (base | 0) && base >= 2 && base <= 36) {
			// var groupSize = Math.floor(BN.wordSize * Math.LN2 / Math.log(base));
			var groupSize = groupSizes[base];
			// var groupBase = Math.pow(base, groupSize);
			var groupBase = groupBases[base];
			out = '';
			var c = this.clone();
			c._negative = 0;
			while (!c.isZero()) {
				var r = c.modn(groupBase).toString(base);
				c = c.idivn(groupBase);

				if (!c.isZero()) {
					out = zeros[groupSize - r.length] + r + out;
				} else {
					out = r + out;
				}
			}
			if (this.isZero()) {
				out = '0' + out;
			}
			while (out.length % padding !== 0) {
				out = '0' + out;
			}
			if (this._negative !== 0) {
				out = '-' + out;
			}
			return out;
		}

		assert(false, 'Base should be between 2 and 36');
	};

	toNumber () {
		var ret = this._words[0];
		if (this._length === 2) {
			ret += this._words[1] * 0x4000000;
		} else if (this._length === 3 && this._words[2] === 0x01) {
			// NOTE: at this stage it is known that the top bit is set
			ret += 0x10000000000000 + (this._words[1] * 0x4000000);
		} else if (this._length > 2) {
			assert(false, 'Number can only safely store up to 53 bits');
		}
		return (this._negative !== 0) ? -ret : ret;
	};

	toJSON () {
		return this.toString(16);
	};

	toBuffer (endian?: Endian, length?: number) {
		// assert(typeof Buffer !== 'undefined');
		return this.toArrayLike(IBufferIMPL, endian, length) as IBuffer;
	};

	toArray (endian?: Endian, length?: number) {
		return this.toArrayLike(Array, endian, length) as number[];
	};

	toArrayLike (ArrayType: ArrayLikeMutConstructor<number>, endian?: Endian, length?: number) {
		var byteLength = this.byteLength();
		var reqLength = length || Math.max(1, byteLength);
		assert(byteLength <= reqLength, 'byte array longer than desired length');
		assert(reqLength > 0, 'Requested array length <= 0');

		this.strip();
		var littleEndian = endian === 'le';
		var res = new ArrayType(reqLength);

		var b, i;
		var q = this.clone();
		if (!littleEndian) {
			// Assume big-endian
			for (i = 0; i < reqLength - byteLength; i++) {
				res[i] = 0;
			}

			for (i = 0; !q.isZero(); i++) {
				b = q.andln(0xff);
				q.iushrn(8);

				res[reqLength - i - 1] = b;
			}
		} else {
			for (i = 0; !q.isZero(); i++) {
				b = q.andln(0xff);
				q.iushrn(8);

				res[i] = b;
			}

			for (; i < reqLength; i++) {
				res[i] = 0;
			}
		}

		return res;
	};

	private _zeroBits (w: number) {
		// Short-cut
		if (w === 0) return 26;

		var t = w;
		var r = 0;
		if ((t & 0x1fff) === 0) {
			r += 13;
			t >>>= 13;
		}
		if ((t & 0x7f) === 0) {
			r += 7;
			t >>>= 7;
		}
		if ((t & 0xf) === 0) {
			r += 4;
			t >>>= 4;
		}
		if ((t & 0x3) === 0) {
			r += 2;
			t >>>= 2;
		}
		if ((t & 0x1) === 0) {
			r++;
		}
		return r;
	};

	// Return number of used bits in a BN
	bitLength () {
		var w = this._words[this._length - 1];
		var hi = _countBits(w);
		return (this._length - 1) * 26 + hi;
	};

	// Number of trailing zero bits
	zeroBits () {
		if (this.isZero()) return 0;

		var r = 0;
		for (var i = 0; i < this._length; i++) {
			var b = this._zeroBits(this._words[i]);
			r += b;
			if (b !== 26) break;
		}
		return r;
	};

	byteLength () {
		return Math.ceil(this.bitLength() / 8);
	};

	toTwos (width: number) {
		if (this._negative !== 0) {
			return this.abs().inotn(width).iaddn(1);
		}
		return this.clone();
	};

	fromTwos (width: number) {
		if (this.testn(width - 1)) {
			return this.notn(width).iaddn(1).ineg();
		}
		return this.clone();
	};

	isNeg () {
		return this._negative !== 0;
	};

	// Return negative clone of `this`
	neg () {
		return this.clone().ineg();
	};

	ineg () {
		if (!this.isZero()) {
			this._negative ^= 1;
		}

		return this;
	};

	// Or `num` with `this` in-place
	iuor (num: BN) {
		while (this._length < num.length) {
			this._words[this._length++] = 0;
		}

		for (var i = 0; i < num.length; i++) {
			this._words[i] = this._words[i] | num._words[i];
		}

		return this.strip();
	};

	ior (num: BN) {
		assert((this._negative | num._negative) === 0);
		return this.iuor(num);
	};

	// Or `num` with `this`
	or (num: BN) {
		if (this._length > num.length) return this.clone().ior(num);
		return num.clone().ior(this);
	};

	uor (num: BN) {
		if (this._length > num.length) return this.clone().iuor(num);
		return num.clone().iuor(this);
	};

	// And `num` with `this` in-place
	iuand (num: BN) {
		// b = min-length(num, this)
		var b;
		if (this._length > num.length) {
			b = num;
		} else {
			b = this;
		}

		for (var i = 0; i < b.length; i++) {
			this._words[i] = this._words[i] & num._words[i];
		}

		this._length = b.length;

		return this.strip();
	};

	iand (num: BN) {
		assert((this._negative | num._negative) === 0);
		return this.iuand(num);
	};

	// And `num` with `this`
	and (num: BN) {
		if (this._length > num.length) return this.clone().iand(num);
		return num.clone().iand(this);
	};

	uand (num: BN) {
		if (this._length > num.length) return this.clone().iuand(num);
		return num.clone().iuand(this);
	};

	// Xor `num` with `this` in-place
	iuxor (num: BN) {
		// a.length > b.length
		var a;
		var b;
		if (this._length > num.length) {
			a = this;
			b = num;
		} else {
			a = num;
			b = this;
		}

		for (var i = 0; i < b.length; i++) {
			this._words[i] = a._words[i] ^ b._words[i];
		}

		if (this !== a) {
			for (; i < a.length; i++) {
				this._words[i] = a._words[i];
			}
		}

		this._length = a.length;

		return this.strip();
	};

	ixor (num: BN) {
		assert((this._negative | num._negative) === 0);
		return this.iuxor(num);
	};

	// Xor `num` with `this`
	xor (num: BN) {
		if (this._length > num.length) return this.clone().ixor(num);
		return num.clone().ixor(this);
	};

	uxor (num: BN) {
		if (this._length > num.length) return this.clone().iuxor(num);
		return num.clone().iuxor(this);
	};

	// Not ``this`` with ``width`` bitwidth
	inotn (width: number) {
		assert(typeof width === 'number' && width >= 0);

		var bytesNeeded = Math.ceil(width / 26) | 0;
		var bitsLeft = width % 26;

		// Extend the buffer with leading zeroes
		this._expand(bytesNeeded);

		if (bitsLeft > 0) {
			bytesNeeded--;
		}

		// Handle complete words
		for (var i = 0; i < bytesNeeded; i++) {
			this._words[i] = ~this._words[i] & 0x3ffffff;
		}

		// Handle the residue
		if (bitsLeft > 0) {
			this._words[i] = ~this._words[i] & (0x3ffffff >> (26 - bitsLeft));
		}

		// And remove leading zeroes
		return this.strip();
	};

	notn (width: number) {
		return this.clone().inotn(width);
	};

	// Set `bit` of `this`
	setn (bit: number, val?: boolean) {
		assert(typeof bit === 'number' && bit >= 0);

		var off = (bit / 26) | 0;
		var wbit = bit % 26;

		this._expand(off + 1);

		if (val) {
			this._words[off] = this._words[off] | (1 << wbit);
		} else {
			this._words[off] = this._words[off] & ~(1 << wbit);
		}

		return this.strip();
	};

	// Add `num` to `this` in-place
	iadd (num: BN) {
		var r: BN;

		// negative + positive
		if (this._negative !== 0 && num._negative === 0) {
			this._negative = 0;
			r = this.isub(num);
			this._negative ^= 1;
			return this._normSign();

		// positive + negative
		} else if (this._negative === 0 && num._negative !== 0) {
			num._negative = 0;
			r = this.isub(num);
			num._negative = 1;
			return r._normSign();
		}

		// a.length > b.length
		var a, b;
		if (this._length > num.length) {
			a = this;
			b = num;
		} else {
			a = num;
			b = this;
		}

		var carry = 0;
		var _r: number;
		for (var i = 0; i < b.length; i++) {
			_r = (a._words[i] | 0) + (b._words[i] | 0) + carry;
			this._words[i] = _r & 0x3ffffff;
			carry = _r >>> 26;
		}
		for (; carry !== 0 && i < a.length; i++) {
			_r = (a._words[i] | 0) + carry;
			this._words[i] = _r & 0x3ffffff;
			carry = _r >>> 26;
		}

		this._length = a.length;
		if (carry !== 0) {
			this._words[this._length] = carry;
			this._length++;
		// Copy the rest of the words
		} else if (a !== this) {
			for (; i < a.length; i++) {
				this._words[i] = a._words[i];
			}
		}

		return this;
	};

	// Add `num` to `this`
	add (num: BN) {
		var res;
		if (num._negative !== 0 && this._negative === 0) {
			num._negative = 0;
			res = this.sub(num);
			num._negative ^= 1;
			return res;
		} else if (num._negative === 0 && this._negative !== 0) {
			this._negative = 0;
			res = num.sub(this);
			this._negative = 1;
			return res;
		}

		if (this._length > num.length) return this.clone().iadd(num);

		return num.clone().iadd(this);
	};

	// Subtract `num` from `this` in-place
	isub (num: BN) {
		// this - (-num) = this + num
		if (num._negative !== 0) {
			num._negative = 0;
			var r = this.iadd(num);
			num._negative = 1;
			return r._normSign();

		// -this - num = -(this + num)
		} else if (this._negative !== 0) {
			this._negative = 0;
			this.iadd(num);
			this._negative = 1;
			return this._normSign();
		}

		// At this point both numbers are positive
		var cmp = this.cmp(num);

		// Optimization - zeroify
		if (cmp === 0) {
			this._negative = 0;
			this._length = 1;
			this._words[0] = 0;
			return this;
		}

		// a > b
		var a, b;
		if (cmp > 0) {
			a = this;
			b = num;
		} else {
			a = num;
			b = this;
		}

		var carry = 0;
		var _r: number;
		for (var i = 0; i < b.length; i++) {
			_r = (a._words[i] | 0) - (b._words[i] | 0) + carry;
			carry = _r >> 26;
			this._words[i] = _r & 0x3ffffff;
		}
		for (; carry !== 0 && i < a.length; i++) {
			_r = (a._words[i] | 0) + carry;
			carry = _r >> 26;
			this._words[i] = _r & 0x3ffffff;
		}

		// Copy rest of the words
		if (carry === 0 && i < a.length && a !== this) {
			for (; i < a.length; i++) {
				this._words[i] = a._words[i];
			}
		}

		this._length = Math.max(this._length, i);

		if (a !== this) {
			this._negative = 1;
		}

		return this.strip();
	};

	// Subtract `num` from `this`
	sub (num: BN) {
		return this.clone().isub(num);
	};

	mulTo (num: BN, out: BN) {
		var res: BN;
		var len = this._length + num.length;
		if (this._length === 10 && num.length === 10) {
			res = BN.comb10MulTo(this, num, out);
		} else if (len < 63) {
			res = BN.smallMulTo(this, num, out);
		} else if (len < 1024) {
			res = BN.bigMulTo(this, num, out);
		} else {
			res = jumboMulTo(this, num, out);
		}

		return res;
	};

	// Multiply `this` by `num`
	mul (num: BN) {
		var out = new BN(null);
		out._words = new Array(this._length + num.length);
		return this.mulTo(num, out);
	};

	// Multiply employing FFT
	mulf (num: BN) {
		var out = new BN(null);
		out._words = new Array(this._length + num.length);
		return jumboMulTo(this, num, out);
	};

	// In-place Multiplication
	imul (num: BN) {
		return this.clone().mulTo(num, this);
	};

	imuln (num: number) {
		assert(typeof num === 'number');
		assert(num < 0x4000000);

		// Carry
		var carry = 0;
		for (var i = 0; i < this._length; i++) {
			var w = (this._words[i] | 0) * num;
			var lo = (w & 0x3ffffff) + (carry & 0x3ffffff);
			carry >>= 26;
			carry += (w / 0x4000000) | 0;
			// NOTE: lo is 27bit maximum
			carry += lo >>> 26;
			this._words[i] = lo & 0x3ffffff;
		}

		if (carry !== 0) {
			this._words[i] = carry;
			this._length++;
		}

		return this;
	};

	muln (num: number) {
		return this.clone().imuln(num);
	};

	// `this` * `this`
	sqr () {
		return this.mul(this);
	};

	// `this` * `this` in-place
	isqr () {
		return this.imul(this.clone());
	};

	// Math.pow(`this`, `num`)
	pow (num: BN) {
		var w = toBitArray(num);
		if (w.length === 0) return new BN(1);

		// Skip leading zeroes
		var res: BN = this;
		for (var i = 0; i < w.length; i++, res = res.sqr()) {
			if (w[i] !== 0) break;
		}

		if (++i < w.length) {
			for (var q = res.sqr(); i < w.length; i++, q = q.sqr()) {
				if (w[i] === 0) continue;

				res = res.mul(q);
			}
		}

		return res;
	};

	// Shift-left in-place
	iushln (bits: number) {
		assert(typeof bits === 'number' && bits >= 0);
		var r = bits % 26;
		var s = (bits - r) / 26;
		var carryMask = (0x3ffffff >>> (26 - r)) << (26 - r);
		var i;

		if (r !== 0) {
			var carry = 0;

			for (i = 0; i < this._length; i++) {
				var newCarry = this._words[i] & carryMask;
				var c = ((this._words[i] | 0) - newCarry) << r;
				this._words[i] = c | carry;
				carry = newCarry >>> (26 - r);
			}

			if (carry) {
				this._words[i] = carry;
				this._length++;
			}
		}

		if (s !== 0) {
			for (i = this._length - 1; i >= 0; i--) {
				this._words[i + s] = this._words[i];
			}

			for (i = 0; i < s; i++) {
				this._words[i] = 0;
			}

			this._length += s;
		}

		return this.strip();
	};

	ishln (bits: number) {
		// TODO(indutny): implement me
		assert(this._negative === 0);
		return this.iushln(bits);
	};

	// Shift-right in-place
	// NOTE: `hint` is a lowest bit before trailing zeroes
	// NOTE: if `extended` is present - it will be filled with destroyed bits
	iushrn (bits: number, hint?: number, extended?: BN) {
		assert(typeof bits === 'number' && bits >= 0);
		var h;
		if (hint) {
			h = (hint - (hint % 26)) / 26;
		} else {
			h = 0;
		}

		var r = bits % 26;
		var s = Math.min((bits - r) / 26, this._length);
		var mask = 0x3ffffff ^ ((0x3ffffff >>> r) << r);
		var maskedWords = extended;

		h -= s;
		h = Math.max(0, h);

		// Extended mode, copy masked part
		if (maskedWords) {
			for (var i = 0; i < s; i++) {
				maskedWords._words[i] = this._words[i];
			}
			maskedWords._length = s;
		}

		if (s === 0) {
			// No-op, we should not move anything at all
		} else if (this._length > s) {
			this._length -= s;
			for (i = 0; i < this._length; i++) {
				this._words[i] = this._words[i + s];
			}
		} else {
			this._words[0] = 0;
			this._length = 1;
		}

		var carry = 0;
		for (i = this._length - 1; i >= 0 && (carry !== 0 || i >= h); i--) {
			var word = this._words[i] | 0;
			this._words[i] = (carry << (26 - r)) | (word >>> r);
			carry = word & mask;
		}

		// Push carried bits as a mask
		if (maskedWords && carry !== 0) {
			maskedWords._words[maskedWords._length++] = carry;
		}

		if (this._length === 0) {
			this._words[0] = 0;
			this._length = 1;
		}

		return this.strip();
	};

	ishrn (bits: number, hint?: number, extended?: BN) {
		// TODO(indutny): implement me
		assert(this._negative === 0);
		return this.iushrn(bits, hint, extended);
	};

	// Shift-left
	shln (bits: number) {
		return this.clone().ishln(bits);
	};

	ushln (bits: number) {
		return this.clone().iushln(bits);
	};

	// Shift-right
	shrn (bits: number) {
		return this.clone().ishrn(bits);
	};

	ushrn (bits: number) {
		return this.clone().iushrn(bits);
	};

	// Test if n bit is set
	testn (bit: number) {
		assert(typeof bit === 'number' && bit >= 0);
		var r = bit % 26;
		var s = (bit - r) / 26;
		var q = 1 << r;

		// Fast case: bit is much higher than all existing words
		if (this._length <= s) return false;

		// Check bit and return
		var w = this._words[s];

		return !!(w & q);
	};

	// Return only lowers bits of number (in-place)
	imaskn (bits: number) {
		assert(typeof bits === 'number' && bits >= 0);
		var r = bits % 26;
		var s = (bits - r) / 26;

		assert(this._negative === 0, 'imaskn works only with positive numbers');

		if (this._length <= s) {
			return this;
		}

		if (r !== 0) {
			s++;
		}
		this._length = Math.min(s, this._length);

		if (r !== 0) {
			var mask = 0x3ffffff ^ ((0x3ffffff >>> r) << r);
			this._words[this._length - 1] &= mask;
		}

		return this.strip();
	};

	// Return only lowers bits of number
	maskn (bits: number) {
		return this.clone().imaskn(bits);
	};

	// Add plain number `num` to `this`
	iaddn (num: number) {
		assert(typeof num === 'number');
		assert(num < 0x4000000);
		if (num < 0) return this.isubn(-num);

		// Possible sign change
		if (this._negative !== 0) {
			if (this._length === 1 && (this._words[0] | 0) < num) {
				this._words[0] = num - (this._words[0] | 0);
				this._negative = 0;
				return this;
			}

			this._negative = 0;
			this.isubn(num);
			this._negative = 1;
			return this;
		}

		// Add without checks
		return this._iaddn(num);
	};

	private _iaddn (num: number) {
		this._words[0] += num;

		// Carry
		for (var i = 0; i < this._length && this._words[i] >= 0x4000000; i++) {
			this._words[i] -= 0x4000000;
			if (i === this._length - 1) {
				this._words[i + 1] = 1;
			} else {
				this._words[i + 1]++;
			}
		}
		this._length = Math.max(this._length, i + 1);

		return this;
	};

	// Subtract plain number `num` from `this`
	isubn (num: number): BN {
		assert(typeof num === 'number');
		assert(num < 0x4000000);
		if (num < 0) return this.iaddn(-num);

		if (this._negative !== 0) {
			this._negative = 0;
			this.iaddn(num);
			this._negative = 1;
			return this;
		}

		this._words[0] -= num;

		if (this._length === 1 && this._words[0] < 0) {
			this._words[0] = -this._words[0];
			this._negative = 1;
		} else {
			// Carry
			for (var i = 0; i < this._length && this._words[i] < 0; i++) {
				this._words[i] += 0x4000000;
				this._words[i + 1] -= 1;
			}
		}

		return this.strip();
	};

	addn (num: number) {
		return this.clone().iaddn(num);
	};

	subn (num: number) {
		return this.clone().isubn(num);
	};

	iabs () {
		this._negative = 0;

		return this;
	};

	abs () {
		return this.clone().iabs();
	};

	private _ishlnsubmul (num: BN, mul: number, shift: number) {
		var len = num.length + shift;
		var i;

		this._expand(len);

		var w;
		var carry = 0;
		for (i = 0; i < num.length; i++) {
			w = (this._words[i + shift] | 0) + carry;
			var right = (num._words[i] | 0) * mul;
			w -= right & 0x3ffffff;
			carry = (w >> 26) - ((right / 0x4000000) | 0);
			this._words[i + shift] = w & 0x3ffffff;
		}
		for (; i < this._length - shift; i++) {
			w = (this._words[i + shift] | 0) + carry;
			carry = w >> 26;
			this._words[i + shift] = w & 0x3ffffff;
		}

		if (carry === 0) return this.strip();

		// Subtraction overflow
		assert(carry === -1);
		carry = 0;
		for (i = 0; i < this._length; i++) {
			w = -(this._words[i] | 0) + carry;
			carry = w >> 26;
			this._words[i] = w & 0x3ffffff;
		}
		this._negative = 1;

		return this.strip();
	};

	private _wordDiv (num: BN, mode?: 'mod' | 'div') {
		var shift = this._length - num.length;

		var a = this.clone();
		var b = num;

		// Normalize
		var bhi = b._words[b.length - 1] | 0;
		var bhiBits = _countBits(bhi);
		shift = 26 - bhiBits;
		if (shift !== 0) {
			b = b.ushln(shift);
			a.iushln(shift);
			bhi = b._words[b.length - 1] | 0;
		}

		// Initialize quotient
		var m = a.length - b.length;
		var q;

		if (mode !== 'mod') {
			q = new BN(null);
			q._length = m + 1;
			q._words = new Array(q.length);
			for (var i = 0; i < q.length; i++) {
				q._words[i] = 0;
			}
		}

		var diff = a.clone()._ishlnsubmul(b, 1, m);
		if (diff._negative === 0) {
			a = diff;
			if (q) {
				q._words[m] = 1;
			}
		}

		for (var j = m - 1; j >= 0; j--) {
			var qj = (a._words[b.length + j] | 0) * 0x4000000 +
				(a._words[b.length + j - 1] | 0);

			// NOTE: (qj / bhi) is (0x3ffffff * 0x4000000 + 0x3ffffff) / 0x2000000 max
			// (0x7ffffff)
			qj = Math.min((qj / bhi) | 0, 0x3ffffff);

			a._ishlnsubmul(b, qj, j);
			while (a._negative !== 0) {
				qj--;
				a._negative = 0;
				a._ishlnsubmul(b, 1, j);
				if (!a.isZero()) {
					a._negative ^= 1;
				}
			}
			if (q) {
				q._words[j] = qj;
			}
		}
		if (q) {
			q.strip();
		}
		a.strip();

		// Denormalize
		if (mode !== 'div' && shift !== 0) {
			a.iushrn(shift);
		}

		return {
			div: q || Zero,
			mod: a
		};
	};

	// NOTE: 1) `mode` can be set to `mod` to request mod only,
	//       to `div` to request div only, or be absent to
	//       request both div & mod
	//       2) `positive` is true if unsigned mod is requested
	divmod (num: BN, mode?: 'div'| 'mod', positive?: boolean): { div: BN; mod: BN } {
		assert(!num.isZero());

		if (this.isZero()) {
			return {
				div: new BN(0),
				mod: new BN(0)
			};
		}

		var div = Zero, mod = Zero, res;
		if (this._negative !== 0 && num._negative === 0) {
			res = this.neg().divmod(num, mode);

			if (mode !== 'mod') {
				div = res.div.neg();
			}

			if (mode !== 'div') {
				mod = res.mod.neg();
				if (positive && mod._negative !== 0) {
					mod.iadd(num);
				}
			}

			return {
				div: div,
				mod: mod
			};
		}

		if (this._negative === 0 && num._negative !== 0) {
			res = this.divmod(num.neg(), mode);

			if (mode !== 'mod') {
				div = res.div.neg();
			}

			return {
				div: div,
				mod: res.mod
			};
		}

		if ((this._negative & num._negative) !== 0) {
			res = this.neg().divmod(num.neg(), mode);

			if (mode !== 'div') {
				mod = res.mod.neg();
				if (positive && mod._negative !== 0) {
					mod.isub(num);
				}
			}

			return {
				div: res.div,
				mod: mod
			};
		}

		// Both numbers are positive at this point

		// Strip both numbers to approximate shift value
		if (num.length > this._length || this.cmp(num) < 0) {
			return {
				div: new BN(0),
				mod: this
			};
		}

		// Very short reduction
		if (num.length === 1) {
			if (mode === 'div') {
				return {
					div: this.divn(num._words[0]),
					mod: Zero
				};
			}

			if (mode === 'mod') {
				return {
					div: Zero,
					mod: new BN(this.modn(num._words[0]))
				};
			}

			return {
				div: this.divn(num._words[0]),
				mod: new BN(this.modn(num._words[0]))
			};
		}

		return this._wordDiv(num, mode);
	};

	// Find `this` / `num`
	div (num: BN) {
		return this.divmod(num, 'div', false).div;
	};

	// Find `this` % `num`
	mod (num: BN) {
		return this.divmod(num, 'mod', false).mod;
	};

	umod (num: BN) {
		return this.divmod(num, 'mod', true).mod;
	};

	// Find Round(`this` / `num`)
	divRound (num: BN) {
		var dm = this.divmod(num);

		// Fast case - exact division
		if (dm.mod.isZero()) return dm.div;

		var mod = dm.div._negative !== 0 ? dm.mod.isub(num) : dm.mod;

		var half = num.ushrn(1);
		var r2 = num.andln(1);
		var cmp = mod.cmp(half);

		// Round down
		if (cmp < 0 || r2 === 1 && cmp === 0) return dm.div;

		// Round up
		return dm.div._negative !== 0 ? dm.div.isubn(1) : dm.div.iaddn(1);
	};

	modn (num: number) {
		assert(num <= 0x3ffffff);
		var p = (1 << 26) % num;

		var acc = 0;
		for (var i = this._length - 1; i >= 0; i--) {
			acc = (p * acc + (this._words[i] | 0)) % num;
		}

		return acc;
	};

	// In-place division by number
	idivn (num: number) {
		assert(num <= 0x3ffffff);

		var carry = 0;
		for (var i = this._length - 1; i >= 0; i--) {
			var w = (this._words[i] | 0) + carry * 0x4000000;
			this._words[i] = (w / num) | 0;
			carry = w % num;
		}

		return this.strip();
	};

	divn (num: number) {
		return this.clone().idivn(num);
	};

	egcd (p: BN) {
		assert(p._negative === 0);
		assert(!p.isZero());

		var x: BN = this;
		var y = p.clone();

		if (x._negative !== 0) {
			x = x.umod(p);
		} else {
			x = x.clone();
		}

		// A * x + B * y = x
		var A = new BN(1);
		var B = new BN(0);

		// C * x + D * y = y
		var C = new BN(0);
		var D = new BN(1);

		var g = 0;

		while (x.isEven() && y.isEven()) {
			x.iushrn(1);
			y.iushrn(1);
			++g;
		}

		var yp = y.clone();
		var xp = x.clone();

		while (!x.isZero()) {
			for (var i = 0, im = 1; (x._words[0] & im) === 0 && i < 26; ++i, im <<= 1);
			if (i > 0) {
				x.iushrn(i);
				while (i-- > 0) {
					if (A.isOdd() || B.isOdd()) {
						A.iadd(yp);
						B.isub(xp);
					}

					A.iushrn(1);
					B.iushrn(1);
				}
			}

			for (var j = 0, jm = 1; (y._words[0] & jm) === 0 && j < 26; ++j, jm <<= 1);
			if (j > 0) {
				y.iushrn(j);
				while (j-- > 0) {
					if (C.isOdd() || D.isOdd()) {
						C.iadd(yp);
						D.isub(xp);
					}

					C.iushrn(1);
					D.iushrn(1);
				}
			}

			if (x.cmp(y) >= 0) {
				x.isub(y);
				A.isub(C);
				B.isub(D);
			} else {
				y.isub(x);
				C.isub(A);
				D.isub(B);
			}
		}

		return {
			a: C,
			b: D,
			gcd: y.iushln(g)
		};
	};

	// This is reduced incarnation of the binary EEA
	// above, designated to invert members of the
	// _prime_ fields F(p) at a maximal speed
	/*private */_invmp (p: BN) {
		assert(p._negative === 0);
		assert(!p.isZero());

		var a: BN = this;
		var b = p.clone();

		if (a._negative !== 0) {
			a = a.umod(p);
		} else {
			a = a.clone();
		}

		var x1 = new BN(1);
		var x2 = new BN(0);

		var delta = b.clone();

		while (a.cmpn(1) > 0 && b.cmpn(1) > 0) {
			for (var i = 0, im = 1; (a._words[0] & im) === 0 && i < 26; ++i, im <<= 1);
			if (i > 0) {
				a.iushrn(i);
				while (i-- > 0) {
					if (x1.isOdd()) {
						x1.iadd(delta);
					}

					x1.iushrn(1);
				}
			}

			for (var j = 0, jm = 1; (b._words[0] & jm) === 0 && j < 26; ++j, jm <<= 1);
			if (j > 0) {
				b.iushrn(j);
				while (j-- > 0) {
					if (x2.isOdd()) {
						x2.iadd(delta);
					}

					x2.iushrn(1);
				}
			}

			if (a.cmp(b) >= 0) {
				a.isub(b);
				x1.isub(x2);
			} else {
				b.isub(a);
				x2.isub(x1);
			}
		}

		var res;
		if (a.cmpn(1) === 0) {
			res = x1;
		} else {
			res = x2;
		}

		if (res.cmpn(0) < 0) {
			res.iadd(p);
		}

		return res;
	};

	gcd (num: BN) {
		if (this.isZero()) return num.abs();
		if (num.isZero()) return this.abs();

		var a = this.clone();
		var b = num.clone();
		a._negative = 0;
		b._negative = 0;

		// Remove common factor of two
		for (var shift = 0; a.isEven() && b.isEven(); shift++) {
			a.iushrn(1);
			b.iushrn(1);
		}

		do {
			while (a.isEven()) {
				a.iushrn(1);
			}
			while (b.isEven()) {
				b.iushrn(1);
			}

			var r = a.cmp(b);
			if (r < 0) {
				// Swap `a` and `b` to make `a` always bigger than `b`
				var t = a;
				a = b;
				b = t;
			} else if (r === 0 || b.cmpn(1) === 0) {
				break;
			}

			a.isub(b);
		} while (true);

		return b.iushln(shift);
	};

	// Invert number in the field F(num)
	invm (num: BN) {
		return this.egcd(num).a.umod(num);
	};

	isEven () {
		return (this._words[0] & 1) === 0;
	};

	isOdd () {
		return (this._words[0] & 1) === 1;
	};

	// And first word and num
	andln (num: number) {
		return this._words[0] & num;
	};

	// Increment at the bit position in-line
	bincn (bit: number) {
		assert(typeof bit === 'number');
		var r = bit % 26;
		var s = (bit - r) / 26;
		var q = 1 << r;

		// Fast case: bit is much higher than all existing words
		if (this._length <= s) {
			this._expand(s + 1);
			this._words[s] |= q;
			return this;
		}

		// Add bit and propagate, if needed
		var carry = q;
		for (var i = s; carry !== 0 && i < this._length; i++) {
			var w = this._words[i] | 0;
			w += carry;
			carry = w >>> 26;
			w &= 0x3ffffff;
			this._words[i] = w;
		}
		if (carry !== 0) {
			this._words[i] = carry;
			this._length++;
		}
		return this;
	};

	isZero () {
		return this._length === 1 && this._words[0] === 0;
	};

	cmpn (num: number) {
		var negative = num < 0;

		if (this._negative !== 0 && !negative) return -1;
		if (this._negative === 0 && negative) return 1;

		this.strip();

		var res;
		if (this._length > 1) {
			res = 1;
		} else {
			if (negative) {
				num = -num;
			}

			assert(num <= 0x3ffffff, 'Number is too big');

			var w = this._words[0] | 0;
			res = w === num ? 0 : w < num ? -1 : 1;
		}
		if (this._negative !== 0) return -res | 0;
		return res;
	};

	// Compare two numbers and return:
	// 1 - if `this` > `num`
	// 0 - if `this` == `num`
	// -1 - if `this` < `num`
	cmp (num: BN) {
		if (this._negative !== 0 && num._negative === 0) return -1;
		if (this._negative === 0 && num._negative !== 0) return 1;

		var res = this.ucmp(num);
		if (this._negative !== 0) return -res | 0;
		return res;
	};

	// Unsigned comparison
	ucmp (num: BN) {
		// At this point both numbers have the same sign
		if (this._length > num.length) return 1;
		if (this._length < num.length) return -1;

		var res = 0;
		for (var i = this._length - 1; i >= 0; i--) {
			var a = this._words[i] | 0;
			var b = num._words[i] | 0;

			if (a === b) continue;
			if (a < b) {
				res = -1;
			} else if (a > b) {
				res = 1;
			}
			break;
		}
		return res;
	};

	gtn (num: number) {
		return this.cmpn(num) === 1;
	};

	gt (num: BN) {
		return this.cmp(num) === 1;
	};

	gten (num: number) {
		return this.cmpn(num) >= 0;
	};

	gte (num: BN) {
		return this.cmp(num) >= 0;
	};

	ltn (num: number) {
		return this.cmpn(num) === -1;
	};

	lt (num: BN) {
		return this.cmp(num) === -1;
	};

	lten (num: number) {
		return this.cmpn(num) <= 0;
	};

	lte (num: BN) {
		return this.cmp(num) <= 0;
	};

	eqn (num: number) {
		return this.cmpn(num) === 0;
	};

	eq (num: BN) {
		return this.cmp(num) === 0;
	};

	//
	// A reduce context, could be using montgomery or something better, depending
	// on the `m` itself.
	//
	static red (num: BN | MPrimeType) {
		return new Red(num);
	};

	toRed (ctx: Red) {
		assert(!this.red, 'Already a number in reduction context');
		assert(this._negative === 0, 'red works only with positives');
		return ctx.convertTo(this)._forceRed(ctx);
	};

	fromRed () {
		assert(this.red, 'fromRed works only with numbers in reduction context');
		return (this.red as Red).convertFrom(this);
	};

	/*private */_forceRed (ctx: Red): BN {
		this._red = ctx;
		return this;
	};

	forceRed (ctx: Red) {
		assert(!this.red, 'Already a number in reduction context');
		return this._forceRed(ctx);
	};

	redAdd (num: BN) {
		assert(this.red, 'redAdd works only with red numbers');
		return (this.red as Red).add(this, num);
	};

	redIAdd (num: BN) {
		assert(this.red, 'redIAdd works only with red numbers');
		return (this.red as Red).iadd(this, num);
	};

	redSub (num: BN) {
		assert(this.red, 'redSub works only with red numbers');
		return (this.red as Red).sub(this, num);
	};

	redISub (num: BN) {
		assert(this.red, 'redISub works only with red numbers');
		return (this.red as Red).isub(this, num);
	};

	redShl (num: number) {
		assert(this.red, 'redShl works only with red numbers');
		return (this.red as Red).shl(this, num);
	};

	redMul (num: BN) {
		assert(this.red, 'redMul works only with red numbers');
		(this.red as Red)._verify2(this, num);
		return (this.red as Red).mul(this, num);
	};

	redIMul (num: BN) {
		assert(this.red, 'redMul works only with red numbers');
		(this.red as Red)._verify2(this, num);
		return (this.red as Red).imul(this, num);
	};

	redSqr () {
		assert(this.red, 'redSqr works only with red numbers');
		(this.red as Red)._verify1(this);
		return (this.red as Red).sqr(this);
	};

	redISqr () {
		assert(this.red, 'redISqr works only with red numbers');
		(this.red as Red)._verify1(this);
		return (this.red as Red).isqr(this);
	};

	// Square root over p
	redSqrt () {
		assert(this.red, 'redSqrt works only with red numbers');
		(this.red as Red)._verify1(this);
		return (this.red as Red).sqrt(this);
	};

	redInvm () {
		assert(this.red, 'redInvm works only with red numbers');
		(this.red as Red)._verify1(this);
		return (this.red as Red).invm(this);
	};

	// Return negative clone of `this` % `red modulo`
	redNeg () {
		assert(this.red, 'redNeg works only with red numbers');
		(this.red as Red)._verify1(this);
		return (this.red as Red).neg(this);
	};

	redPow (num: BN) {
		assert(this.red && !num.red, 'redPow(normalNum)');
		(this.red as Red)._verify1(this);
		return (this.red as Red).pow(this, num);
	};

	// Exported mostly for testing purposes, use plain name instead
	static _prime (name: MPrimeType) {
		// Cached version of prime
		if (primes[name])
			return primes[name] as MPrime;

		var prime: MPrime;
		if (name === 'k256') {
			prime = new K256();
		} else if (name === 'p224') {
			prime = new P224();
		} else if (name === 'p192') {
			prime = new P192();
		} else if (name === 'p25519') {
			prime = new P25519();
		} else {
			throw new Error('Unknown prime ' + name);
		}
		primes[name] = prime;

		return prime;
	};

	static mont (num: BN | MPrimeType) {
		return new Mont(num);
	};

}

export const Zero = new BN(0);

export type MPrimeType = 'k256' | 'p224' | 'p192' | 'p25519';

// Prime numbers with efficient reduction
const primes = {
	k256: null as (MPrime | null),
	p224: null as (MPrime | null),
	p192: null as (MPrime | null),
	p25519: null as (MPrime | null),
};

// Pseudo-Mersenne prime
export class MPrime {
	name: string;
	p: BN;
	n: number;
	k: BN;
	tmp: BN;
	constructor(name: string, p: string) {
		// P = 2 ^ N - K
		this.name = name;
		this.p = new BN(p, 16);
		this.n = this.p.bitLength();
		this.k = new BN(1).iushln(this.n).isub(this.p);

		this.tmp = this._tmp();
	}

	private _tmp () {
		var n = Math.ceil(this.n / 13);
		var tmp = new BN(null);
		(tmp as any)._words = new Array(n); // TODO private visit
		return tmp;
	};

	ireduce (num: BN) {
		// Assumes that `num` is less than `P^2`
		// num = HI * (2 ^ N - K) + HI * K + LO = HI * K + LO (mod P)
		var r = num;
		var rlen;

		do {
			this.split(r, this.tmp);
			r = this.imulK(r);
			r = r.iadd(this.tmp);
			rlen = r.bitLength();
		} while (rlen > this.n);

		var cmp = rlen < this.n ? -1 : r.ucmp(this.p);
		if (cmp === 0) {
			r.words[0] = 0;
			(r as any).length = 1; // TODO private visit
		} else if (cmp > 0) {
			r.isub(this.p);
		} else {
			r.strip();
		}

		return r;
	};

	split (input: BN, out: BN) {
		input.iushrn(this.n, 0, out);
	};

	imulK (num: BN) {
		return num.imul(this.k);
	};

}

class K256 extends MPrime {
	constructor() {
		super(
			'k256',
			'ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff fffffffe fffffc2f');
	}

	split (input: BN, output: BN) {
		// 256 = 9 * 26 + 22
		var mask = 0x3fffff;

		var outLen = Math.min(input.length, 9);
		for (var i = 0; i < outLen; i++) {
			output.words[i] = input.words[i];
		}
		(output as any)._length = outLen; // TODO ptivate visit

		if (input.length <= 9) {
			input.words[0] = 0;
			(input as any)._length = 1; // TODO ptivate visit
			return;
		}

		// Shift by 9 limbs
		var prev = input.words[9];
		output.words[(output as any)._length++] = prev & mask; // TODO ptivate visit

		for (i = 10; i < input.length; i++) {
			var next = input.words[i] | 0;
			input.words[i - 10] = ((next & mask) << 4) | (prev >>> 22);
			prev = next;
		}
		prev >>>= 22;
		input.words[i - 10] = prev;
		if (prev === 0 && input.length > 10) {
			(input as any)._length -= 10; // TODO ptivate visit
		} else {
			(input as any).length -= 9; // TODO ptivate visit
		}
	};

	imulK (num: BN) {
		// K = 0x1000003d1 = [ 0x40, 0x3d1 ]
		num.words[num.length] = 0;
		num.words[num.length + 1] = 0;
		(num as any)._length += 2; // TODO ptivate visit

		// bounded at: 0x40 * 0x3ffffff + 0x3d0 = 0x100000390
		var lo = 0;
		for (var i = 0; i < num.length; i++) {
			var w = num.words[i] | 0;
			lo += w * 0x3d1;
			num.words[i] = lo & 0x3ffffff;
			lo = w * 0x40 + ((lo / 0x4000000) | 0);
		}

		// Fast length reduction
		if (num.words[num.length - 1] === 0) {
			(num as any)._length--; // TODO ptivate visit
			if (num.words[num.length - 1] === 0) {
				(num as any)._length--; // TODO ptivate visit
			}
		}
		return num;
	};

}

class P224 extends MPrime {
	constructor() {
		super(
			'p224',
			'ffffffff ffffffff ffffffff ffffffff 00000000 00000000 00000001');
	}
}

class P192 extends MPrime {
	constructor() {
		super(
			'p192',
			'ffffffff ffffffff ffffffff fffffffe ffffffff ffffffff');
	}
}

class P25519 extends MPrime {
	constructor() {
		// 2 ^ 255 - 19
		super(
			'25519',
			'7fffffffffffffff ffffffffffffffff ffffffffffffffff ffffffffffffffed');
	}

	imulK (num: BN) {
		// K = 0x13
		var carry = 0;
		for (var i = 0; i < num.length; i++) {
			var hi = (num.words[i] | 0) * 0x13 + carry;
			var lo = hi & 0x3ffffff;
			hi >>>= 26;

			num.words[i] = lo;
			carry = hi;
		}
		if (carry !== 0) {
			num.words[(num as any)._length++] = carry; // TODO ptivate visit
		}
		return num;
	};

}

//
// Base reduction engine
//
export class Red {

	m: BN;
	prime: MPrime | null;

	constructor(m: MPrimeType | BN) {
		if (typeof m === 'string') {
			var prime = BN._prime(m);
			this.m = prime.p;
			this.prime = prime;
		} else {
			assert(m.gtn(1), 'modulus must be greater than 1');
			this.m = m;
			this.prime = null;
		}
	}

	/*private */_verify1 (a: BN) {
		assert(a.negative === 0, 'red works only with positives');
		assert(a.red, 'red works only with red numbers');
	};

	/*private */_verify2 (a: BN, b: BN) {
		assert((a.negative | b.negative) === 0, 'red works only with positives');
		assert(a.red && a.red === b.red,
			'red works only with red numbers');
	};

	imod (a: BN) {
		if (this.prime) return this.prime.ireduce(a)._forceRed(this);
		return a.umod(this.m)._forceRed(this);
	};

	neg (a: BN) {
		if (a.isZero()) {
			return a.clone();
		}

		return this.m.sub(a)._forceRed(this);
	};

	add (a: BN, b: BN) {
		this._verify2(a, b);

		var res = a.add(b);
		if (res.cmp(this.m) >= 0) {
			res.isub(this.m);
		}
		return res._forceRed(this);
	};

	iadd (a: BN, b: BN) {
		this._verify2(a, b);

		var res = a.iadd(b);
		if (res.cmp(this.m) >= 0) {
			res.isub(this.m);
		}
		return res;
	};

	sub (a: BN, b: BN) {
		this._verify2(a, b);

		var res = a.sub(b);
		if (res.cmpn(0) < 0) {
			res.iadd(this.m);
		}
		return res._forceRed(this);
	};

	isub (a: BN, b: BN) {
		this._verify2(a, b);

		var res = a.isub(b);
		if (res.cmpn(0) < 0) {
			res.iadd(this.m);
		}
		return res;
	};

	shl (a: BN, num: number) {
		this._verify1(a);
		return this.imod(a.ushln(num));
	};

	imul (a: BN, b: BN) {
		this._verify2(a, b);
		return this.imod(a.imul(b));
	};

	mul (a: BN, b: BN) {
		this._verify2(a, b);
		return this.imod(a.mul(b));
	};

	isqr (a: BN) {
		return this.imul(a, a.clone());
	};

	sqr (a: BN) {
		return this.mul(a, a);
	};

	sqrt (a: BN) {
		if (a.isZero()) return a.clone();

		var mod3 = this.m.andln(3);
		assert(mod3 % 2 === 1);

		// Fast case
		if (mod3 === 3) {
			var pow = this.m.add(new BN(1)).iushrn(2);
			return this.pow(a, pow);
		}

		// Tonelli-Shanks algorithm (Totally unoptimized and slow)
		//
		// Find Q and S, that Q * 2 ^ S = (P - 1)
		var q = this.m.subn(1);
		var s = 0;
		while (!q.isZero() && q.andln(1) === 0) {
			s++;
			q.iushrn(1);
		}
		assert(!q.isZero());

		var one = new BN(1).toRed(this);
		var nOne = one.redNeg();

		// Find quadratic non-residue
		// NOTE: Max is such because of generalized Riemann hypothesis.
		var lpow = this.m.subn(1).iushrn(1);
		var zNum = this.m.bitLength();
		var z = new BN(2 * zNum * zNum).toRed(this);

		while (this.pow(z, lpow).cmp(nOne) !== 0) {
			z.redIAdd(nOne);
		}

		var c = this.pow(z, q);
		var r = this.pow(a, q.addn(1).iushrn(1));
		var t = this.pow(a, q);
		var m = s;
		while (t.cmp(one) !== 0) {
			var tmp = t;
			for (var i = 0; tmp.cmp(one) !== 0; i++) {
				tmp = tmp.redSqr();
			}
			assert(i < m);
			var b = this.pow(c, new BN(1).iushln(m - i - 1));

			r = r.redMul(b);
			c = b.redSqr();
			t = t.redMul(c);
			m = i;
		}

		return r;
	};

	invm (a: BN) {
		var inv = a._invmp(this.m);
		if (inv.negative !== 0) {
			(inv as any)._negative = 0; // TODO private visit
			return this.imod(inv).redNeg();
		} else {
			return this.imod(inv);
		}
	};

	pow (a: BN, num: BN) {
		if (num.isZero()) return new BN(1).toRed(this);
		if (num.cmpn(1) === 0) return a.clone();

		var windowSize = 4;
		var wnd = new Array(1 << windowSize);
		wnd[0] = new BN(1).toRed(this);
		wnd[1] = a;
		for (var i = 2; i < wnd.length; i++) {
			wnd[i] = this.mul(wnd[i - 1], a);
		}

		var res = wnd[0];
		var current = 0;
		var currentLen = 0;
		var start = num.bitLength() % 26;
		if (start === 0) {
			start = 26;
		}

		for (i = num.length - 1; i >= 0; i--) {
			var word = num.words[i];
			for (var j = start - 1; j >= 0; j--) {
				var bit = (word >> j) & 1;
				if (res !== wnd[0]) {
					res = this.sqr(res);
				}

				if (bit === 0 && current === 0) {
					currentLen = 0;
					continue;
				}

				current <<= 1;
				current |= bit;
				currentLen++;
				if (currentLen !== windowSize && (i !== 0 || j !== 0)) continue;

				res = this.mul(res, wnd[current]);
				currentLen = 0;
				current = 0;
			}
			start = 26;
		}

		return res;
	};

	convertTo (num: BN) {
		var r = num.umod(this.m);

		return r === num ? r.clone() : r;
	};

	convertFrom (num: BN) {
		var res = num.clone();
		(res as any)._red = null; // TODO private visit
		return res;
	};

}

//
// Montgomery method engine
//

export class Mont extends Red {
	shift: number;
	r: BN;
	r2: BN;
	rinv: BN;
	minv: BN;
	constructor(m: MPrimeType | BN) {
		super(m);

		this.shift = this.m.bitLength();
		if (this.shift % 26 !== 0) {
			this.shift += 26 - (this.shift % 26);
		}

		this.r = new BN(1).iushln(this.shift);
		this.r2 = this.imod(this.r.sqr());
		this.rinv = this.r._invmp(this.m);

		this.minv = this.rinv.mul(this.r).isubn(1).div(this.m);
		this.minv = this.minv.umod(this.r);
		this.minv = this.r.sub(this.minv);
	}

	convertTo (num: BN) {
		return this.imod(num.ushln(this.shift));
	};

	convertFrom (num: BN) {
		var r = this.imod(num.mul(this.rinv));
		(r as any)._red = null; // TODO private visit
		return r;
	};

	imul (a: BN, b: BN): BN {
		if (a.isZero() || b.isZero()) {
			a.words[0] = 0;
			(a as any)._length = 1; // private visit
			return a;
		}

		var t = a.imul(b);
		var c = t.maskn(this.shift).mul(this.minv).imaskn(this.shift).mul(this.m);
		var u = t.isub(c).iushrn(this.shift);
		var res = u;

		if (u.cmp(this.m) >= 0) {
			res = u.isub(this.m);
		} else if (u.cmpn(0) < 0) {
			res = u.iadd(this.m);
		}

		return res._forceRed(this);
	};

	mul (a: BN, b: BN): BN {
		if (a.isZero() || b.isZero()) return new BN(0)._forceRed(this);

		var t = a.mul(b);
		var c = t.maskn(this.shift).mul(this.minv).imaskn(this.shift).mul(this.m);
		var u = t.isub(c).iushrn(this.shift);
		var res = u;
		if (u.cmp(this.m) >= 0) {
			res = u.isub(this.m);
		} else if (u.cmpn(0) < 0) {
			res = u.iadd(this.m);
		}

		return res._forceRed(this);
	};

	invm (a: BN): BN {
		// (AR)^-1 * R^2 = (A^-1 * R^-1) * R^2 = A^-1 * R
		var res = this.imod(a._invmp(this.m).mul(this.r2));
		return res._forceRed(this);
	};

}