
import buffer, {IBuffer,IBufferEncoding} from 'somes/buffer';
import BN from '../bn';

export function assert(val: any, msg?: string) {
	if (!val)
		throw new Error(msg || 'Assertion failed');
};

export function toArray(msg: number[] | string | object, enc?: 'hex') {
	if (Array.isArray(msg))
		return msg.slice() as number[];
	if (!msg)
		return [] as number[];

	var res: number[] = [];
	var _msg = msg as any;
	if (typeof msg !== 'string') {
		for (var i = 0; i < _msg.length; i++)
			res[i] = _msg[i] | 0;
		return res;
	}

	if (!enc) {
		for (var i = 0; i < msg.length; i++) {
			var c = msg.charCodeAt(i);
			var hi = c >> 8;
			var lo = c & 0xff;
			if (hi)
				res.push(hi, lo);
			else
				res.push(lo);
		}
	}
	else if (enc === 'hex') {
		msg = msg.replace(/[^a-z0-9]+/ig, '');
		if (msg.length % 2 !== 0)
			msg = '0' + msg;
		for (var i = 0; i < msg.length; i += 2)
			res.push(parseInt(msg[i] + msg[i + 1], 16));
	}

	return res;
}

// export function zero2(word: string) {
// 	if (word.length === 1)
// 		return '0' + word;
// 	else
// 		return word;
// }

// export function toHex(msg: ArrayLike<number>) {
// 	var res = '';
// 	for (var i = 0; i < msg.length; i++)
// 		res += zero2(msg[i].toString(16));
// 	return res;
// }

export type Encoding = IBufferEncoding;

export function encode(arr: ArrayLike<number>, enc?: Encoding): string {
	return buffer.from(arr).toString(enc);
}

// Represent num in a w-NAF form
export function getNAF(num: BN, w: number) {
	var naf: number[] = [];
	var ws = 1 << (w + 1);
	var k = num.clone();
	while (k.cmpn(1) >= 0) {
		var z;
		if (k.isOdd()) {
			var mod = k.andln(ws - 1);
			if (mod > (ws >> 1) - 1)
				z = (ws >> 1) - mod;
			else
				z = mod;
			k.isubn(z);
		} else {
			z = 0;
		}
		naf.push(z);

		// Optimization, shift by word if possible
		var shift = (k.cmpn(0) !== 0 && k.andln(ws - 1) === 0) ? (w + 1) : 1;
		for (var i = 1; i < shift; i++)
			naf.push(0);
			k.iushrn(shift);
	}

	return naf;
}

// Represent k1, k2 in a Joint Sparse Form
export function getJSF(k1: BN, k2: BN) {
	var jsf = [
		[] as number[],
		[] as number[]
	];

	k1 = k1.clone();
	k2 = k2.clone();
	var d1 = 0;
	var d2 = 0;
	while (k1.cmpn(-d1) > 0 || k2.cmpn(-d2) > 0) {

		// First phase
		var m14 = (k1.andln(3) + d1) & 3;
		var m24 = (k2.andln(3) + d2) & 3;
		if (m14 === 3)
			m14 = -1;
		if (m24 === 3)
			m24 = -1;
		var u1;
		if ((m14 & 1) === 0) {
			u1 = 0;
		} else {
			var m8 = (k1.andln(7) + d1) & 7;
			if ((m8 === 3 || m8 === 5) && m24 === 2)
				u1 = -m14;
			else
				u1 = m14;
		}
		jsf[0].push(u1);

		var u2;
		if ((m24 & 1) === 0) {
			u2 = 0;
		} else {
			var m8 = (k2.andln(7) + d2) & 7;
			if ((m8 === 3 || m8 === 5) && m14 === 2)
				u2 = -m24;
			else
				u2 = m24;
		}
		jsf[1].push(u2);

		// Second phase
		if (2 * d1 === u1 + 1)
			d1 = 1 - d1;
		if (2 * d2 === u2 + 1)
			d2 = 1 - d2;
		k1.iushrn(1);
		k2.iushrn(1);
	}

	return jsf;
}

export function cachedProperty(obj: any, name: string) {
	var computer = obj[name];
	var key = '_' + name;
	obj[name] = function() {
		return this[key] !== undefined ? this[key] :
					 this[key] = computer.call(this);
	};
}

export function parseBytes(bytes: IBuffer | string) {
	return typeof bytes === 'string' ? buffer.from(toArray(bytes, 'hex')): bytes;
}

export function intFromLE(bytes: IBuffer) {
	return new BN(bytes, 'hex', 'le');
}