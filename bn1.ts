
import {IBuffer} from 'somes/buffer';
import * as BN from 'bn.js';

declare class BN0 extends BN.BN {
	constructor(
		number: number | string | number[] | Uint8Array | Buffer | IBuffer | BN,
		base?: number | 'hex',
		endian?: BN.Endianness
	);
	constructor(
			number: number | string | number[] | Uint8Array | Buffer | IBuffer | BN,
			endian?: BN.Endianness
	);
}

export default BN0;

exports.default = BN;