
import {IBuffer} from 'somes/buffer';
import * as BN_ from 'bn.js';

export interface BN extends BN_ {}

export declare class BNConstructor extends BN_.BN {
	constructor(
		number: number | string | number[] | Uint8Array | Buffer | IBuffer | BN,
		base?: number | 'hex',
		endian?: BN_.Endianness
	);
	constructor(
			number: number | string | number[] | Uint8Array | Buffer | IBuffer | BN,
			endian?: BN_.Endianness
	);
}

export const BN = BN_ as unknown as typeof BNConstructor;
