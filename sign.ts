

import buffer, {Buffer} from 'somes/buffer';
import {keccak} from './keccak';
import {toBuffer} from './utils';
import assert from './assert';
import {k1} from './ec';
import * as gm from './gm';
import {rng} from 'somes/rng';

export interface Signature {
	signature: Buffer;
	recovery: number;
}

export enum KeyType {
	K1 = 0,
	GM = 1,
}

export type Types = 
	'address' |
	'int256' |
	'int160' |
	'int128' |
	'int64' |
	'int32' |
	'int16' |
	'int8' |
	'uint256' |
	'uint160' |
	'uint128' |
	'uint64' |
	'uint32' |
	'uint16' |
	'uint8' |
	'byte32' |
	'bytes' |
	'string';

const ArgumentsBytesLen: Dict<number> = {
	'address': 20,
	'int256': 32,
	'int160': 20,
	'int128': 16,
	'int64': 8,
	'int32': 4,
	'int16': 2,
	'int8': 1,
	'uint256': 32,
	'uint160': 20,
	'uint128': 16,
	'uint64': 8,
	'uint32': 4,
	'uint16': 2,
	'uint8': 1,
	'byte32': 32,
	'bytes': -1,
	'string': -1,
};

export interface Options {
	noncefn?: ()=>Buffer;
	data?: Buffer;
	type?: KeyType;
}

export type Data = string | number| bigint | Uint8Array | ArrayLike<number>;

export function message(data: Data[], types: Types[]) {
	return buffer.from(keccak(concat(data, types)).data);
}

export function concat(data: Data[], types: Types[]) {
	const args = [];

	for (var i = 0; i < data.length; i++) {
		var _arg = toBuffer(data[i]);
		var arg = buffer.from(_arg.buffer, _arg.byteOffset, _arg.length);
		var len = ArgumentsBytesLen[types[i]] || arg.length;
		if (len == -1) { // variable
		} else if (arg.length < len) {
			arg = buffer.concat([buffer.alloc(len - arg.length), arg]);
		} else if (arg.length > len) {
			// arg = buffer.from(arg.buffer, arg.byteOffset + arg.length - len, len);
			assert(arg.length == len, `arg${i}: ${types[i]} Conversion overflow`);
		}
		args.push(arg);
	}
	return buffer.concat(args);
}

export function sign(msg: Buffer, privateKey: Buffer, options: Options = {}): Signature {
	if (options.type == KeyType.GM) {
		var sign = gm.sign(msg, privateKey);
		return {
			signature: buffer.from(sign, 'hex'),
			recovery: 0,
		};
	} else {
		options = Object.assign({ noncefn: ()=>rng(32) }, options);
		return k1.sign(msg, privateKey, options);
	}
}

export function signArgumentsFromTypes(args: Data[], types: Types[], privateKey: Buffer, options?: Options) {

	// (erc20, proxy, token, tokenId)
	// erc20：0x94CcfFF7c18647c5c8C8255886E2f42B5B8d80a9
	// proxy：0xD1a67514A2126C5b7A0f5DD59003aB0F3464bbf8
	// token: 1 
	// tokenId:0xd580c78d48631a60f09fd9356670764577f27786c0c3c415a033b76a92222f43 

	// privatekey: 8bd71af62734df779b28b3bfc1a52582e6c0108fbec174d91ce5ba8d2788fb89

	// signArgumentsFromTypes(
	// 	['0x94CcfFF7c18647c5c8C8255886E2f42B5B8d80a9', '0xD1a67514A2126C5b7A0f5DD59003aB0F3464bbf8', 1, '0xd580c78d48631a60f09fd9356670764577f27786c0c3c415a033b76a92222f43'],
	// 	['address', 'address', 'uint256', 'uint256'],
	// 	toBuffer('0x8bd71af62734df779b28b3bfc1a52582e6c0108fbec174d91ce5ba8d2788fb89')
	// );

	const msg = message(args, types);
	const signature = sign(msg, privateKey, options);

	return {
		signature: signature.signature,
		recovery: signature.recovery,
		message: '0x' + msg.toString('hex'),
		r: '0x' + signature.signature.slice(0, 32).toString('hex'),
		s: '0x' + signature.signature.slice(32, 64).toString('hex'),
		v: signature.recovery,
	};
}