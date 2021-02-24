
var buffer = require('somes/buffer').default;
var crypto_tx = require('./index');
var toBuffer = require('./utils').toBuffer;
var assert = require('./assert');

const ArgumentsBytesLen = {
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
};

function message(data, types) {
	const args = [];

	for (var i = 0; i < data.length; i++) {
		var _arg = toBuffer(data[i]);
		var arg = buffer.from(_arg.buffer, _arg.byteOffset, _arg.length);
		var len = ArgumentsBytesLen[types[i]] || arg.length;
		if (arg.length < len) {
			arg = buffer.concat([buffer.alloc(len - arg.length), arg]);
		} else if (arg.length > len) {
			// arg = buffer.from(arg.buffer, arg.byteOffset + arg.length - len, len);
			assert(arg.length == len, `arg${i}: ${types[i]} Conversion overflow`);
		}
		args.push(arg);
	}

	var msg = buffer.from(crypto_tx.keccak(buffer.concat(args)).data);

	return msg;
}

function signArgumentsFromTypes(data, types, privateKey, options) {

	var signature = crypto_tx.sign(message(data, types), privateKey, options);

	return {
		r: '0x' + signature.signature.slice(0, 32).toString('hex'),
		s: '0x' + signature.signature.slice(32, 64).toString('hex'),
		v: signature.recovery,
	};
}

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

exports.message = message;
exports.signArgumentsFromTypes = signArgumentsFromTypes;
