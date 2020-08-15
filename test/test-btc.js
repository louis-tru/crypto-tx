
var btc = require('../btc');
var buffer = require('somes/buffer').default;

function test(k, compress) {
	var k_ = buffer.from(k, 'hex');
	console.log('wif    ', btc.wif(k_, compress).toString('base58'));
	console.log('address', btc.address(k_, compress).toString('base58'));
}

function test2(wif_b58) {
	var {mainnet,private,compress,public,address} = btc.parseWIF(buffer.from(wif_b58, 'base58'));
	console.log();
	console.log('mainnet', mainnet);
	console.log('compress', compress);
	console.log('privateKey', private.toString('hex'));
	console.log('publicKey', public.toString('hex'));
	console.log('address', address.toString('base58'));
	console.log('wif', wif_b58);
}

// test('0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D', true);
// test('9B257AD1E78C14794FBE9DC60B724B375FDE5D0FB2415538820D0D929C4AD436', true);
test('1c236f70ad3db5efd0bd8ffc22acf9c645fc5b1865250c5293b392729ce5f9e5', true);
test(btc.parseWIF(buffer.from('KwZFBkdzBEVNvwm2kHX8Abs2o9PZcoWnKbhAvaQGQdk3RY2WVxmG', 'base58')).private.toString('hex'), true);

// --

test2('KxAQdkAwqkeGk6AtzAdwVecg6P64r5p16qhDAKk3X8YThpvPJ1kT');
test2('KwZFBkdzBEVNvwm2kHX8Abs2o9PZcoWnKbhAvaQGQdk3RY2WVxmG');
test2('cVWobZH8WMCpdNpBnA8ED2NTbguxAvVmVTZ6mbVc8krumG8RGV5A');
test2('cQuHDfpaC17kVWzW9AspcVej6NyDqmv53QtYZn96J25Qw8LQz761');