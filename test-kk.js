
var crypto_tx = require('.');

function genAccountAddress(id) {
	var hash = crypto_tx.keccak(String('')).data;
	console.log('0x' + Buffer.from(hash).toString('hex'));
	var address = Buffer.from(hash.slice(-20));
	console.log('0x' + crypto_tx.toChecksumAddress(address));
}

genAccountAddress('1');

var k = '800C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D';
var k_ = Buffer.from(k, 'hex');

console.log('keccak256', crypto_tx.keccak(k_).hex.slice(2));