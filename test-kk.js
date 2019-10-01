
var crypto_tx = require('.');

function genAccountAddress(id) {
	var hash = crypto_tx.keccak(String('')).data;
	console.log('0x' + Buffer.from(hash).toString('hex'));
	var address = Buffer.from(hash.slice(-20));
	console.log('0x' + crypto_tx.toChecksumAddress(address));
}

genAccountAddress('1')

