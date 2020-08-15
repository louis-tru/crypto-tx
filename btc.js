
// var somes = require('somes').default;
var crypto = require('./account');
var hash_js = require('hash.js');
var buffer = require('somes/buffer').default;

function sha256(k, enc) {
	return new hash_js.sha256().update(k).digest(enc);
}

function ripemd160(k, enc) {
	return new hash_js.ripemd160().update(k).digest(enc);
}

function wif(k, compress = false, test = false) {
	var k = buffer.concat([[test ? 0xEF : 0x80/*0x80 mainnet| 0xEF tstnet*/], k, compress ? [0x01]: []]);
	var hash = sha256(sha256(k));
	var check = hash.slice(0, 4);
	var wif = buffer.concat([k, check]);
	// console.log('wif', wif.toString('base58'));
	return wif;
}

function address(k, compress = false, test = false) {
	// 0	00	P2PKH address	1	17VZNX1SN5NtKa8UQFxwQbFeFc3iqRYhem
	// 5	05	P2SH address	3	3EktnHQD7RiAE6uzMj2ZifT9YgRrkSgzQX
	// 111	6F	Testnet P2PKH address pub key	m or n	mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn
	// 196	C4	Testnet P2SH address pub key	m or n	mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn
	var pub = crypto.getPublic(k, compress);
	var hash = buffer.concat([[test ? 0x6F : 0x00], ripemd160(sha256(pub))]);
	var check = sha256(sha256(hash)).slice(0, 4);
	var address = buffer.concat([hash, check]);
	// console.log('pub', pub.toString('hex'));
	// console.log('address', address.toString('base58'));
	return address;
}

function parseWIF(wif_bytes) {
	var _wif = wif_bytes; // buffer.from(wif_b58, 'base58');
	var compress = _wif.length == 38 && _wif[33] == 0x01;
	var network = _wif[0];
	var private = _wif.slice(1, 33);
	var check = compress ? _wif.slice(34, 38): _wif.slice(33, 37);
	var public = buffer.from(crypto.getPublic(private, compress));
	var _address = address(private, compress, network == 0xEF);
	// somes.assert(wif(private, compress).toString('base58') == wif_b58, 'parseWIF(), check code error');
	return {
		mainnet: network == 0x80,  /*0x80 mainnet| 0xEF tstnet*/
		private: private,
		compress: compress,
		check: check,
		public: public,
		address: _address,
	};
}

function parseAddress(address_bytes) {
	var address = address_bytes; // buffer.from(address_b58, 'base58');
	var type = address[0];
	var hash = address.slice(1, 20);
	var check = address.slice(21, 4);
	return {
		type, // 00 P2PKH | 05	P2SH address | 6F Testnet P2PKH address | C4 Testnet P2SH address
		hash, check,
	};
}

exports.wif = wif;
exports.address = address;
exports.parseWIF = parseWIF;
exports.parseAddress = parseAddress;