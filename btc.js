
// var somes = require('somes').default;
var account = require('./account');
var hash_js = require('hash.js');
var buffer = require('somes/buffer').default;

function sha256(k, enc) {
	return new hash_js.sha256().update(k).digest(enc);
}

function ripemd160(k, enc) {
	return new hash_js.ripemd160().update(k).digest(enc);
}

function getWIFKey(privateKey_bin, compress = false, test = false) { // get btc wif private key from private ey
	var k = buffer.concat([[test ? 0xEF : 0x80/*0x80 mainnet| 0xEF tstnet*/], privateKey_bin, compress ? [0x01]: []]);
	var hash = sha256(sha256(k));
	var check = hash.slice(0, 4);
	var wif = buffer.concat([k, check]);
	// console.log('wif', wif.toString('base58'));
	return wif;
}

function getAddress(publicKey_bin, compress = false, test = false) { // get btc address from public key
	// 0	00	P2PKH address	1	17VZNX1SN5NtKa8UQFxwQbFeFc3iqRYhem
	// 5	05	P2SH address	3	3EktnHQD7RiAE6uzMj2ZifT9YgRrkSgzQX
	// 111	6F	Testnet P2PKH address pub key	m or n	mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn
	// 196	C4	Testnet P2SH address pub key	m or n	mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn
	var pub = account.publicKeyConvert(publicKey_bin, compress);
	var hash = buffer.concat([[test ? 0x6F : 0x00], ripemd160(sha256(pub))]);
	var check = sha256(sha256(hash)).slice(0, 4);
	var address = buffer.concat([hash, check]);
	// console.log('pub', pub.toString('hex'));
	// console.log('address', address.toString('base58'));
	return address;
}

function getAddressFromPrivateKey(private_key_bin, compress = false, test = false) {
	var public = buffer.from(account.getPublic(private_key_bin, compress));
	return getAddress(public, compress, test);
}

function parseWIFKey(wif_bin) { // wif key bin
	var wif = wif_bin;
	var compress = wif.length == 38 && wif[33] == 0x01;
	var network = wif[0];
	var private = wif.slice(1, 33);
	var check = compress ? wif.slice(34, 38): wif.slice(33, 37);
	var public = buffer.from(account.getPublic(private, compress));
	var address = getAddress(public, compress, network == 0xEF);
	// somes.assert(wif(private, compress).toString('base58') == wif_b58, 'parseWIF(), check code error');
	return {
		mainnet: network == 0x80,  /*0x80 mainnet| 0xEF tstnet*/
		private: private,
		compress: compress,
		check: check,
		public: public,
		address: address,
	};
}

function parseAddress(address_bin) {
	var address = address_bin;
	var type = address[0];
	var hash = address.slice(1, 20);
	var check = address.slice(21, 4);
	return {
		type, // 00 P2PKH | 05	P2SH address | 6F Testnet P2PKH address | C4 Testnet P2SH address
		hash, check,
	};
}

function parseWIFKeyFromB58String(wif_b58_str) { // wif key base58 string
	return parseWIFKey(buffer.from(wif_b58_str, 'base58'));
}

function parseAddressFromB58String(address_b58_str) {
	return parseAddress(buffer.from(address_b58_str, 'base58'));
}

exports.getAddressFromPrivateKey = getAddressFromPrivateKey;
exports.getWIFKey = getWIFKey;
exports.parseWIFKeyFromB58String = parseWIFKeyFromB58String;
exports.address = address;
exports.parseWIFKey = parseWIFKey;
exports.parseAddress = parseAddress;
exports.parseAddressFromB58String = parseAddressFromB58String;