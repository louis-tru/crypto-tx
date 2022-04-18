
import * as account from './account';
import * as hash_js from 'hash.js';
import buffer, {Buffer} from 'somes/buffer';

function sha256(k: string | Buffer | ArrayLike<number>) {
	return hash_js.sha256().update(k).digest();
}

function ripemd160(k: string | Buffer | ArrayLike<number>) {
	return hash_js.ripemd160().update(k).digest();
}

export function getWIFKey(privateKey: Buffer, compress = false, test = false) { // get btc wif private key from private ey
	var k = buffer.concat([[test ? 0xEF : 0x80/*0x80 mainnet| 0xEF tstnet*/], privateKey, compress ? [0x01]: []]);
	var hash = sha256(sha256(k));
	var check = hash.slice(0, 4);
	var wif = buffer.concat([k, check]);
	// console.log('wif', wif.toString('base58'));
	return wif;
}

export function getAddress(publicKey: Buffer, compress = false, test = false) { // get btc address from public key
	// 0	00	P2PKH address	1	17VZNX1SN5NtKa8UQFxwQbFeFc3iqRYhem
	// 5	05	P2SH address	3	3EktnHQD7RiAE6uzMj2ZifT9YgRrkSgzQX
	// 111	6F	Testnet P2PKH address pub key	m or n	mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn
	// 196	C4	Testnet P2SH address pub key	m or n	mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn
	var pub = account.publicKeyConvert(publicKey, compress);
	var hash = buffer.concat([[test ? 0x6F : 0x00], ripemd160(sha256(pub))]);
	var check = sha256(sha256(hash)).slice(0, 4);
	var address = buffer.concat([hash, check]);
	// console.log('pub', pub.toString('hex'));
	// console.log('address', address.toString('base58'));
	return address;
}

export function getAddressFromPrivateKey(private_key: Buffer, compress = false, test = false) {
	var publicKey = buffer.from(account.getPublic(private_key, compress));
	return getAddress(publicKey, compress, test);
}

export function parseWIFKey(wif: Buffer) { // wif key bin
	var compress = wif.length == 38 && wif[33] == 0x01;
	var network = wif[0];
	var privateKey = wif.slice(1, 33);
	var check = compress ? wif.slice(34, 38): wif.slice(33, 37);
	var publicKey = buffer.from(account.getPublic(privateKey, compress));
	var address = getAddress(publicKey, compress, network == 0xEF);
	// somes.assert(wif(private, compress).toString('base58') == wif_b58, 'parseWIF(), check code error');
	return {
		mainnet: network == 0x80,  /*0x80 mainnet| 0xEF tstnet*/
		private: privateKey,
		compress: compress,
		check: check,
		public: publicKey,
		address: address,
	};
}

export function parseAddress(address: Buffer) {
	var type = address[0];
	var hash = address.slice(1, 20);
	var check = address.slice(21, 4);
	return {
		type, // 00 P2PKH | 05	P2SH address | 6F Testnet P2PKH address | C4 Testnet P2SH address
		hash, check,
	};
}

export function parseWIFKeyFromB58String(wif_b58: string) { // wif key base58 string
	return parseWIFKey(buffer.from(wif_b58, 'base58'));
}

export function parseAddressFromB58String(address_b58: string) {
	return parseAddress(buffer.from(address_b58, 'base58'));
}