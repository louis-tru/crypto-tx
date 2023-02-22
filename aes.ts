
import buffer,{IBuffer} from 'somes/buffer';
import * as kk from './keccak';
import * as crypto from 'crypto';

export function aes256cbcEncrypt(plaintext: IBuffer, pwd: string) {
	let key = buffer.from(kk.keccak(pwd).data);
	let iv = key.slice(16);

	let cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
	let firstChunk = cipher.update(plaintext);
	let secondChunk = cipher.final();
	let ciphertext = buffer.concat([firstChunk, secondChunk]);

	return {
		plaintext: plaintext + '',
		ciphertext_hex: '0x' + ciphertext.toString('hex'),
		ciphertext_base64: ciphertext.toString('base64'),
	};
}

export function aes256cbcDecrypt(ciphertext: IBuffer, pwd: string) {
	let key = buffer.from(kk.keccak(pwd).data);
	let iv = key.slice(16);

	var cipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
	var firstChunk = cipher.update(ciphertext);
	var secondChunk = cipher.final();
	let plaintext = buffer.concat([firstChunk, secondChunk]);

	return {
		plaintext: plaintext + '',
		plaintext_hex: '0x' + plaintext.toString('hex'),
		plaintext_base64: plaintext.toString('base64'),
	};
}
