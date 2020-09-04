
var crypto = require('./index');
var toBuffer = require('./utils').toBuffer;
var assert = require('./assert');
var {Console} = require('somes/log');

new Console().makeDefault();

async function sign(k, hash) {

	var privateKey = toBuffer(k);
	var data = toBuffer(hash);

	assert.isBufferLength(privateKey, 32, 'Bad privateKey length');
	assert.isBufferLength(data, 32, 'Bad data length');

	var signature = crypto.sign(data, privateKey);
	var signature_buf = Buffer.concat([signature.signature, Buffer.from([signature.recovery])]);

	console.timeLog('sign', '0x' + signature_buf.toString('hex'));
}

console.time('sign');

for (var i = 0; i < 1000; i++) {
	sign('0x2a50f73626d277e0b135eded15c9178ee5133a3e3c872ee6787bc5d28bbcfe0c', '0xa532bdfa7687d196cdd2ed8fef48b4eed1d3d765b4d6d9bf5af291c9d2321303');
}

console.timeEnd('sign');