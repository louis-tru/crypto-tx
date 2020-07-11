'use strict';

var elliptic = exports;

export * from './utils'; // elliptic.utils = require('./utils');
elliptic.hmacDRBG = require('./hmac-drbg');
elliptic.curve = require('./curve');
elliptic.curves = require('./curves');

// Protocols
elliptic.ec = require('./ec');
elliptic.eddsa = require('./eddsa');
